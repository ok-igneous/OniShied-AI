import { createHash } from "node:crypto";

export type AuthEvent = {
  tenant_id: string;
  event_id: string;
  event_type: string;
  observed_at: string;
  data: Record<string, unknown>;
};

export type Detection = {
  rule_id: "AUTH_FAILURE_BURST" | "AUTH_FAILURES_THEN_SUCCESS";
  tenant_id: string;
  subject: string;
  source_ip: string;
  first_observed_at: string;
  last_observed_at: string;
  evidence_event_ids: string[];
  severity: "medium" | "high";
  fingerprint: string;
};

const FAILURE = "auth.login.failure";
const SUCCESS = "auth.login.success";
const BURST_WINDOW_MS = 10 * 60 * 1000;
const SUCCESS_WINDOW_MS = 15 * 60 * 1000;
const BURST_THRESHOLD = 5;
const SEQUENCE_THRESHOLD = 3;

function stringField(data: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = data[key];
    if (typeof value === "string" && value.trim()) return value.trim().toLowerCase();
  }
  return null;
}

function timestamp(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function fingerprint(parts: string[]): string {
  return createHash("sha256").update(parts.join("\0")).digest("hex");
}

/**
 * Pure, deterministic authentication detections. Events are grouped by tenant,
 * normalized principal and source IP; input ordering does not affect results.
 * Events without both a principal and source IP are deliberately ignored.
 */
export function detectAuthenticationAnomalies(events: AuthEvent[]): Detection[] {
  const groups = new Map<string, Array<AuthEvent & { time: number; subject: string; ip: string }>>();

  for (const event of events) {
    if (event.event_type !== FAILURE && event.event_type !== SUCCESS) continue;
    const subject = stringField(event.data, ["user_id", "username", "email", "principal"]);
    const ip = stringField(event.data, ["source_ip", "ip_address", "client_ip"]);
    const time = timestamp(event.observed_at);
    if (!subject || !ip || time === null || !event.tenant_id || !event.event_id) continue;
    const key = JSON.stringify([event.tenant_id, subject, ip]);
    const group = groups.get(key) ?? [];
    group.push({ ...event, time, subject, ip });
    groups.set(key, group);
  }

  const detections: Detection[] = [];
  for (const group of groups.values()) {
    group.sort((a, b) => a.time - b.time || a.event_id.localeCompare(b.event_id));
    const failures = group.filter((event) => event.event_type === FAILURE);

    for (let end = 0; end < failures.length; end++) {
      const current = failures[end]!;
      const window = failures.filter((event) =>
        event.time <= current.time && event.time >= current.time - BURST_WINDOW_MS
      );
      if (window.length === BURST_THRESHOLD) {
        const ids = window.map((event) => event.event_id).sort();
        const tenant = current.tenant_id;
        const fp = fingerprint(["AUTH_FAILURE_BURST", tenant, current.subject, current.ip, ...ids]);
        detections.push({
          rule_id: "AUTH_FAILURE_BURST", tenant_id: tenant,
          subject: current.subject, source_ip: current.ip,
          first_observed_at: new Date(Math.min(...window.map((e) => e.time))).toISOString(),
          last_observed_at: new Date(current.time).toISOString(),
          evidence_event_ids: ids, severity: "medium", fingerprint: fp
        });
      }
    }

    for (const success of group.filter((event) => event.event_type === SUCCESS)) {
      const preceding = failures.filter((event) =>
        event.time <= success.time && event.time >= success.time - SUCCESS_WINDOW_MS
      );
      if (preceding.length < SEQUENCE_THRESHOLD) continue;
      const evidence = [...preceding, success];
      const ids = evidence.map((event) => event.event_id).sort();
      detections.push({
        rule_id: "AUTH_FAILURES_THEN_SUCCESS", tenant_id: success.tenant_id,
        subject: success.subject, source_ip: success.ip,
        first_observed_at: new Date(preceding[0]!.time).toISOString(),
        last_observed_at: new Date(success.time).toISOString(),
        evidence_event_ids: ids, severity: "high",
        fingerprint: fingerprint(["AUTH_FAILURES_THEN_SUCCESS", success.tenant_id,
          success.subject, success.ip, ...ids])
      });
    }
  }

  const unique = new Map<string, Detection>();
  for (const detection of detections) unique.set(detection.fingerprint, detection);
  return [...unique.values()].sort((a, b) =>
    a.last_observed_at.localeCompare(b.last_observed_at) ||
    a.rule_id.localeCompare(b.rule_id) ||
    a.fingerprint.localeCompare(b.fingerprint)
  );
}
