import { createHash } from "node:crypto";
import type { SecurityEventInput } from "./security-event.js";

export type DetectionFinding = {
  finding_id: string;
  tenant_id: string;
  rule_id: "AUTH_FAILURE_BURST" | "AUTH_FAILURE_THEN_SUCCESS";
  rule_version: "1.0.0";
  status: "open";
  title: string;
  explanation: string;
  severity: "medium";
  confidence: "high";
  first_seen_at: string;
  last_seen_at: string;
  episode_anchor: { connector_id: string; event_id: string };
  evidence_event_ids: string[];
  evidence_event_refs: Array<{ connector_id: string; event_id: string }>;
  grouping_key_hash: string;
  matched_conditions: string[];
  known_limitations: string[];
};

const FAILURE = "identity.authentication.failure";
const SUCCESS = "identity.authentication.success";
const BURST_WINDOW_MS = 5 * 60 * 1000;
const SEQUENCE_WINDOW_MS = 10 * 60 * 1000;

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}
function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
function timestamp(event: SecurityEventInput): number {
  return Date.parse(event.observed_at);
}
function compareEvents(a: SecurityEventInput, b: SecurityEventInput): number {
  return timestamp(a) - timestamp(b) ||
    a.source.connector_id.localeCompare(b.source.connector_id) ||
    a.event_id.localeCompare(b.event_id);
}
function evidenceOrder(events: SecurityEventInput[]): SecurityEventInput[] {
  const unique = new Map<string, SecurityEventInput>();
  for (const event of events) {
    const key = JSON.stringify([event.tenant_id, event.source.connector_id, event.event_id]);
    if (!unique.has(key)) unique.set(key, event);
  }
  return [...unique.values()].sort(compareEvents);
}
function makeFinding(input: {
  tenantId: string;
  ruleId: DetectionFinding["rule_id"];
  title: string;
  explanation: string;
  events: SecurityEventInput[];
  anchorEvent: SecurityEventInput;
  grouping: string;
  matched: string[];
  limitations: string[];
}): DetectionFinding {
  const events = [...input.events].sort(compareEvents);
  const evidenceIds = events.map((event) => `${event.source.connector_id}:${event.event_id}`);
  const evidenceRefs = events.map((event) => ({
    connector_id: event.source.connector_id, event_id: event.event_id
  }));
  const groupingKeyHash = digest(input.grouping);
  const episodeAnchor = {
    connector_id: input.anchorEvent.source.connector_id,
    event_id: input.anchorEvent.event_id
  };
  // Identity is anchored to the event that first satisfies the rule, never the
  // mutable evidence set. Structured JSON keeps opaque IDs delimiter-safe.
  const findingId = digest(JSON.stringify([
    input.ruleId, "1.0.0", input.tenantId, groupingKeyHash, episodeAnchor
  ]));
  return {
    finding_id: findingId,
    tenant_id: input.tenantId,
    rule_id: input.ruleId,
    rule_version: "1.0.0",
    status: "open",
    title: input.title,
    explanation: input.explanation,
    severity: "medium",
    confidence: "high",
    first_seen_at: events[0]!.observed_at,
    last_seen_at: events[events.length - 1]!.observed_at,
    episode_anchor: episodeAnchor,
    evidence_event_ids: evidenceIds,
    evidence_event_refs: evidenceRefs,
    grouping_key_hash: groupingKeyHash,
    matched_conditions: input.matched,
    known_limitations: input.limitations
  };
}

/**
 * Evaluates a bounded event batch deterministically.
 *
 * Burst episodes are anchored at the first event that completes the 8-failure
 * threshold. Evidence with event time in the following five minutes belongs to
 * that episode; a later qualifying threshold creates another episode.
 * A late event after the anchor can enrich the same episode without changing
 * its ID. A late event before the anchor can change which event first crosses
 * the threshold; durable historical reconciliation is deferred to replay.
 *
 * Each qualifying success is its own sequence episode, anchored by that success.
 */
export function evaluateDetections(inputEvents: readonly SecurityEventInput[]): DetectionFinding[] {
  const events = evidenceOrder([...inputEvents]);
  const findings: DetectionFinding[] = [];
  const failuresByBurstKey = new Map<string, SecurityEventInput[]>();
  const authByPrincipal = new Map<string, SecurityEventInput[]>();

  for (const event of events) {
    const principal = nonEmptyString(event.data.principal_ref);
    const host = nonEmptyString(event.source.host_ref);
    if (!principal || !host) continue;
    const principalKey = JSON.stringify([event.tenant_id, host, principal]);
    if (event.event_type === FAILURE || event.event_type === SUCCESS) {
      const current = authByPrincipal.get(principalKey) ?? [];
      current.push(event);
      authByPrincipal.set(principalKey, current);
    }
    if (event.event_type === FAILURE) {
      const address = nonEmptyString(event.data.source_address);
      if (!address) continue;
      const burstKey = JSON.stringify([event.tenant_id, host, principal, address]);
      const current = failuresByBurstKey.get(burstKey) ?? [];
      current.push(event);
      failuresByBurstKey.set(burstKey, current);
    }
  }

  for (const [grouping, group] of failuresByBurstKey) {
    let lastAnchorTime = Number.NEGATIVE_INFINITY;
    for (let end = 0; end < group.length; end += 1) {
      const anchor = group[end]!;
      const anchorTime = timestamp(anchor);
      if (anchorTime <= lastAnchorTime + BURST_WINDOW_MS) continue;
      const qualifying = group.filter((event) => {
        const delta = anchorTime - timestamp(event);
        return delta >= 0 && delta <= BURST_WINDOW_MS;
      });
      if (qualifying.length < 8) continue;
      const episodeEvidence = group.filter((event) => {
        const delta = timestamp(event) - anchorTime;
        return delta >= -BURST_WINDOW_MS && delta <= BURST_WINDOW_MS;
      });
      findings.push(makeFinding({
        tenantId: anchor.tenant_id,
        ruleId: "AUTH_FAILURE_BURST",
        title: "Authentication failure burst",
        explanation: `${qualifying.length} failed authentication events occurred for one principal and source address within five minutes.`,
        events: episodeEvidence,
        anchorEvent: anchor,
        grouping,
        matched: ["at_least_8_failures", "within_5_minutes", "same_tenant_host_principal_source", "five_minute_post_trigger_episode"],
        limitations: [
          "A legitimate user or service with stale credentials can trigger this rule.",
          "Distributed attempts across source addresses are not combined.",
          "Shared NAT can combine activity from different actors.",
          "A late event earlier than the episode anchor can change the threshold-crossing event; durable replay reconciliation is not yet implemented."
        ]
      }));
      lastAnchorTime = anchorTime;
    }
  }

  for (const [grouping, group] of authByPrincipal) {
    const failures: SecurityEventInput[] = [];
    for (const event of group) {
      if (event.event_type === FAILURE) {
        failures.push(event);
        continue;
      }
      if (event.event_type !== SUCCESS) continue;
      const successTime = timestamp(event);
      const precedingFailures = failures.filter((failure) => {
        const delta = successTime - timestamp(failure);
        return delta >= 0 && delta <= SEQUENCE_WINDOW_MS;
      });
      if (precedingFailures.length < 5) continue;
      findings.push(makeFinding({
        tenantId: event.tenant_id,
        ruleId: "AUTH_FAILURE_THEN_SUCCESS",
        title: "Repeated authentication failures followed by success",
        explanation: `${precedingFailures.length} failed authentication events were followed by a successful login for the same principal within ten minutes.`,
        events: [...precedingFailures, event],
        anchorEvent: event,
        grouping,
        matched: ["at_least_5_failures", "followed_by_success", "within_10_minutes", "same_tenant_host_principal"],
        limitations: [
          "A user correcting a mistyped password can trigger this rule.",
          "The sequence does not prove account compromise.",
          "The rule does not currently correlate device reputation or MFA outcomes."
        ]
      }));
    }
  }

  const uniqueFindings = new Map<string, DetectionFinding>();
  for (const finding of findings) uniqueFindings.set(finding.finding_id, finding);
  return [...uniqueFindings.values()].sort((a, b) =>
    a.rule_id.localeCompare(b.rule_id) || a.finding_id.localeCompare(b.finding_id)
  );
}
