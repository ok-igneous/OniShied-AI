import { test } from "node:test";
import assert from "node:assert/strict";
import { detectAuthenticationAnomalies, type AuthEvent } from "./detection-engine.js";

function event(id: string, type: string, minute: number, tenant = "tenant-a", user = "alice", ip = "203.0.113.7"): AuthEvent {
  return {
    tenant_id: tenant, event_id: id, event_type: type,
    observed_at: new Date(Date.UTC(2026, 0, 1, 0, minute)).toISOString(),
    data: { username: user, source_ip: ip }
  };
}

test("detects a five-failure burst within ten minutes with evidence", () => {
  const events = [0, 1, 2, 3, 4].map((m) => event("f" + m, "auth.login.failure", m));
  const detections = detectAuthenticationAnomalies(events);
  const burst = detections.find((d) => d.rule_id === "AUTH_FAILURE_BURST");
  assert.ok(burst);
  assert.equal(burst.evidence_event_ids.length, 5);
  assert.equal(burst.severity, "medium");
});

test("detects failures followed by a successful login as high severity", () => {
  const events = [
    event("f1", "auth.login.failure", 0),
    event("f2", "auth.login.failure", 1),
    event("f3", "auth.login.failure", 2),
    event("s1", "auth.login.success", 3)
  ];
  const result = detectAuthenticationAnomalies(events);
  const sequence = result.find((d) => d.rule_id === "AUTH_FAILURES_THEN_SUCCESS");
  assert.ok(sequence);
  assert.equal(sequence.severity, "high");
  assert.deepEqual(sequence.evidence_event_ids, ["f1", "f2", "f3", "s1"]);
});

test("is independent of input ordering and deduplicates identical evidence", () => {
  const events = [0, 1, 2, 3, 4].map((m) => event("f" + m, "auth.login.failure", m));
  assert.deepEqual(detectAuthenticationAnomalies(events), detectAuthenticationAnomalies([...events].reverse()));
});

test("does not combine tenants, users, or source IPs", () => {
  const events = [
    ...[0, 1, 2].map((m) => event("a" + m, "auth.login.failure", m)),
    event("b1", "auth.login.failure", 3, "tenant-b"),
    event("b2", "auth.login.failure", 4, "tenant-b")
  ];
  assert.equal(detectAuthenticationAnomalies(events).length, 0);
});

test("ignores malformed timestamps and events missing identity fields", () => {
  const malformed = event("bad", "auth.login.failure", 0);
  malformed.observed_at = "not-a-date";
  const missing = event("missing", "auth.login.failure", 1);
  missing.data = {};
  assert.deepEqual(detectAuthenticationAnomalies([malformed, missing]), []);
});

test("does not flag a success outside the fifteen-minute correlation window", () => {
  const events = [
    event("f1", "auth.login.failure", 0),
    event("f2", "auth.login.failure", 1),
    event("f3", "auth.login.failure", 2),
    event("s1", "auth.login.success", 20)
  ];
  assert.equal(detectAuthenticationAnomalies(events).length, 0);
});
