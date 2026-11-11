import test from "node:test";
import assert from "node:assert/strict";
import { securityEventSchema } from "./security-event.js";

const validEvent = {
  schema_version: "0.1.0",
  event_id: "lab-evt-000001",
  tenant_id: "lab-tenant",
  source: {
    connector_id: "lab-connector-01",
    kind: "synthetic-lab",
    version: "0.1.0",
    host_ref: "lab-workstation-01"
  },
  event_type: "identity.authentication.failure",
  observed_at: "2026-11-11T12:00:00Z",
  severity_hint: "medium",
  provenance: {
    record_ref: "scenario-auth-burst-01",
    collection_method: "synthetic_replay"
  },
  data: {
    principal_ref: "user-test-01",
    failure_count_window: 8,
    window_seconds: 60,
    source_address: "192.0.2.25",
    result: "failure"
  }
};

test("accepts a valid synthetic security event", () => {
  const result = securityEventSchema.safeParse(validEvent);
  assert.equal(result.success, true);
});

test("rejects unsupported schema versions", () => {
  const result = securityEventSchema.safeParse({
    ...validEvent,
    schema_version: "9.9.9"
  });
  assert.equal(result.success, false);
});

test("rejects malformed event type names", () => {
  const result = securityEventSchema.safeParse({
    ...validEvent,
    event_type: "Authentication Failure"
  });
  assert.equal(result.success, false);
});

test("rejects events with unexpected top-level properties", () => {
  const result = securityEventSchema.safeParse({
    ...validEvent,
    execute_response: true
  });
  assert.equal(result.success, false);
});

test("rejects invalid timestamps", () => {
  const result = securityEventSchema.safeParse({
    ...validEvent,
    observed_at: "yesterday"
  });
  assert.equal(result.success, false);
});

test("rejects more than 100 top-level data properties", () => {
  const data = Object.fromEntries(
    Array.from({ length: 101 }, (_, index) => [`field_${index}`, index])
  );
  const result = securityEventSchema.safeParse({
    ...validEvent,
    data
  });
  assert.equal(result.success, false);
});
