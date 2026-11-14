import assert from "node:assert/strict";
import test from "node:test";
import { evaluateDetections } from "./detection-engine.js";
import type { SecurityEventInput } from "./security-event.js";

function event(input: {
  id: string;
  type?: string;
  at: string;
  tenant?: string;
  host?: string;
  principal?: string;
  address?: string;
}): SecurityEventInput {
  return {
    schema_version: "0.1.0",
    event_id: input.id,
    tenant_id: input.tenant ?? "tenant-a",
    source: {
      connector_id: "connector-a",
      kind: "synthetic-lab",
      host_ref: input.host ?? "host-a"
    },
    event_type: input.type ?? "identity.authentication.failure",
    observed_at: input.at,
    provenance: {
      record_ref: input.id,
      collection_method: "synthetic_replay"
    },
    data: {
      principal_ref: input.principal ?? "user-a",
      source_address: input.address ?? "192.0.2.10"
    }
  };
}

const base = Date.parse("2026-11-14T00:00:00.000Z");
const at = (seconds: number) => new Date(base + seconds * 1000).toISOString();

test("detects exactly eight failures within five minutes", () => {
  const events = Array.from({ length: 8 }, (_, i) => event({ id: `f${i}`, at: at(i * 20) }));
  const findings = evaluateDetections(events);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.rule_id, "AUTH_FAILURE_BURST");
  assert.equal(findings[0]?.evidence_event_ids.length, 8);
});

test("does not detect seven failures", () => {
  const events = Array.from({ length: 7 }, (_, i) => event({ id: `f${i}`, at: at(i * 20) }));
  assert.equal(evaluateDetections(events).length, 0);
});

test("does not combine events from different tenants", () => {
  const events = Array.from({ length: 8 }, (_, i) =>
    event({ id: `f${i}`, at: at(i * 10), tenant: i < 4 ? "tenant-a" : "tenant-b" })
  );
  assert.equal(evaluateDetections(events).length, 0);
});

test("deduplicates repeated event IDs and is independent of input order", () => {
  const events = Array.from({ length: 8 }, (_, i) => event({ id: `f${i}`, at: at(i * 10) }));
  const forward = evaluateDetections([...events, events[0]!]);
  const reverse = evaluateDetections([...events].reverse());
  assert.deepEqual(forward, reverse);
  assert.equal(forward.length, 1);
});

test("detects five failures followed by a success within ten minutes", () => {
  const failures = Array.from({ length: 5 }, (_, i) => event({ id: `f${i}`, at: at(i * 30) }));
  const success = event({
    id: "success-1",
    type: "identity.authentication.success",
    at: at(180),
    address: "192.0.2.11"
  });
  const findings = evaluateDetections([...failures, success]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.rule_id, "AUTH_FAILURE_THEN_SUCCESS");
  assert.equal(findings[0]?.evidence_event_ids.length, 6);
});

test("does not detect a success outside the ten-minute window", () => {
  const failures = Array.from({ length: 5 }, (_, i) => event({ id: `f${i}`, at: at(i * 10) }));
  const success = event({
    id: "success-1",
    type: "identity.authentication.success",
    at: at(700)
  });
  assert.equal(evaluateDetections([...failures, success]).length, 0);
});

test("does not correlate different principals", () => {
  const failures = Array.from({ length: 5 }, (_, i) => event({ id: `f${i}`, at: at(i * 10) }));
  const success = event({
    id: "success-1",
    type: "identity.authentication.success",
    at: at(100),
    principal: "user-b"
  });
  assert.equal(evaluateDetections([...failures, success]).length, 0);
});

test("findings carry deterministic IDs and immutable evidence references", () => {
  const events = Array.from({ length: 8 }, (_, i) => event({ id: `f${i}`, at: at(i * 10) }));
  const first = evaluateDetections(events)[0]!;
  const second = evaluateDetections(events)[0]!;
  assert.equal(first.finding_id, second.finding_id);
  assert.deepEqual(first.evidence_event_ids, events.map((item) => item.event_id));
  assert.equal(first.rule_version, "1.0.0");
});


test("burst window includes an event exactly five minutes old", () => {
  const events = Array.from({ length: 8 }, (_, i) =>
    event({ id: `edge-${i}`, at: at(i === 0 ? 0 : 300) })
  );
  assert.equal(evaluateDetections(events).filter((item) => item.rule_id === "AUTH_FAILURE_BURST").length, 1);
});

test("burst detection does not combine different source addresses", () => {
  const events = Array.from({ length: 8 }, (_, i) =>
    event({ id: `addr-${i}`, at: at(i * 10), address: i < 4 ? "192.0.2.10" : "192.0.2.11" })
  );
  assert.equal(evaluateDetections(events).length, 0);
});

test("sequence detection correlates the same principal across source addresses", () => {
  const failures = Array.from({ length: 5 }, (_, i) =>
    event({ id: `multi-${i}`, at: at(i * 20), address: "192.0.2.10" })
  );
  const success = event({
    id: "multi-success",
    type: "identity.authentication.success",
    at: at(120),
    address: "198.51.100.8"
  });
  assert.equal(evaluateDetections([...failures, success])[0]?.rule_id, "AUTH_FAILURE_THEN_SUCCESS");
});

test("sequence detection includes a failure exactly ten minutes before success", () => {
  const failures = Array.from({ length: 5 }, (_, i) =>
    event({ id: `ten-${i}`, at: at(i === 0 ? 0 : 1) })
  );
  const success = event({
    id: "ten-success",
    type: "identity.authentication.success",
    at: at(600)
  });
  assert.equal(evaluateDetections([...failures, success]).length, 1);
});

test("missing principal or host reference produces no finding", () => {
  const failures = Array.from({ length: 8 }, (_, i) =>
    event({ id: `missing-${i}`, at: at(i * 5), principal: i === 0 ? " " : "user-a" })
  );
  assert.equal(evaluateDetections(failures).length, 0);
  const missingHost = Array.from({ length: 8 }, (_, i) =>
    event({ id: `host-${i}`, at: at(i * 5), host: i === 0 ? " " : "host-a" })
  );
  assert.equal(evaluateDetections(missingHost).length, 0);
});
