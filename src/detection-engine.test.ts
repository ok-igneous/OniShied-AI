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
  connector?: string;
}): SecurityEventInput {
  return {
    schema_version: "0.1.0",
    event_id: input.id,
    tenant_id: input.tenant ?? "tenant-a",
    source: {
      connector_id: input.connector ?? "connector-a",
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
  assert.deepEqual(first.evidence_event_ids, events.map((item) => `${item.source.connector_id}:${item.event_id}`));
  assert.deepEqual(first.evidence_event_refs, events.map((item) => ({
    connector_id: item.source.connector_id,
    event_id: item.event_id
  })));
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

test("same-time events from different connectors have stable evidence ordering", () => {
  const events = Array.from({ length: 8 }, (_, i) => event({
    id: `shared-${i}`,
    at: at(0),
    connector: i % 2 === 0 ? "connector-b" : "connector-a"
  }));
  const forward = evaluateDetections(events);
  const reverse = evaluateDetections([...events].reverse());
  assert.deepEqual(forward, reverse);
  assert.equal(forward.length, 1);
  assert.deepEqual(
    forward[0]?.evidence_event_ids,
    [...events]
      .sort((a, b) => a.source.connector_id.localeCompare(b.source.connector_id) || a.event_id.localeCompare(b.event_id))
      .map((item) => `${item.source.connector_id}:${item.event_id}`)
  );
});


test("finding identity cannot collide on colon-containing connector and event IDs", () => {
  const left = Array.from({ length: 8 }, (_, i) => event({
    id: `event-${i}`,
    connector: `connector:part`,
    at: at(i * 10)
  }));
  const right = Array.from({ length: 8 }, (_, i) => event({
    id: `part:event-${i}`,
    connector: "connector",
    at: at(i * 10)
  }));

  const leftFinding = evaluateDetections(left)[0]!;
  const rightFinding = evaluateDetections(right)[0]!;
  assert.deepEqual(leftFinding.evidence_event_ids, rightFinding.evidence_event_ids);
  assert.notDeepEqual(leftFinding.evidence_event_refs, rightFinding.evidence_event_refs);
  assert.notEqual(leftFinding.finding_id, rightFinding.finding_id);
});


test("adding later evidence inside the burst episode does not change incident identity", () => {
  const initial = Array.from({ length: 8 }, (_, i) => event({ id: `stable-${i}`, at: at(i * 10) }));
  const first = evaluateDetections(initial)[0]!;
  const later = event({ id: "stable-late", at: at(240) });
  const enriched = evaluateDetections([...initial, later])[0]!;
  assert.equal(enriched.finding_id, first.finding_id);
  assert.deepEqual(enriched.episode_anchor, first.episode_anchor);
  assert.equal(enriched.evidence_event_refs.length, 9);
});

test("a burst after the five-minute post-trigger boundary is a separate episode", () => {
  const firstEpisode = Array.from({ length: 8 }, (_, i) => event({ id: `first-${i}`, at: at(i * 5) }));
  const secondEpisode = Array.from({ length: 8 }, (_, i) => event({ id: `second-${i}`, at: at(360 + i * 5) }));
  const findings = evaluateDetections([...firstEpisode, ...secondEpisode])
    .filter((finding) => finding.rule_id === "AUTH_FAILURE_BURST");
  assert.equal(findings.length, 2);
  assert.notEqual(findings[0]?.finding_id, findings[1]?.finding_id);
});

test("out-of-order evidence after the burst anchor enriches the same episode", () => {
  const initial = Array.from({ length: 8 }, (_, i) => event({ id: `late-base-${i}`, at: at(i * 10) }));
  const late = event({ id: "late-arrival", at: at(90) });
  const first = evaluateDetections(initial)[0]!;
  const replayed = evaluateDetections([...initial.slice(0, 7), late, initial[7]!])[0]!;
  assert.equal(replayed.finding_id, first.finding_id);
  assert.ok(replayed.evidence_event_refs.some((ref) => ref.event_id === "late-arrival"));
});

test("each qualifying success creates a distinct sequence episode", () => {
  const failures = Array.from({ length: 5 }, (_, i) => event({ id: `seq-f-${i}`, at: at(i * 10) }));
  const successes = [100, 110].map((second, i) => event({
    id: `seq-s-${i}`, type: "identity.authentication.success", at: at(second)
  }));
  const findings = evaluateDetections([...failures, ...successes])
    .filter((finding) => finding.rule_id === "AUTH_FAILURE_THEN_SUCCESS");
  assert.equal(findings.length, 2);
  assert.notEqual(findings[0]?.finding_id, findings[1]?.finding_id);
});


test("a late event before the burst anchor can move the threshold anchor", () => {
  const initial = Array.from({ length: 8 }, (_, i) => event({ id: `pre-anchor-${i}`, at: at(i * 10) }));
  const original = evaluateDetections(initial)[0]!;
  const lateEarlier = event({ id: "pre-anchor-late", at: at(-10) });
  const recomputed = evaluateDetections([...initial, lateEarlier])[0]!;
  assert.notEqual(recomputed.finding_id, original.finding_id);
  assert.equal(recomputed.episode_anchor.event_id, "pre-anchor-6");
});
