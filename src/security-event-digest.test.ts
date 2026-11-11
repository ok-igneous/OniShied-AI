import test from "node:test";
import assert from "node:assert/strict";
import { securityEventDigest } from "./security-event-digest.js";

test("canonical digest ignores JSON object key ordering", () => {
  const first = { tenant: "lab-a", data: { count: 3, address: "192.0.2.25" } };
  const reordered = { data: { address: "192.0.2.25", count: 3 }, tenant: "lab-a" };

  assert.equal(securityEventDigest(first), securityEventDigest(reordered));
});

test("canonical digest changes when event content changes", () => {
  const first = { event_id: "evt-1", data: { count: 3 } };
  const changed = { event_id: "evt-1", data: { count: 4 } };

  assert.notEqual(securityEventDigest(first), securityEventDigest(changed));
});
