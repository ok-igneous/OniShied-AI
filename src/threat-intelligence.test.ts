import assert from "node:assert/strict";
import test from "node:test";
import {
  IndicatorValidationError,
  matchThreatIndicators,
  normalizeIndicatorValue,
  type ThreatIndicator
} from "./threat-intelligence.js";

const validFrom = "2026-01-01T00:00:00.000Z";
const now = new Date("2026-11-13T12:00:00.000Z");

function indicator(
  overrides: Partial<ThreatIndicator> = {}
): ThreatIndicator {
  return {
    id: "indicator-1",
    version: 1,
    type: "domain",
    value_normalized: "evil.test",
    status: "active",
    valid_from: validFrom,
    expires_at: null,
    confidence: 85,
    tlp: "green",
    source_id: "source-1",
    ...overrides
  };
}

test("normalizes IPv4 addresses", () => {
  assert.equal(normalizeIndicatorValue("ipv4", "192.0.2.44"), "192.0.2.44");
  assert.throws(
    () => normalizeIndicatorValue("ipv4", "192.0.2.999"),
    IndicatorValidationError
  );
});

test("validates and canonicalizes IPv6 addresses", () => {
  assert.equal(
    normalizeIndicatorValue("ipv6", "2001:0DB8:0:0:0:0:0:1"),
    "2001:db8::1"
  );
  assert.throws(
    () => normalizeIndicatorValue("ipv6", "2001:not-ipv6"),
    IndicatorValidationError
  );
});

test("normalizes IDN domains and a single terminal dot", () => {
  assert.equal(normalizeIndicatorValue("domain", "BÜCHER.example."), "xn--bcher-kva.example");
  assert.throws(
    () => normalizeIndicatorValue("domain", "-invalid.test"),
    IndicatorValidationError
  );
  assert.throws(
    () => normalizeIndicatorValue("domain", "192.0.2.44"),
    IndicatorValidationError
  );
});

test("canonicalizes HTTP URLs and strips embedded credentials", () => {
  assert.equal(
    normalizeIndicatorValue("url", "https://user:secret@Example.test/a"),
    "https://example.test/a"
  );
  assert.throws(
    () => normalizeIndicatorValue("url", "file:///etc/passwd"),
    IndicatorValidationError
  );
});

test("normalizes SHA-256 and email values", () => {
  const digest = "A".repeat(64);
  assert.equal(
    normalizeIndicatorValue("file_hash_sha256", digest),
    digest.toLowerCase()
  );
  assert.equal(
    normalizeIndicatorValue("email_address", "analyst@BÜCHER.example"),
    "analyst@xn--bcher-kva.example"
  );
  assert.throws(
    () => normalizeIndicatorValue("file_hash_sha256", "abc"),
    IndicatorValidationError
  );
  assert.throws(
    () => normalizeIndicatorValue("email_address", "bad@@example.test"),
    IndicatorValidationError
  );
});

test("rejects control characters, surrounding whitespace, and oversized values", () => {
  assert.throws(
    () => normalizeIndicatorValue("domain", " evil.test"),
    IndicatorValidationError
  );
  assert.throws(
    () => normalizeIndicatorValue("domain", "evil.test\n"),
    IndicatorValidationError
  );
  assert.throws(
    () => normalizeIndicatorValue("domain", "a".repeat(2049)),
    IndicatorValidationError
  );
});

test("matches only explicitly mapped event fields using exact normalized values", () => {
  const matches = matchThreatIndicators({
    connectorId: "connector-1",
    eventId: "event-1",
    data: { source_ip: "192.0.2.44", domain: "EVIL.TEST." },
    indicators: [
      indicator(),
      indicator({
        id: "indicator-ip",
        type: "ipv4",
        value_normalized: "192.0.2.44"
      })
    ],
    now
  });

  assert.equal(matches.length, 2);
  assert.ok(matches.every((match) => match.event_id === "event-1"));
  assert.ok(matches.every((match) => match.connector_id === "connector-1"));
  assert.deepEqual(
    matches.map((match) => match.matched_field_path).sort(),
    ["data.domain", "data.source_ip"]
  );
});

test("matches IP indicators against authentication source_address", () => {
  const matches = matchThreatIndicators({
    connectorId: "connector-auth",
    eventId: "auth-failure-1",
    data: { source_address: "192.0.2.44" },
    indicators: [indicator({
      type: "ipv4",
      value_normalized: "192.0.2.44"
    })],
    now
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.matched_field_path, "data.source_address");
  assert.equal(matches[0]?.connector_id, "connector-auth");
});

test("does not match pending, expired, revoked, rejected, future, or expired-by-time indicators", () => {
  const states: ThreatIndicator[] = [
    indicator({ status: "pending", id: "pending" }),
    indicator({ status: "expired", id: "expired" }),
    indicator({ status: "revoked", id: "revoked" }),
    indicator({ status: "rejected", id: "rejected" }),
    indicator({ id: "future", valid_from: "2027-01-01T00:00:00.000Z" }),
    indicator({ id: "past-expiry", expires_at: "2026-11-13T11:59:59.000Z" })
  ];

  assert.deepEqual(
    matchThreatIndicators({
      connectorId: "connector-1",
      eventId: "event-2",
      data: { domain: "evil.test" },
      indicators: states,
      now
    }),
    []
  );
});

test("does not recursively inspect arbitrary event properties", () => {
  assert.deepEqual(
    matchThreatIndicators({
      connectorId: "connector-1",
      eventId: "event-3",
      data: { nested: { domain: "evil.test" }, notes: "evil.test" },
      indicators: [indicator()],
      now
    }),
    []
  );
});

test("deduplicates repeated indicator records by indicator version and evidence path", () => {
  const first = indicator();
  const duplicate = indicator();
  const matches = matchThreatIndicators({
    connectorId: "connector-1",
    eventId: "event-4",
    data: { domain: "evil.test" },
    indicators: [first, duplicate],
    now
  });

  assert.equal(matches.length, 1);
});

test("keeps connector identity attached when event IDs collide across connectors", () => {
  const fromA = matchThreatIndicators({
    connectorId: "connector-a",
    eventId: "shared-event",
    data: { domain: "evil.test" },
    indicators: [indicator()],
    now
  });
  const fromB = matchThreatIndicators({
    connectorId: "connector-b",
    eventId: "shared-event",
    data: { domain: "evil.test" },
    indicators: [indicator()],
    now
  });

  assert.equal(fromA[0]?.event_id, fromB[0]?.event_id);
  assert.notEqual(fromA[0]?.connector_id, fromB[0]?.connector_id);
});

test("rejects oversized candidate sets and invalid event or connector identifiers", () => {
  assert.throws(
    () => matchThreatIndicators({
      connectorId: "connector-1",
      eventId: "event-limit",
      data: {},
      indicators: Array.from({ length: 10_001 }, (_, index) =>
        indicator({ id: String(index) })
      ),
      now
    }),
    IndicatorValidationError
  );
  assert.throws(
    () => matchThreatIndicators({
      connectorId: "",
      eventId: "event-connector-invalid",
      data: {},
      indicators: [],
      now
    }),
    IndicatorValidationError
  );
  assert.throws(
    () => matchThreatIndicators({
      connectorId: "connector-1",
      eventId: "",
      data: {},
      indicators: [],
      now
    }),
    IndicatorValidationError
  );
});
