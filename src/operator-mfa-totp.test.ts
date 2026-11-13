import assert from "node:assert/strict";
import test from "node:test";
import { decodeBase32, encodeBase32, generateTotpAt, generateTotpSecret, verifyTotp } from "./operator-mfa-totp.js";

test("base32 encoding and decoding round-trip", () => {
  const original = Buffer.from("OniShield MFA");
  assert.deepEqual(decodeBase32(encodeBase32(original)), original);
});

test("generated TOTP secrets contain 160 bits of entropy", () => {
  const first = generateTotpSecret();
  const second = generateTotpSecret();
  assert.match(first, /^[A-Z2-7]{32}$/);
  assert.notEqual(first, second);
  assert.equal(decodeBase32(first).length, 20);
});

test("TOTP generation is stable within a 30-second time step", () => {
  const secret = encodeBase32(Buffer.from("12345678901234567890"));
  assert.equal(generateTotpAt(secret, 59_000), generateTotpAt(secret, 60_000));
  assert.match(generateTotpAt(secret, 59_000), /^\d{6}$/);
});

test("verification accepts current and adjacent time step but rejects malformed codes", () => {
  const secret = generateTotpSecret();
  const now = 1_800_000_000_000;
  const code = generateTotpAt(secret, now);
  assert.notEqual(verifyTotp(secret, code, now), null);
  assert.notEqual(verifyTotp(secret, code, now + 30_000), null);
  assert.equal(verifyTotp(secret, "12ab56", now), null);
  assert.equal(verifyTotp(secret, "12345", now), null);
  assert.equal(verifyTotp(secret, code, now, 2), null);
});

test("invalid secrets and timestamps are rejected", () => {
  assert.throws(() => decodeBase32("not-valid-secret"));
  assert.throws(() => generateTotpAt("A".repeat(32), -1));
});
