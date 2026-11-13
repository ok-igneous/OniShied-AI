import assert from "node:assert/strict";
import test from "node:test";
import { decryptMfaSecret, encryptMfaSecret } from "./operator-mfa-crypto.js";

const key = "ab".repeat(32);

test("MFA secrets are AES-256-GCM encrypted and decrypt with the correct key", () => {
  const encrypted = encryptMfaSecret("JBSWY3DPEHPK3PXP", key);
  assert.notEqual(encrypted.ciphertext.toString("utf8"), "JBSWY3DPEHPK3PXP");
  assert.equal(decryptMfaSecret(encrypted, key), "JBSWY3DPEHPK3PXP");
});

test("MFA encryption uses a fresh nonce and rejects wrong keys or tampering", () => {
  const first = encryptMfaSecret("secret", key);
  const second = encryptMfaSecret("secret", key);
  assert.notDeepEqual(first.nonce, second.nonce);
  assert.throws(() => decryptMfaSecret(first, "cd".repeat(32)));
  const tampered = { ...first, ciphertext: Buffer.from(first.ciphertext) };
  tampered.ciphertext[0] ^= 1;
  assert.throws(() => decryptMfaSecret(tampered, key));
});

test("MFA encryption key must be exactly 32 bytes of hex", () => {
  assert.throws(() => encryptMfaSecret("secret", "short"));
});
