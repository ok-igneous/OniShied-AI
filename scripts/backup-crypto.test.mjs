import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  createBackupCipher, createBackupDecipher, deriveBackupKeys,
  signBackupManifest, verifyBackupManifestSignature
} from "./backup-crypto.mjs";

test("AES-256-GCM backup stream round-trips with derived encryption key", () => {
  const keys = deriveBackupKeys("ab".repeat(32));
  const iv = randomBytes(12);
  const plaintext = Buffer.from("synthetic OniShield database backup");
  const cipher = createBackupCipher(keys.encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const decipher = createBackupDecipher(keys.encryptionKey, iv, cipher.getAuthTag());
  const restored = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  assert.deepEqual(restored, plaintext);
});

test("backup authentication rejects a modified manifest", () => {
  const keys = deriveBackupKeys("cd".repeat(32));
  const manifest = signBackupManifest({
    version: 1, backup_id: "synthetic", encrypted_sha256: "a".repeat(64)
  }, keys.manifestKey);
  assert.equal(verifyBackupManifestSignature(manifest, keys.manifestKey), true);
  assert.equal(verifyBackupManifestSignature({ ...manifest, backup_id: "changed" }, keys.manifestKey), false);
});

test("backup keys require a 256-bit hexadecimal root key", () => {
  assert.throws(() => deriveBackupKeys("not-a-key"), /64 hexadecimal characters/);
});

test("AES-GCM rejects ciphertext modified after backup creation", () => {
  const keys = deriveBackupKeys("ef".repeat(32));
  const iv = randomBytes(12);
  const cipher = createBackupCipher(keys.encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from("important evidence")), cipher.final()]);
  const damaged = Buffer.from(ciphertext);
  damaged[0] ^= 0x01;
  const decipher = createBackupDecipher(keys.encryptionKey, iv, cipher.getAuthTag());
  assert.throws(() => {
    decipher.update(damaged);
    decipher.final();
  });
});
