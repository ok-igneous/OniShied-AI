import { createCipheriv, createDecipheriv, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

export const BACKUP_MAGIC = Buffer.from("ONIBKP01", "ascii");
export const BACKUP_HEADER_BYTES = BACKUP_MAGIC.length + 12;
export const BACKUP_TAG_BYTES = 16;

export function deriveBackupKeys(masterKeyHex) {
  if (!/^[a-fA-F0-9]{64}$/.test(masterKeyHex ?? "")) {
    throw new Error("BACKUP_ENCRYPTION_KEY must be exactly 64 hexadecimal characters");
  }
  const master = Buffer.from(masterKeyHex, "hex");
  const material = Buffer.from(hkdfSync(
    "sha256", master, Buffer.from("onishield-backup-v1"), Buffer.from("encryption-and-manifest-authentication"), 64
  ));
  return { encryptionKey: material.subarray(0, 32), manifestKey: material.subarray(32, 64) };
}

export function createBackupCipher(encryptionKey, iv) {
  if (encryptionKey.length !== 32 || iv.length !== 12) throw new Error("Invalid AES-256-GCM key or IV length");
  return createCipheriv("aes-256-gcm", encryptionKey, iv);
}

export function createBackupDecipher(encryptionKey, iv, authTag) {
  if (encryptionKey.length !== 32 || iv.length !== 12 || authTag.length !== BACKUP_TAG_BYTES) {
    throw new Error("Invalid AES-256-GCM backup header or authentication tag");
  }
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(authTag);
  return decipher;
}

function manifestPayload(manifest) {
  const { manifest_hmac: ignored, ...payload } = manifest;
  return Buffer.from(JSON.stringify(payload), "utf8");
}

export function signBackupManifest(manifest, manifestKey) {
  return {
    ...manifest,
    manifest_hmac: createHmac("sha256", manifestKey).update(manifestPayload(manifest)).digest("hex")
  };
}

export function verifyBackupManifestSignature(manifest, manifestKey) {
  if (!/^[a-f0-9]{64}$/.test(manifest?.manifest_hmac ?? "")) return false;
  const expected = createHmac("sha256", manifestKey).update(manifestPayload(manifest)).digest();
  const actual = Buffer.from(manifest.manifest_hmac, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
