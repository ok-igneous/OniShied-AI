import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface EncryptedMfaSecret { ciphertext: Buffer; nonce: Buffer; authTag: Buffer; }

function encryptionKey(encoded: string): Buffer {
  if (!/^[a-f0-9]{64}$/i.test(encoded)) {
    throw new Error("MFA_ENCRYPTION_KEY must be exactly 64 hexadecimal characters");
  }
  return Buffer.from(encoded, "hex");
}

export function encryptMfaSecret(secret: string, encodedKey: string): EncryptedMfaSecret {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(encodedKey), nonce);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}

export function decryptMfaSecret(
  encrypted: EncryptedMfaSecret,
  encodedKey: string
): string {
  if (encrypted.nonce.length !== 12 || encrypted.authTag.length !== 16 ||
      encrypted.ciphertext.length < 16 || encrypted.ciphertext.length > 256) {
    throw new Error("Invalid encrypted MFA secret");
  }
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(encodedKey), encrypted.nonce);
  decipher.setAuthTag(encrypted.authTag);
  return Buffer.concat([
    decipher.update(encrypted.ciphertext),
    decipher.final()
  ]).toString("utf8");
}
