import { deriveBackupKeys } from "./backup-crypto.mjs";

const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_KEYRING_ENTRIES = 32;

function validateKeyId(keyId) {
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) {
    throw new Error("Backup key ID must be 1-64 safe alphanumeric, dot, underscore or hyphen characters");
  }
  return keyId;
}

export function loadBackupKeyring(environment = process.env) {
  const serialized = environment.BACKUP_KEYRING_JSON;
  if (serialized !== undefined && serialized !== "") {
    let parsed;
    try {
      parsed = JSON.parse(serialized);
    } catch {
      throw new Error("BACKUP_KEYRING_JSON must contain a valid JSON object");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
        Object.getPrototypeOf(parsed) !== Object.prototype) {
      throw new Error("BACKUP_KEYRING_JSON must be a plain object mapping key IDs to 64-character hex keys");
    }
    const entries = Object.entries(parsed);
    if (entries.length === 0 || entries.length > MAX_KEYRING_ENTRIES) {
      throw new Error(`Backup keyring must contain 1-${MAX_KEYRING_ENTRIES} keys`);
    }
    const keys = new Map();
    for (const [keyId, keyHex] of entries) {
      validateKeyId(keyId);
      if (typeof keyHex !== "string" || !/^[a-fA-F0-9]{64}$/.test(keyHex)) {
        throw new Error(`Backup key material for ID ${keyId} must be exactly 64 hexadecimal characters`);
      }
      keys.set(keyId, deriveBackupKeys(keyHex));
    }
    const activeKeyId = validateKeyId(environment.BACKUP_ACTIVE_KEY_ID);
    if (!keys.has(activeKeyId)) {
      throw new Error("BACKUP_ACTIVE_KEY_ID must identify a key present in BACKUP_KEYRING_JSON");
    }
    return Object.freeze({ activeKeyId, keys, source: "keyring" });
  }

  // Compatibility path for existing single-key deployments. New deployments should use a keyring.
  const legacyKeyId = validateKeyId(environment.BACKUP_ENCRYPTION_KEY_ID);
  const legacyKey = environment.BACKUP_ENCRYPTION_KEY;
  if (typeof legacyKey !== "string" || !/^[a-fA-F0-9]{64}$/.test(legacyKey)) {
    throw new Error("Configure BACKUP_KEYRING_JSON and BACKUP_ACTIVE_KEY_ID, or the legacy BACKUP_ENCRYPTION_KEY and BACKUP_ENCRYPTION_KEY_ID pair");
  }
  return Object.freeze({
    activeKeyId: legacyKeyId,
    keys: new Map([[legacyKeyId, deriveBackupKeys(legacyKey)]]),
    source: "legacy-single-key"
  });
}

export function resolveBackupKeys(keyring, keyId) {
  validateKeyId(keyId);
  const keys = keyring?.keys?.get(keyId);
  if (!keys) {
    throw new Error(`Backup encryption key ID "${keyId}" is unavailable; restore the matching historical key from the secrets manager`);
  }
  return keys;
}
