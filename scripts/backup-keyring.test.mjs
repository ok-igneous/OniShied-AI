import assert from "node:assert/strict";
import test from "node:test";
import { loadBackupKeyring, resolveBackupKeys } from "./backup-keyring.mjs";

const oldKey = "11".repeat(32);
const newKey = "22".repeat(32);

test("active key is selected for new backups while historical keys remain resolvable", () => {
  const ring = loadBackupKeyring({
    BACKUP_KEYRING_JSON: JSON.stringify({ "backup-2026-01": oldKey, "backup-2026-11": newKey }),
    BACKUP_ACTIVE_KEY_ID: "backup-2026-11"
  });
  assert.equal(ring.activeKeyId, "backup-2026-11");
  assert.deepEqual(resolveBackupKeys(ring, ring.activeKeyId), resolveBackupKeys(ring, "backup-2026-11"));
  assert.deepEqual(resolveBackupKeys(ring, "backup-2026-01"), resolveBackupKeys(
    loadBackupKeyring({ BACKUP_ENCRYPTION_KEY: oldKey, BACKUP_ENCRYPTION_KEY_ID: "backup-2026-01" }),
    "backup-2026-01"
  ));
});

test("historical key lookup fails closed when an old key is omitted", () => {
  const ring = loadBackupKeyring({
    BACKUP_KEYRING_JSON: JSON.stringify({ "backup-new": newKey }),
    BACKUP_ACTIVE_KEY_ID: "backup-new"
  });
  assert.throws(() => resolveBackupKeys(ring, "backup-old"), /unavailable/);
});

test("malformed keyring JSON, key material and active IDs are rejected", () => {
  assert.throws(() => loadBackupKeyring({
    BACKUP_KEYRING_JSON: "{not-json",
    BACKUP_ACTIVE_KEY_ID: "key-1"
  }), /valid JSON object/);
  assert.throws(() => loadBackupKeyring({
    BACKUP_KEYRING_JSON: JSON.stringify({ "key-1": "short" }),
    BACKUP_ACTIVE_KEY_ID: "key-1"
  }), /64 hexadecimal/);
  assert.throws(() => loadBackupKeyring({
    BACKUP_KEYRING_JSON: JSON.stringify({ "key-1": oldKey }),
    BACKUP_ACTIVE_KEY_ID: "missing"
  }), /present in BACKUP_KEYRING_JSON/);
  assert.throws(() => loadBackupKeyring({
    BACKUP_KEYRING_JSON: JSON.stringify({ "bad key": oldKey }),
    BACKUP_ACTIVE_KEY_ID: "bad key"
  }), /Backup key ID/);
});

test("legacy single-key environment remains supported during migration", () => {
  const ring = loadBackupKeyring({
    BACKUP_ENCRYPTION_KEY: oldKey,
    BACKUP_ENCRYPTION_KEY_ID: "legacy-key-01"
  });
  assert.equal(ring.source, "legacy-single-key");
  assert.equal(ring.activeKeyId, "legacy-key-01");
  assert.ok(resolveBackupKeys(ring, "legacy-key-01").encryptionKey);
});

test("keyring is bounded to prevent unbounded configuration input", () => {
  const entries = Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`key-${index}`, oldKey]));
  assert.throws(() => loadBackupKeyring({
    BACKUP_KEYRING_JSON: JSON.stringify(entries),
    BACKUP_ACTIVE_KEY_ID: "key-0"
  }), /1-32 keys/);
});
