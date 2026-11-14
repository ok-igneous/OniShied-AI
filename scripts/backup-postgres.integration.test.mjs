import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { postgresEnvironment } from "./backup-postgres-connection.mjs";

function run(command, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", code => code === 0
      ? resolve(stdout.trim())
      : reject(new Error(`${command} exited ${code}: ${stderr.trim()}`)));
  });
}

function databaseUrl(base, database) {
  const url = new URL(base);
  url.pathname = `/${database}`;
  return url.toString();
}

function keyringEnvironment(oldKey, newKey, activeKeyId) {
  return {
    BACKUP_KEYRING_JSON: JSON.stringify({
      "backup-key-old-01": oldKey,
      "backup-key-new-01": newKey
    }),
    BACKUP_ACTIVE_KEY_ID: activeKeyId
  };
}

function backupFiles(output) {
  const artifact = output.match(/^Backup created: (.+)$/m)?.[1];
  const manifest = output.match(/^Manifest: (.+)$/m)?.[1];
  assert.ok(artifact, "backup command must report the artifact filename");
  assert.ok(manifest, "backup command must report the manifest filename");
  return { artifact, manifest };
}

test("PostgreSQL backup created before key rotation remains verifiable and restorable after rotation", {
  skip: !process.env.BACKUP_TEST_ADMIN_DATABASE_URL
}, async () => {
  const adminUrl = process.env.BACKUP_TEST_ADMIN_DATABASE_URL;
  const sourceName = `backup_src_${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const oldTargetName = `backup_old_${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const newTargetName = `backup_new_${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const sourceUrl = databaseUrl(adminUrl, sourceName);
  const oldTargetUrl = databaseUrl(adminUrl, oldTargetName);
  const newTargetUrl = databaseUrl(adminUrl, newTargetName);
  const backupDirectory = await mkdtemp(path.join(os.tmpdir(), "onishield-backup-rotation-test-"));
  const adminEnv = postgresEnvironment(adminUrl);
  const oldKey = "ab".repeat(32);
  const newKey = "cd".repeat(32);
  const oldKeyId = "backup-key-old-01";
  const newKeyId = "backup-key-new-01";
  const baseCliEnv = { ...process.env, DATABASE_URL: sourceUrl, BACKUP_DIRECTORY: backupDirectory };
  delete baseCliEnv.BACKUP_ENCRYPTION_KEY;
  delete baseCliEnv.BACKUP_ENCRYPTION_KEY_ID;

  const psql = async (url, sql) => run("psql", [
    "-X", "-w", "-v", "ON_ERROR_STOP=1", "-Atqc", sql
  ], postgresEnvironment(url));

  const cli = async (action, files, keyring) => run(process.execPath, [
    "scripts/backup-postgres.mjs", action
  ], {
    ...baseCliEnv,
    ...keyring,
    ...(files ? {
      BACKUP_ARTIFACT: path.join(backupDirectory, files.artifact),
      BACKUP_MANIFEST: path.join(backupDirectory, files.manifest)
    } : {})
  });

  const restore = async (files, targetUrl, keyring) => cli("restore", files, {
    ...keyring,
    RESTORE_TARGET_DATABASE_URL: targetUrl,
    RESTORE_CONFIRMATION: "RESTORE_TO_ISOLATED_DATABASE"
  });

  try {
    for (const name of [sourceName, oldTargetName, newTargetName]) {
      await run("psql", ["-X", "-w", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
        `CREATE DATABASE "${name}"`], adminEnv);
    }

    await psql(sourceUrl, `
      CREATE TABLE public.recovery_probe(id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
      INSERT INTO public.recovery_probe VALUES (1, 'restored-row');
      CREATE SCHEMA onishield;
      CREATE TABLE onishield.operator_sessions(revoked_at TIMESTAMPTZ);
      INSERT INTO onishield.operator_sessions VALUES (NULL);
      CREATE TABLE onishield.operator_login_challenges(consumed_at TIMESTAMPTZ);
      INSERT INTO onishield.operator_login_challenges VALUES (NULL);
      CREATE TABLE onishield.operator_email_actions(consumed_at TIMESTAMPTZ);
      INSERT INTO onishield.operator_email_actions VALUES (NULL);
      CREATE TABLE onishield.operator_mfa_credentials(
        pending_ciphertext BYTEA, pending_nonce BYTEA, pending_tag BYTEA,
        pending_expires_at TIMESTAMPTZ
      );
      INSERT INTO onishield.operator_mfa_credentials
        VALUES (decode('aa','hex'),decode('bb','hex'),decode('cc','hex'),NOW()+INTERVAL '5 minutes');
      CREATE TABLE onishield.operator_mfa_recovery_codes(used_at TIMESTAMPTZ);
      INSERT INTO onishield.operator_mfa_recovery_codes VALUES (NULL);
    `);

    // Phase 1: create an artifact using the old active key.
    const oldKeyring = keyringEnvironment(oldKey, newKey, oldKeyId);
    const oldFiles = backupFiles(await cli("create", null, oldKeyring));
    assert.match(await cli("verify", oldFiles, oldKeyring), /integrity and PostgreSQL archive validation passed/);

    // Phase 2: rotate the active key, retaining the old key for historical recovery.
    const rotatedKeyring = keyringEnvironment(oldKey, newKey, newKeyId);
    assert.match(await cli("verify", oldFiles, rotatedKeyring), /integrity and PostgreSQL archive validation passed/);
    await restore(oldFiles, oldTargetUrl, rotatedKeyring);

    // New backups must use the new active key while old backups remain recoverable.
    const newFiles = backupFiles(await cli("create", null, rotatedKeyring));
    const newManifest = JSON.parse(await (await import("node:fs/promises")).readFile(
      path.join(backupDirectory, newFiles.manifest), "utf8"
    ));
    assert.equal(newManifest.key_id, newKeyId);
    assert.match(await cli("verify", newFiles, rotatedKeyring), /integrity and PostgreSQL archive validation passed/);
    await restore(newFiles, newTargetUrl, rotatedKeyring);

    const recoveredSql = `
      SELECT (SELECT payload FROM public.recovery_probe WHERE id=1),
        (SELECT (revoked_at IS NOT NULL)::text FROM onishield.operator_sessions),
        (SELECT (consumed_at IS NOT NULL)::text FROM onishield.operator_login_challenges),
        (SELECT (consumed_at IS NOT NULL)::text FROM onishield.operator_email_actions),
        (SELECT (pending_ciphertext IS NULL AND pending_nonce IS NULL AND pending_tag IS NULL
          AND pending_expires_at IS NULL)::text FROM onishield.operator_mfa_credentials),
        (SELECT (used_at IS NOT NULL)::text FROM onishield.operator_mfa_recovery_codes)
    `;
    assert.equal(await psql(oldTargetUrl, recoveredSql), "restored-row|true|true|true|true|true");
    assert.equal(await psql(newTargetUrl, recoveredSql), "restored-row|true|true|true|true|true");

    // Removing the old key must fail closed rather than silently trying the active key.
    const newOnlyKeyring = {
      BACKUP_KEYRING_JSON: JSON.stringify({ [newKeyId]: newKey }),
      BACKUP_ACTIVE_KEY_ID: newKeyId
    };
    await assert.rejects(cli("verify", oldFiles, newOnlyKeyring), /key ID .* unavailable/);
  } finally {
    for (const name of [newTargetName, oldTargetName, sourceName]) {
      await run("psql", ["-X", "-w", "-d", "postgres", "-c",
        `DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`], adminEnv).catch(() => {});
    }
    await rm(backupDirectory, { recursive: true, force: true });
  }
});
