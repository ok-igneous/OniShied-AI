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

test("PostgreSQL 16 backup is verified, restored to the requested database, and auth state is invalidated", {
  skip: !process.env.BACKUP_TEST_ADMIN_DATABASE_URL
}, async () => {
  const adminUrl = process.env.BACKUP_TEST_ADMIN_DATABASE_URL;
  const sourceName = `backup_src_${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const targetName = `backup_dst_${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const sourceUrl = databaseUrl(adminUrl, sourceName);
  const targetUrl = databaseUrl(adminUrl, targetName);
  const backupDirectory = await mkdtemp(path.join(os.tmpdir(), "onishield-backup-test-"));
  const adminEnv = postgresEnvironment(adminUrl);
  const key = "ab".repeat(32);
  const keyId = "ci-postgres16-test-key";

  const psql = async (url, sql) => run("psql", [
    "-X", "-w", "-v", "ON_ERROR_STOP=1", "-Atqc", sql
  ], postgresEnvironment(url));

  try {
    await run("psql", ["-X", "-w", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
      `CREATE DATABASE "${sourceName}"`], adminEnv);
    await run("psql", ["-X", "-w", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
      `CREATE DATABASE "${targetName}"`], adminEnv);

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

    const cliEnv = {
      ...process.env,
      DATABASE_URL: sourceUrl,
      BACKUP_DIRECTORY: backupDirectory,
      BACKUP_ENCRYPTION_KEY: key,
      BACKUP_ENCRYPTION_KEY_ID: keyId
    };
    const createOutput = await run(process.execPath, ["scripts/backup-postgres.mjs", "create"], cliEnv);
    const artifactName = createOutput.match(/^Backup created: (.+)$/m)?.[1];
    const manifestName = createOutput.match(/^Manifest: (.+)$/m)?.[1];
    assert.ok(artifactName, "backup command must report the artifact filename");
    assert.ok(manifestName, "backup command must report the manifest filename");

    const backupEnv = {
      ...cliEnv,
      BACKUP_ARTIFACT: path.join(backupDirectory, artifactName),
      BACKUP_MANIFEST: path.join(backupDirectory, manifestName)
    };
    await run(process.execPath, ["scripts/backup-postgres.mjs", "verify"], backupEnv);
    await run(process.execPath, ["scripts/backup-postgres.mjs", "restore"], {
      ...backupEnv,
      RESTORE_TARGET_DATABASE_URL: targetUrl,
      RESTORE_CONFIRMATION: "RESTORE_TO_ISOLATED_DATABASE"
    });

    const recovered = await psql(targetUrl, `
      SELECT (SELECT payload FROM public.recovery_probe WHERE id=1),
        (SELECT (revoked_at IS NOT NULL)::text FROM onishield.operator_sessions),
        (SELECT (consumed_at IS NOT NULL)::text FROM onishield.operator_login_challenges),
        (SELECT (consumed_at IS NOT NULL)::text FROM onishield.operator_email_actions),
        (SELECT (pending_ciphertext IS NULL AND pending_nonce IS NULL AND pending_tag IS NULL
          AND pending_expires_at IS NULL)::text FROM onishield.operator_mfa_credentials),
        (SELECT (used_at IS NOT NULL)::text FROM onishield.operator_mfa_recovery_codes)
    `);
    assert.equal(recovered, "restored-row|true|true|true|true|true");
  } finally {
    await run("psql", ["-X", "-w", "-d", "postgres", "-c",
      `DROP DATABASE IF EXISTS "${targetName}" WITH (FORCE)`], adminEnv).catch(() => {});
    await run("psql", ["-X", "-w", "-d", "postgres", "-c",
      `DROP DATABASE IF EXISTS "${sourceName}" WITH (FORCE)`], adminEnv).catch(() => {});
    await rm(backupDirectory, { recursive: true, force: true });
  }
});
