import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
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

const enabled = process.env.BACKUP_S3_TEST_ENABLE === "YES_I_UNDERSTAND_IMMUTABLE_UPLOADS";
const bucket = process.env.BACKUP_S3_TEST_BUCKET;
const prefix = process.env.BACKUP_S3_TEST_PREFIX;
const adminUrl = process.env.BACKUP_TEST_ADMIN_DATABASE_URL;
const configured = enabled && bucket && prefix && adminUrl && prefix.split("/").includes("integration-tests");

test("S3 immutable-vault download and isolated PostgreSQL restore survive key rotation", {
  skip: !configured
    ? "Requires explicit immutable-upload opt-in, dedicated test bucket/prefix, and PostgreSQL admin URL"
    : false,
  timeout: 10 * 60 * 1000
}, async () => {
  const names = ["source", "old", "old_after_rotation", "new"].map(
    label => `backup_s3_${label}_${randomUUID().replaceAll("-", "").slice(0, 12)}`
  );
  const [sourceName, oldTargetName, oldRotatedTargetName, newTargetName] = names;
  const sourceUrl = databaseUrl(adminUrl, sourceName);
  const backupDirectory = await mkdtemp(path.join(os.tmpdir(), "onishield-s3-backup-"));
  const oldDownloadDirectory = await mkdtemp(path.join(os.tmpdir(), "onishield-s3-old-"));
  const oldRotatedDownloadDirectory = await mkdtemp(path.join(os.tmpdir(), "onishield-s3-old-rotated-"));
  const newDownloadDirectory = await mkdtemp(path.join(os.tmpdir(), "onishield-s3-new-"));
  const adminEnv = postgresEnvironment(adminUrl);
  const oldKey = "ab".repeat(32);
  const newKey = "cd".repeat(32);
  const oldKeyId = "backup-key-old-01";
  const newKeyId = "backup-key-new-01";
  const baseEnv = {
    ...process.env,
    DATABASE_URL: sourceUrl,
    BACKUP_DIRECTORY: backupDirectory,
    S3_BUCKET: bucket,
    S3_PREFIX: prefix,
    S3_RETENTION_DAYS: "1"
  };
  delete baseEnv.BACKUP_ENCRYPTION_KEY;
  delete baseEnv.BACKUP_ENCRYPTION_KEY_ID;

  const psql = async (url, sql) => run("psql", [
    "-X", "-w", "-v", "ON_ERROR_STOP=1", "-Atqc", sql
  ], postgresEnvironment(url));

  const cli = (action, env = {}) => run(process.execPath, [
    "scripts/backup-postgres.mjs", action
  ], { ...baseEnv, ...env });

  const restoreDownloaded = async (files, directory, targetName, keyring) => {
    const targetUrl = databaseUrl(adminUrl, targetName);
    await run(process.execPath, ["scripts/backup-postgres.mjs", "restore"], {
      ...baseEnv,
      ...keyring,
      BACKUP_ARTIFACT: path.join(directory, files.artifact),
      BACKUP_MANIFEST: path.join(directory, files.manifest),
      RESTORE_TARGET_DATABASE_URL: targetUrl,
      RESTORE_CONFIRMATION: "RESTORE_TO_ISOLATED_DATABASE"
    });
    assert.equal(await psql(targetUrl,
      "SELECT payload FROM public.recovery_probe WHERE id=1"), "remote-vault-recovered");
  };

  const upload = async (files, keyring) => {
    const manifest = JSON.parse(await readFile(path.join(backupDirectory, files.manifest), "utf8"));
    const output = await run(process.execPath, ["scripts/backup-s3.mjs", "upload"], {
      ...baseEnv,
      ...keyring,
      BACKUP_ARTIFACT: path.join(backupDirectory, files.artifact),
      BACKUP_MANIFEST: path.join(backupDirectory, files.manifest)
    });
    const result = JSON.parse(output);
    assert.equal(result.status, "uploaded_and_remote_metadata_verified");
    assert.ok(result.artifact.version_id, "upload must return the immutable artifact version ID");
    assert.ok(result.manifest.version_id, "upload must return the immutable manifest version ID");
    return {
      backupId: manifest.backup_id,
      artifactVersionId: result.artifact.version_id,
      manifestVersionId: result.manifest.version_id
    };
  };

  const download = async (uploaded, directory, keyring, artifactName) => {
    assert.match(artifactName, /^[A-Za-z0-9._-]+\\.pgdump\\.enc$/);
    const manifestName = `${backupId}.manifest.json`;
    const output = await run(process.execPath, ["scripts/backup-s3.mjs", "download"], {
      ...baseEnv,
      ...keyring,
      S3_BACKUP_ID: uploaded.backupId,
      S3_ARTIFACT_VERSION_ID: uploaded.artifactVersionId,
      S3_MANIFEST_VERSION_ID: uploaded.manifestVersionId,
      BACKUP_ARTIFACT: path.join(directory, artifactName),
      BACKUP_MANIFEST: path.join(directory, manifestName)
    });
    assert.match(output, /downloaded_and_locally_verified/);
    return { artifact: artifactName, manifest: manifestName, output };
  };

  try {
    for (const name of names) {
      await run("psql", ["-X", "-w", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
        `CREATE DATABASE "${name}"`], adminEnv);
    }
    await psql(sourceUrl, `
      CREATE TABLE public.recovery_probe(id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
      INSERT INTO public.recovery_probe VALUES (1, 'remote-vault-recovered');
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

    const oldKeyring = keyringEnvironment(oldKey, newKey, oldKeyId);
    const oldFiles = backupFiles(await cli("create", oldKeyring));
    const oldManifest = JSON.parse(await readFile(path.join(backupDirectory, oldFiles.manifest), "utf8"));
    assert.equal(oldManifest.key_id, oldKeyId);
    const oldBackup = await upload(oldFiles, oldKeyring);

    // Rotate the active key but retain the old key so remote historical backups remain recoverable.
    const rotatedKeyring = keyringEnvironment(oldKey, newKey, newKeyId);
    const oldRemoteFiles = await download(oldBackup, oldDownloadDirectory, rotatedKeyring, oldManifest.artifact);
    await restoreDownloaded(oldRemoteFiles, oldDownloadDirectory, oldTargetName, rotatedKeyring);

    // Repeat the historical restore from a second fresh download to ensure the vault copy remains usable.
    const oldAgain = await download(oldBackup, oldRotatedDownloadDirectory, rotatedKeyring, oldManifest.artifact);
    await restoreDownloaded(oldAgain, oldRotatedDownloadDirectory, oldRotatedTargetName, rotatedKeyring);

    const newFiles = backupFiles(await cli("create", rotatedKeyring));
    const newManifest = JSON.parse(await readFile(path.join(backupDirectory, newFiles.manifest), "utf8"));
    assert.equal(newManifest.key_id, newKeyId);
    const newBackup = await upload(newFiles, rotatedKeyring);
    const newRemoteFiles = await download(newBackup, newDownloadDirectory, rotatedKeyring, newManifest.artifact);
    await restoreDownloaded(newRemoteFiles, newDownloadDirectory, newTargetName, rotatedKeyring);

    for (const targetName of [oldTargetName, oldRotatedTargetName, newTargetName]) {
      const targetUrl = databaseUrl(adminUrl, targetName);
      assert.equal(await psql(targetUrl, `
        SELECT (SELECT revoked_at IS NOT NULL FROM onishield.operator_sessions)
          AND (SELECT consumed_at IS NOT NULL FROM onishield.operator_login_challenges)
          AND (SELECT consumed_at IS NOT NULL FROM onishield.operator_email_actions)
          AND (SELECT pending_ciphertext IS NULL AND pending_nonce IS NULL
            AND pending_tag IS NULL AND pending_expires_at IS NULL
            FROM onishield.operator_mfa_credentials)
          AND (SELECT used_at IS NOT NULL FROM onishield.operator_mfa_recovery_codes)
      `), "t");
    }

    const newOnlyKeyring = {
      BACKUP_KEYRING_JSON: JSON.stringify({ [newKeyId]: newKey }),
      BACKUP_ACTIVE_KEY_ID: newKeyId
    };
    await assert.rejects(
      run(process.execPath, ["scripts/backup-postgres.mjs", "verify"], {
        ...baseEnv,
        ...newOnlyKeyring,
        BACKUP_ARTIFACT: path.join(oldDownloadDirectory, oldRemoteFiles.artifact),
        BACKUP_MANIFEST: path.join(oldDownloadDirectory, oldRemoteFiles.manifest)
      }),
      /key ID .* unavailable/
    );
  } finally {
    for (const name of [...names].reverse()) {
      await run("psql", ["-X", "-w", "-d", "postgres", "-c",
        `DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`], adminEnv).catch(() => {});
    }
    await Promise.all([
      rm(backupDirectory, { recursive: true, force: true }),
      rm(oldDownloadDirectory, { recursive: true, force: true }),
      rm(oldRotatedDownloadDirectory, { recursive: true, force: true }),
      rm(newDownloadDirectory, { recursive: true, force: true })
    ]);
  }
});
