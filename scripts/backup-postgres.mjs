import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import {
  BACKUP_HEADER_BYTES, BACKUP_MAGIC, BACKUP_TAG_BYTES,
  createBackupCipher, createBackupDecipher, deriveBackupKeys,
  signBackupManifest, verifyBackupManifestSignature
} from "./backup-crypto.mjs";

const action = process.argv[2];
const backupDirectory = path.resolve(process.env.BACKUP_DIRECTORY || "./var/backups");
const databaseUrl = process.env.DATABASE_URL;
const masterKey = process.env.BACKUP_ENCRYPTION_KEY;
const keyId = process.env.BACKUP_ENCRYPTION_KEY_ID;

function required(value, name) {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function databaseIdentity(value) {
  const url = new URL(value);
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname ||
      !url.pathname || url.pathname === "/") {
    throw new Error("A valid PostgreSQL connection URL with a database name is required");
  }
  return { host: url.hostname, port: url.port || "5432", database: decodeURIComponent(url.pathname.slice(1)) };
}

function localHost(host) {
  return ["localhost", "127.0.0.1", "::1"].includes(host);
}


async function hashFile(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function readBackup(artifactPath, manifestPath) {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const info = await stat(artifactPath);
  if (manifest.format !== "onishield-postgres-custom-aes-256-gcm-v1" ||
      manifest.artifact !== path.basename(artifactPath) ||
      info.size !== manifest.encrypted_bytes ||
      info.size < BACKUP_HEADER_BYTES + BACKUP_TAG_BYTES + 1) {
    throw new Error("Backup manifest or artifact size is invalid");
  }
  const keys = deriveBackupKeys(required(masterKey, "BACKUP_ENCRYPTION_KEY"));
  if (manifest.key_id !== required(keyId, "BACKUP_ENCRYPTION_KEY_ID") ||
      !verifyBackupManifestSignature(manifest, keys.manifestKey)) {
    throw new Error("Backup manifest authentication failed or key ID does not match");
  }
  if (await hashFile(artifactPath) !== manifest.encrypted_sha256) {
    throw new Error("Encrypted backup checksum mismatch");
  }
  const handle = await open(artifactPath, "r");
  const header = Buffer.alloc(BACKUP_HEADER_BYTES);
  const tag = Buffer.alloc(BACKUP_TAG_BYTES);
  try {
    await handle.read(header, 0, header.length, 0);
    await handle.read(tag, 0, tag.length, info.size - tag.length);
  } finally {
    await handle.close();
  }
  if (!header.subarray(0, BACKUP_MAGIC.length).equals(BACKUP_MAGIC)) {
    throw new Error("Unknown backup artifact format");
  }
  return { manifest, info, iv: header.subarray(BACKUP_MAGIC.length), tag, keys };
}

function decryptedStream(artifactPath, info, iv, tag, encryptionKey) {
  const decipher = createBackupDecipher(encryptionKey, iv, tag);
  const ciphertext = createReadStream(artifactPath, {
    start: BACKUP_HEADER_BYTES,
    end: info.size - BACKUP_TAG_BYTES - 1
  });
  return { decipher, ciphertext };
}

async function createBackup() {
  required(databaseUrl, "DATABASE_URL");
  required(keyId, "BACKUP_ENCRYPTION_KEY_ID");
  const keys = deriveBackupKeys(required(masterKey, "BACKUP_ENCRYPTION_KEY"));
  await mkdir(backupDirectory, { recursive: true, mode: 0o700 });
  await chmod(backupDirectory, 0o700);
  const id = `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID()}`;
  const artifact = `${id}.pgdump.enc`;
  const artifactPath = path.join(backupDirectory, artifact);
  const temporaryPath = `${artifactPath}.partial`;
  const manifestTemporaryPath = path.join(backupDirectory, `${id}.manifest.json.partial`);
  const iv = randomBytes(12);
  const cipher = createBackupCipher(keys.encryptionKey, iv);
  const output = createWriteStream(temporaryPath, { mode: 0o600, flags: "wx" });
  const child = spawn("pg_dump", ["--no-password", "--format=custom", "--no-owner", "--no-acl"], {
    env: { ...process.env, PGDATABASE: databaseUrl },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-12000); });
  const exit = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve() : reject(
      new Error(`pg_dump exited with code ${code}: ${stderr.trim()}`)
    ));
  });
  try {
    output.write(Buffer.concat([BACKUP_MAGIC, iv]));
    await Promise.all([pipeline(child.stdout, cipher, output), exit]);
    await writeFile(temporaryPath, cipher.getAuthTag(), { flag: "a", mode: 0o600 });
    await rename(temporaryPath, artifactPath);
    const encryptedBytes = (await stat(artifactPath)).size;
    const manifest = signBackupManifest({
      version: 1,
      backup_id: id,
      created_at: new Date().toISOString(),
      format: "onishield-postgres-custom-aes-256-gcm-v1",
      artifact,
      encrypted_bytes: encryptedBytes,
      encrypted_sha256: await hashFile(artifactPath),
      key_id: keyId,
      source: databaseIdentity(databaseUrl),
      scope: "single PostgreSQL database; global roles and cluster-wide objects are excluded",
      database_server_version: await queryScalar(databaseUrl, "SHOW server_version"),
      pg_dump_version: (await commandOutput("pg_dump", ["--version"])).trim()
    }, keys.manifestKey);
    const manifestPath = path.join(backupDirectory, `${id}.manifest.json`);
    const manifestTemporary = `${manifestPath}.partial`;
    await writeFile(manifestTemporary, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    await rename(manifestTemporary, manifestPath);
    process.stdout.write(`Backup created: ${artifact}\nManifest: ${path.basename(manifestPath)}\n`);
  } catch (error) {
    child.kill("SIGTERM");
    await rm(temporaryPath, { force: true });
    await rm(artifactPath, { force: true });
    await rm(manifestTemporaryPath, { force: true });
    throw error;
  }
}

function commandOutput(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve(stdout) : reject(new Error(stderr)));
  });
}

async function validateArchive(artifactPath, info, iv, tag, encryptionKey) {
  const { decipher, ciphertext } = decryptedStream(artifactPath, info, iv, tag, encryptionKey);
  const child = spawn("pg_restore", ["--no-password", "--list"], { stdio: ["pipe", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-12000); });
  const exit = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve() : reject(new Error(
      `pg_restore archive validation failed: ${stderr.trim()}`
    )));
  });
  await Promise.all([pipeline(ciphertext, decipher, child.stdin), exit]);
}

async function verifyBackup() {
  const artifactPath = path.resolve(required(process.env.BACKUP_ARTIFACT, "BACKUP_ARTIFACT"));
  const manifestPath = path.resolve(required(process.env.BACKUP_MANIFEST, "BACKUP_MANIFEST"));
  const { manifest, info, iv, tag, keys } = await readBackup(artifactPath, manifestPath);
  await validateArchive(artifactPath, info, iv, tag, keys.encryptionKey);
  process.stdout.write(`Backup integrity and PostgreSQL archive validation passed: ${manifest.backup_id}\\n`);
}

async function restoreBackup() {
  const artifactPath = path.resolve(required(process.env.BACKUP_ARTIFACT, "BACKUP_ARTIFACT"));
  const manifestPath = path.resolve(required(process.env.BACKUP_MANIFEST, "BACKUP_MANIFEST"));
  const targetUrl = required(process.env.RESTORE_TARGET_DATABASE_URL, "RESTORE_TARGET_DATABASE_URL");
  if (process.env.RESTORE_CONFIRMATION !== "RESTORE_TO_ISOLATED_DATABASE") {
    throw new Error("Set RESTORE_CONFIRMATION=RESTORE_TO_ISOLATED_DATABASE to authorize an isolated restore");
  }
  const target = databaseIdentity(targetUrl);
  if (!localHost(target.host) && process.env.RESTORE_ALLOW_REMOTE_TARGET !== "YES_I_UNDERSTAND") {
    throw new Error("Restore target must be loopback unless RESTORE_ALLOW_REMOTE_TARGET=YES_I_UNDERSTAND is explicitly set");
  }
  const { manifest, info, iv, tag, keys } = await readBackup(artifactPath, manifestPath);
  if (target.database === manifest.source.database) {
    throw new Error("Restore target database name must differ from the source database name");
  }
  // Authenticate/decrypt the complete archive before connecting to the target.
  await validateArchive(artifactPath, info, iv, tag, keys.encryptionKey);
  const objectCount = await queryScalar(targetUrl, `
    SELECT
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
         AND c.relkind IN ('r','p','v','m','S','f'))
      + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
         WHERE n.nspname NOT IN ('pg_catalog','information_schema'))
      + (SELECT count(*) FROM pg_namespace
         WHERE nspname NOT IN ('pg_catalog','information_schema','public','pg_toast'))
      + (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql')
  `);
  if (Number(objectCount) !== 0) throw new Error("Restore target is not empty; no objects were changed");
  const { decipher, ciphertext } = decryptedStream(artifactPath, info, iv, tag, keys.encryptionKey);
  const child = spawn("pg_restore", [
    "--no-password", "--exit-on-error", "--no-owner", "--no-acl", "--single-transaction"
  ], { env: { ...process.env, PGDATABASE: targetUrl }, stdio: ["pipe", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-12000); });
  const exit = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve() : reject(new Error(
      `pg_restore failed: ${stderr.trim()}`
    )));
  });
  await Promise.all([pipeline(ciphertext, decipher, child.stdin), exit]);
  await invalidateRestoredAuthenticationState(targetUrl);
  process.stdout.write(`Restore completed into isolated database ${target.database}; restored sessions and one-time authentication material were invalidated. Run application and tenant-integrity checks before any cutover.\\n`);
}

async function invalidateRestoredAuthenticationState(targetUrl) {
  const sql = `
    DO $restore_security$
    BEGIN
      IF to_regclass('onishield.operator_sessions') IS NOT NULL THEN
        EXECUTE 'UPDATE onishield.operator_sessions SET revoked_at=COALESCE(revoked_at,NOW()) WHERE revoked_at IS NULL';
      END IF;
      IF to_regclass('onishield.operator_login_challenges') IS NOT NULL THEN
        EXECUTE 'UPDATE onishield.operator_login_challenges SET consumed_at=COALESCE(consumed_at,NOW()) WHERE consumed_at IS NULL';
      END IF;
      IF to_regclass('onishield.operator_email_actions') IS NOT NULL THEN
        EXECUTE 'UPDATE onishield.operator_email_actions SET consumed_at=COALESCE(consumed_at,NOW()) WHERE consumed_at IS NULL';
      END IF;
      IF to_regclass('onishield.operator_mfa_credentials') IS NOT NULL THEN
        EXECUTE 'UPDATE onishield.operator_mfa_credentials SET pending_ciphertext=NULL,pending_nonce=NULL,pending_tag=NULL,pending_expires_at=NULL WHERE pending_ciphertext IS NOT NULL';
      END IF;
      IF to_regclass('onishield.operator_mfa_recovery_codes') IS NOT NULL THEN
        EXECUTE 'UPDATE onishield.operator_mfa_recovery_codes SET used_at=COALESCE(used_at,NOW()) WHERE used_at IS NULL';
      END IF;
    END
    $restore_security$;
  `;
  try {
    await queryScalar(targetUrl, sql);
  } catch {
    throw new Error("Database restore completed, but post-restore authentication invalidation failed. Keep the database isolated and do not start application services.");
  }
}

async function queryScalar(url, sql) {
  return new Promise((resolve, reject) => {
    const child = spawn("psql", ["-X", "-w", "-v", "ON_ERROR_STOP=1", "-Atqc", sql], {
      env: { ...process.env, PGDATABASE: url }, stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve(stdout.trim()) : reject(new Error(stderr.trim())));
  });
}

try {
  if (action === "create") await createBackup();
  else if (action === "verify") await verifyBackup();
  else if (action === "restore") await restoreBackup();
  else throw new Error("Usage: node scripts/backup-postgres.mjs <create|verify|restore>");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Backup operation failed");
  process.exitCode = 1;
}
