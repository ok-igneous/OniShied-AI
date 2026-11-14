import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { readFile, rm, stat } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import {
  GetBucketObjectLockConfigurationCommand,
  GetObjectCommand,
  GetBucketVersioningCommand,
  HeadObjectCommand,
  S3Client
} from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";

function required(value, name) {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function integerSetting(value, fallback, name, minimum, maximum) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return parsed;
}

async function sha256(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function runLocalVerification(artifactPath, manifestPath) {
  const scriptPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "backup-postgres.mjs");
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, "verify"], {
      env: { ...process.env, BACKUP_ARTIFACT: artifactPath, BACKUP_MANIFEST: manifestPath },
      stdio: ["ignore", "inherit", "inherit"]
    });
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve() : reject(
      new Error("Local backup verification failed; refusing off-site upload")
    ));
  });
}

async function headAndVerify(client, bucket, key, expected, retentionDate) {
  const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
  if (!head.VersionId ||
      head.Metadata?.sha256 !== expected.sha256 ||
      head.Metadata?.backup_id !== expected.backupId ||
      head.Metadata?.object_kind !== expected.kind ||
      !head.VersionId ||
      head.ObjectLockMode !== "COMPLIANCE" ||
      !head.ObjectLockRetainUntilDate ||
      new Date(head.ObjectLockRetainUntilDate) < retentionDate ||
      head.ContentLength !== expected.size) {
    throw new Error(`Remote object verification or compliance retention check failed for ${key}`);
  }
  return { version_id: head.VersionId, size: head.ContentLength, retain_until: head.ObjectLockRetainUntilDate };
}

async function downloadLockedObject(client, bucket, key, destination, expected, kind, backupId) {
  const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
  if (!head.VersionId || head.Metadata?.backup_id !== backupId ||
      head.Metadata?.object_kind !== kind || head.ObjectLockMode !== "COMPLIANCE" ||
      !head.ObjectLockRetainUntilDate || !Number.isInteger(head.ContentLength)) {
    throw new Error(`Remote object is missing required identity, version or COMPLIANCE retention: ${key}`);
  }
  const response = await client.send(new GetObjectCommand({
    Bucket: bucket, Key: key, VersionId: head.VersionId
  }));
  const output = createWriteStream(destination, { flags: "wx", mode: 0o600 });
  let created = false;
  output.once("open", () => { created = true; });
  try {
    await pipeline(response.Body, output);
  } catch (error) {
    if (created) await rm(destination, { force: true });
    throw error;
  }
  const info = await stat(destination);
  const digest = await sha256(destination);
  if (info.size !== head.ContentLength || digest !== head.Metadata.sha256 ||
      (expected?.sha256 && digest !== expected.sha256)) {
    await rm(destination, { force: true });
    throw new Error(`Downloaded object integrity check failed: ${key}`);
  }
  return { version_id: head.VersionId, size: info.size, sha256: digest };
}

async function downloadBackup(client, bucket, baseKey, backupId) {
  const artifactPath = path.resolve(required(process.env.BACKUP_ARTIFACT, "BACKUP_ARTIFACT"));
  const manifestPath = path.resolve(required(process.env.BACKUP_MANIFEST, "BACKUP_MANIFEST"));
  const manifestName = `${backupId}.manifest.json`;
  if (path.basename(manifestPath) !== manifestName) {
    throw new Error(`BACKUP_MANIFEST must end with ${manifestName}`);
  }
  const manifestKey = `${baseKey}/${manifestName}`;
  let manifestDownloaded = false;
  let artifactDownloaded = false;
  try {
    const manifestObject = await downloadLockedObject(
      client, bucket, manifestKey, manifestPath, null, "authenticated-backup-manifest", backupId
    );
    manifestDownloaded = true;
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (manifest.backup_id !== backupId || typeof manifest.artifact !== "string" ||
        manifest.artifact.length > 220 || !manifest.artifact.endsWith(".pgdump.enc") ||
        path.basename(manifest.artifact) !== manifest.artifact ||
        path.basename(artifactPath) !== manifest.artifact) {
      throw new Error("Downloaded manifest identity does not match requested backup or artifact path");
    }
    const artifactKey = `${baseKey}/${manifest.artifact}`;
    const artifactObject = await downloadLockedObject(
      client, bucket, artifactKey, artifactPath,
      { sha256: manifest.encrypted_sha256 }, "encrypted-postgresql-artifact", backupId
    );
    artifactDownloaded = true;
    await runLocalVerification(artifactPath, manifestPath);
    return {
      backup_id: backupId,
      artifact: { key: artifactKey, ...artifactObject },
      manifest: { key: manifestKey, ...manifestObject },
      local_verification: "passed"
    };
  } catch (error) {
    if (artifactDownloaded) await rm(artifactPath, { force: true });
    if (manifestDownloaded) await rm(manifestPath, { force: true });
    throw error;
  }
}

async function uploadLockedObject(client, bucket, key, file, metadata, retentionDate, contentType) {
  const upload = new Upload({
    client,
    params: {
      Bucket: bucket,
      Key: key,
      Body: createReadStream(file),
      ContentType: contentType,
      Metadata: {
        sha256: metadata.sha256,
        backup_id: metadata.backupId,
        object_kind: metadata.kind
      },
      ObjectLockMode: "COMPLIANCE",
      ObjectLockRetainUntilDate: retentionDate
    },
    queueSize: 4,
    partSize: 16 * 1024 * 1024,
    leavePartsOnError: false
  });
  await upload.done();
  return headAndVerify(client, bucket, key, metadata, retentionDate);
}

async function main() {
  const action = process.argv[2];
  if (!["upload", "download"].includes(action)) {
    throw new Error("Usage: node scripts/backup-s3.mjs <upload|download>");
  }
  const bucket = required(process.env.S3_BUCKET, "S3_BUCKET");
  const region = process.env.S3_REGION || "us-east-1";
  if (process.env.S3_ENDPOINT) {
    const endpoint = new URL(process.env.S3_ENDPOINT);
    if (endpoint.protocol !== "https:") {
      throw new Error("S3_ENDPOINT must use HTTPS; plaintext object-storage connections are refused");
    }
  }
  const prefix = (process.env.S3_PREFIX || "onishield/postgres").split("/").filter(Boolean).join("/");
  if (prefix.split("/").some(part => part === "." || part === "..")) {
    throw new Error("S3_PREFIX cannot contain dot path segments");
  }
  const client = new S3Client({
    region,
    ...(process.env.S3_ENDPOINT ? { endpoint: process.env.S3_ENDPOINT } : {}),
    forcePathStyle: process.env.S3_FORCE_PATH_STYLE === "true"
  });
  try {
    const versioning = await client.send(new GetBucketVersioningCommand({ Bucket: bucket }));
    if (versioning.Status !== "Enabled") {
      throw new Error("Destination bucket versioning must be Enabled before vault operations");
    }
    const lock = await client.send(new GetBucketObjectLockConfigurationCommand({ Bucket: bucket }));
    if (lock.ObjectLockConfiguration?.ObjectLockEnabled !== "Enabled") {
      throw new Error("Destination bucket must have S3 Object Lock enabled; refusing a mutable vault");
    }

    if (action === "download") {
      const backupId = required(process.env.S3_BACKUP_ID, "S3_BACKUP_ID");
      if (!/^[A-Za-z0-9._-]{1,180}$/.test(backupId)) {
        throw new Error("S3_BACKUP_ID contains invalid characters");
      }
      const baseKey = [prefix, backupId].filter(Boolean).join("/");
      const result = await downloadBackup(client, bucket, baseKey, backupId);
      process.stdout.write(JSON.stringify({
        status: "downloaded_and_locally_verified", bucket, region, ...result
      }, null, 2) + String.fromCharCode(10));
      return;
    }

    const artifactPath = path.resolve(required(process.env.BACKUP_ARTIFACT, "BACKUP_ARTIFACT"));
    const manifestPath = path.resolve(required(process.env.BACKUP_MANIFEST, "BACKUP_MANIFEST"));
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (!/^[A-Za-z0-9._-]{1,180}$/.test(manifest.backup_id || "") ||
        path.basename(manifestPath) !== `${manifest.backup_id}.manifest.json` ||
        manifest.artifact !== path.basename(artifactPath)) {
      throw new Error("Backup manifest identity does not match the selected artifact");
    }
    const artifactInfo = await stat(artifactPath);
    const manifestInfo = await stat(manifestPath);
    if (artifactInfo.size !== manifest.encrypted_bytes ||
        await sha256(artifactPath) !== manifest.encrypted_sha256) {
      throw new Error("Local artifact size or SHA-256 does not match its manifest");
    }

    // Verify manifest authentication, AES-GCM tag and PostgreSQL archive parsing before upload.
    await runLocalVerification(artifactPath, manifestPath);
    const retentionDays = integerSetting(process.env.S3_RETENTION_DAYS, 90, "S3_RETENTION_DAYS", 1, 3650);
    const retentionDate = new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000);
    const baseKey = [prefix, manifest.backup_id].filter(Boolean).join("/");
    const artifactKey = `${baseKey}/${path.basename(artifactPath)}`;
    const manifestKey = `${baseKey}/${path.basename(manifestPath)}`;
    const artifactMetadata = {
      sha256: manifest.encrypted_sha256,
      backupId: manifest.backup_id,
      kind: "encrypted-postgresql-artifact",
      size: artifactInfo.size
    };
    const manifestMetadata = {
      sha256: await sha256(manifestPath),
      backupId: manifest.backup_id,
      kind: "authenticated-backup-manifest",
      size: manifestInfo.size
    };

    const artifactResult = await uploadLockedObject(
      client, bucket, artifactKey, artifactPath, artifactMetadata, retentionDate,
      "application/octet-stream"
    );
    const manifestResult = await uploadLockedObject(
      client, bucket, manifestKey, manifestPath, manifestMetadata, retentionDate,
      "application/json"
    );
    process.stdout.write(JSON.stringify({
      status: "uploaded_and_remote_metadata_verified",
      bucket,
      region,
      backup_id: manifest.backup_id,
      retention_mode: "COMPLIANCE",
      retention_until: retentionDate.toISOString(),
      artifact: { key: artifactKey, ...artifactResult },
      manifest: { key: manifestKey, ...manifestResult }
    }, null, 2) + String.fromCharCode(10));
  } finally {
    client.destroy();
  }
}
main().catch(error => {
  console.error(error instanceof Error ? error.message : "Off-site backup upload failed");
  process.exitCode = 1;
});
