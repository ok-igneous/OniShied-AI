import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  GetBucketObjectLockConfigurationCommand,
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
  if (head.Metadata?.sha256 !== expected.sha256 ||
      head.Metadata?.backup_id !== expected.backupId ||
      head.Metadata?.object_kind !== expected.kind ||
      head.ObjectLockMode !== "COMPLIANCE" ||
      !head.ObjectLockRetainUntilDate ||
      new Date(head.ObjectLockRetainUntilDate) < retentionDate ||
      head.ContentLength !== expected.size) {
    throw new Error(`Remote object verification or compliance retention check failed for ${key}`);
  }
  return { version_id: head.VersionId, size: head.ContentLength, retain_until: head.ObjectLockRetainUntilDate };
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
  if (process.argv[2] !== "upload") {
    throw new Error("Usage: node scripts/backup-s3.mjs upload");
  }
  const artifactPath = path.resolve(required(process.env.BACKUP_ARTIFACT, "BACKUP_ARTIFACT"));
  const manifestPath = path.resolve(required(process.env.BACKUP_MANIFEST, "BACKUP_MANIFEST"));
  const bucket = required(process.env.S3_BUCKET, "S3_BUCKET");
  const region = process.env.S3_REGION || "us-east-1";
  const prefix = (process.env.S3_PREFIX || "onishield/postgres").replace(/^\\/+|\\/+$/g, "");
  const retentionDays = integerSetting(process.env.S3_RETENTION_DAYS, 90, "S3_RETENTION_DAYS", 1, 3650);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (!/^[A-Za-z0-9._-]{1,180}$/.test(manifest.backup_id || "") ||
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

  const client = new S3Client({
    region,
    ...(process.env.S3_ENDPOINT ? { endpoint: process.env.S3_ENDPOINT } : {}),
    forcePathStyle: process.env.S3_FORCE_PATH_STYLE === "true"
  });
  const versioning = await client.send(new GetBucketVersioningCommand({ Bucket: bucket }));
  if (versioning.Status !== "Enabled") {
    throw new Error("Destination bucket versioning must be Enabled before backup upload");
  }
  const lock = await client.send(new GetBucketObjectLockConfigurationCommand({ Bucket: bucket }));
  if (lock.ObjectLockConfiguration?.ObjectLockEnabled !== "Enabled") {
    throw new Error("Destination bucket must have S3 Object Lock enabled; refusing a mutable vault");
  }

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
  }, null, 2) + "\\n");
  await client.destroy();
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : "Off-site backup upload failed");
  process.exitCode = 1;
});
