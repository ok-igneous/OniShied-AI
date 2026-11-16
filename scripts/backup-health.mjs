import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { verifyCustomerBackupPair } from "./backup-customer-copy.mjs";

function fail(message) {
  process.stderr.write(`BACKUP HEALTH FAILED: ${message}\n`);
  process.exitCode = 1;
}

async function main() {
  const directory = path.resolve(process.env.BACKUP_DIRECTORY || "./var/backups");
  const statusPath = path.resolve(process.env.BACKUP_STATUS_FILE || path.join(directory, "backup-status.json"));
  const maxAgeHours = Number(process.env.BACKUP_MAX_AGE_HOURS ?? "26");
  if (!Number.isFinite(maxAgeHours) || maxAgeHours <= 0 || maxAgeHours > 24 * 366) {
    throw new Error("BACKUP_MAX_AGE_HOURS must be greater than 0 and no more than 8784");
  }

  let status;
  try {
    status = JSON.parse(await readFile(statusPath, "utf8"));
  } catch {
    throw new Error("Backup status file is missing or unreadable");
  }
  if (status.version !== 1 || status.state !== "success" || !status.completed_at ||
      !status.backup_id || !status.artifact || !status.manifest) {
    throw new Error("Latest backup run is not recorded as a complete success");
  }

  const completedAt = Date.parse(status.completed_at);
  const ageHours = (Date.now() - completedAt) / 3_600_000;
  if (!Number.isFinite(completedAt) || ageHours < 0 || ageHours > maxAgeHours) {
    throw new Error(`Last successful backup is ${Number.isFinite(ageHours) ? ageHours.toFixed(2) : "an invalid age"} hours old`);
  }

  for (const filename of [status.artifact, status.manifest]) {
    if (typeof filename !== "string" || path.basename(filename) !== filename) {
      throw new Error("Backup status contains an unsafe artifact filename");
    }
    const file = await stat(path.join(directory, filename));
    if (!file.isFile() || file.size <= 0) {
      throw new Error(`Backup output is missing or empty: ${filename}`);
    }
  }

  const manifest = JSON.parse(await readFile(path.join(directory, status.manifest), "utf8"));
  if (manifest.backup_id !== status.backup_id || manifest.artifact !== status.artifact ||
      !Number.isSafeInteger(manifest.encrypted_bytes) || manifest.encrypted_bytes <= 0) {
    throw new Error("Backup manifest does not match the latest successful status record");
  }
  const artifactInfo = await stat(path.join(directory, status.artifact));
  if (artifactInfo.size !== manifest.encrypted_bytes) {
    throw new Error("Encrypted artifact size does not match its manifest");
  }

  let customerCopy = "not_configured";
  if (process.env.CUSTOMER_BACKUP_DIRECTORY) {
    if (!status.customer_artifact || !status.customer_manifest ||
        !["copied_and_checksum_verified_on_separate_device", "copied_and_checksum_verified_same_device"].includes(status.customer_copy)) {
      if (process.env.BACKUP_CUSTOMER_COPY_REQUIRED === "true") {
        throw new Error("Required customer-controlled backup copy is not recorded as complete");
      }
      customerCopy = "not_verified";
    } else {
      await verifyCustomerBackupPair({
        artifactPath: path.join(directory, status.artifact),
        manifestPath: path.join(directory, status.manifest),
        destinationDirectory: process.env.CUSTOMER_BACKUP_DIRECTORY
      });
      customerCopy = status.customer_copy;
    }
  } else if (process.env.BACKUP_CUSTOMER_COPY_REQUIRED === "true") {
    throw new Error("BACKUP_CUSTOMER_COPY_REQUIRED is true but CUSTOMER_BACKUP_DIRECTORY is not configured");
  }

  if (process.env.BACKUP_CUSTOMER_COPY_REQUIRED === "true" &&
      status.customer_copy !== "copied_and_checksum_verified_on_separate_device") {
    throw new Error("Required customer backup is not on a separate filesystem device");
  }

  if (process.env.BACKUP_UPLOAD_REQUIRED === "true" &&
      status.remote_upload !== "uploaded_and_remote_metadata_verified") {
    throw new Error("Mandatory off-site backup upload is not recorded as successful");
  }

  process.stdout.write(JSON.stringify({
    status: "healthy",
    backup_id: status.backup_id,
    completed_at: status.completed_at,
    age_hours: Number(ageHours.toFixed(2)),
    local_artifact: "present_and_size_matched",
    customer_copy: customerCopy,
    remote_upload: status.remote_upload || "not_recorded",
    protection_level: status.remote_upload === "uploaded_and_remote_metadata_verified" && customerCopy.startsWith("copied_and_checksum_verified_on_separate_device")
      ? "customer_copy_plus_remote_vault"
      : status.remote_upload === "uploaded_and_remote_metadata_verified"
        ? "remote_vault_only"
        : customerCopy.startsWith("copied_and_checksum_verified_on_separate_device")
          ? "local_plus_customer_separate_device"
          : "local_only_or_not_independently_verified"
  }, null, 2) + "\n");
}

main().catch(error => fail(error instanceof Error ? error.message : "Unknown backup health error"));
