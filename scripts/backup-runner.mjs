import { randomUUID } from "node:crypto";
import { mkdir, open, rename, rm, stat, chmod } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const backupDirectory = path.resolve(process.env.BACKUP_DIRECTORY || "./var/backups");
const lockDirectory = path.join(backupDirectory, ".onishield-backup.lock");
const statusPath = path.join(backupDirectory, "backup-status.json");
const runId = randomUUID();

function writeCommand(command, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout = (stdout + chunk).slice(-65536); });
    child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-8192); });
    child.once("error", () => reject(new Error(`Unable to start ${path.basename(command)}`)));
    child.once("close", code => code === 0
      ? resolve(stdout)
      : reject(new Error(`${path.basename(command)} failed with exit code ${code}; details withheld from status file`)));
  });
}

async function saveStatus(status) {
  const temporary = `${statusPath}.${runId}.partial`;
  await writeFile(temporary, JSON.stringify(status, null, 2) + "\n", {
    encoding: "utf8", mode: 0o600, flag: "wx"
  });
  await rename(temporary, statusPath);
  await chmod(statusPath, 0o600);
}

async function main() {
  await mkdir(backupDirectory, { recursive: true, mode: 0o700 });
  await chmod(backupDirectory, 0o700);
  try {
    await mkdir(lockDirectory, { mode: 0o700 });
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error("Another backup run may be active, or a previous run left a lock. Inspect the host before manually clearing the lock.");
    }
    throw error;
  }

  const startedAt = new Date().toISOString();
  const status = {
    version: 1,
    run_id: runId,
    state: "running",
    started_at: startedAt,
    completed_at: null,
    backup_id: null,
    artifact: null,
    manifest: null,
    remote_upload: "not_configured",
    failure: null
  };

  try {
    const lockFile = await open(path.join(lockDirectory, "owner.json"), "wx", 0o600);
    await lockFile.writeFile(JSON.stringify({ run_id: runId, pid: process.pid, started_at: startedAt }));
    await lockFile.close();
    await saveStatus(status);

    const env = { ...process.env, BACKUP_DIRECTORY: backupDirectory };
    const backupScript = path.join(scriptDirectory, "backup-postgres.mjs");
    const createOutput = await writeCommand(process.execPath, [backupScript, "create"], env);
    const artifact = createOutput.match(/^Backup created: (.+)$/m)?.[1];
    const manifest = createOutput.match(/^Manifest: (.+)$/m)?.[1];
    if (!artifact || !manifest || path.basename(artifact) !== artifact || path.basename(manifest) !== manifest) {
      throw new Error("Backup command did not return valid artifact and manifest names");
    }

    const artifactPath = path.join(backupDirectory, artifact);
    const manifestPath = path.join(backupDirectory, manifest);
    const [artifactInfo, manifestInfo] = await Promise.all([stat(artifactPath), stat(manifestPath)]);
    if (!artifactInfo.isFile() || !manifestInfo.isFile() || artifactInfo.size <= 0 || manifestInfo.size <= 0) {
      throw new Error("Backup output files are missing or empty");
    }

    const verifyEnv = {
      ...env,
      BACKUP_ARTIFACT: artifactPath,
      BACKUP_MANIFEST: manifestPath
    };
    await writeCommand(process.execPath, [backupScript, "verify"], verifyEnv);
    status.backup_id = path.basename(manifest, ".manifest.json");
    status.artifact = artifact;
    status.manifest = manifest;
    status.local_verification = "passed";
    await saveStatus(status);

    if (process.env.S3_BUCKET) {
      const s3Script = path.join(scriptDirectory, "backup-s3.mjs");
      await writeCommand(process.execPath, [s3Script, "upload"], verifyEnv);
      status.remote_upload = "uploaded_and_remote_metadata_verified";
    } else if (process.env.BACKUP_UPLOAD_REQUIRED === "true") {
      throw new Error("BACKUP_UPLOAD_REQUIRED is true but S3_BUCKET is not configured");
    }

    status.state = "success";
    status.completed_at = new Date().toISOString();
    await saveStatus(status);
    process.stdout.write(JSON.stringify(status, null, 2) + "\n");
  } catch (error) {
    status.state = "failed";
    status.completed_at = new Date().toISOString();
    status.failure = error instanceof Error ? error.message : "Backup run failed";
    await saveStatus(status).catch(() => {});
    throw error;
  } finally {
    await rm(lockDirectory, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`OniShield scheduled backup failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
  process.exitCode = 1;
});
