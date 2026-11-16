import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { link, lstat, mkdir, realpath, rm, stat, chmod } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { createWriteStream } from "node:fs";

async function sha256(filePath) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest("hex");
}

async function copyImmutableName(sourcePath, destinationPath) {
  const temporaryPath = `${destinationPath}.${process.pid}.${cryptoRandomId()}.partial`;
  try {
    await pipeline(
      createReadStream(sourcePath),
      createWriteStream(temporaryPath, { flags: "wx", mode: 0o600 })
    );
    await chmod(temporaryPath, 0o600);
    const [sourceHash, copiedHash, sourceInfo, copiedInfo] = await Promise.all([
      sha256(sourcePath), sha256(temporaryPath), stat(sourcePath), stat(temporaryPath)
    ]);
    if (sourceHash !== copiedHash || sourceInfo.size !== copiedInfo.size || copiedInfo.size <= 0) {
      throw new Error("Customer backup copy failed size or SHA-256 verification");
    }
    // link() publishes the completed file atomically and refuses to overwrite an existing backup.
    await link(temporaryPath, destinationPath);
    await rm(temporaryPath, { force: true });
    return { sha256: copiedHash, bytes: copiedInfo.size };
  } catch (error) {
    await rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
}

function cryptoRandomId() {
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export async function copyVerifiedBackupPair({ artifactPath, manifestPath, destinationDirectory }) {
  if (!destinationDirectory) throw new Error("Customer backup destination is required");
  const artifactName = path.basename(artifactPath);
  const manifestName = path.basename(manifestPath);
  if (artifactName !== path.basename(artifactPath) || manifestName !== path.basename(manifestPath) ||
      !artifactName.endsWith(".pgdump.enc") || !manifestName.endsWith(".manifest.json")) {
    throw new Error("Unsafe customer backup filenames");
  }
  const manifest = JSON.parse(await (await import("node:fs/promises")).readFile(manifestPath, "utf8"));
  if (manifest.artifact !== artifactName || !manifest.backup_id ||
      manifestName !== `${manifest.backup_id}.manifest.json`) {
    throw new Error("Customer backup manifest does not match its artifact");
  }

  const sourceDirectory = await realpath(path.dirname(artifactPath));
  await mkdir(destinationDirectory, { recursive: true, mode: 0o700 });
  const destinationRoot = await realpath(destinationDirectory);
  const destinationInfo = await lstat(destinationRoot);
  if (!destinationInfo.isDirectory() || destinationInfo.isSymbolicLink()) {
    throw new Error("Customer backup destination must be a real directory");
  }
  if (destinationRoot === sourceDirectory ||
      destinationRoot.startsWith(sourceDirectory + path.sep) ||
      sourceDirectory.startsWith(destinationRoot + path.sep)) {
    throw new Error("Customer backup destination must be separate from the local backup directory");
  }

  const artifactDestination = path.join(destinationRoot, artifactName);
  const manifestDestination = path.join(destinationRoot, manifestName);
  const artifactCopy = await copyImmutableName(artifactPath, artifactDestination);
  try {
    const manifestCopy = await copyImmutableName(manifestPath, manifestDestination);
    return {
      artifact: artifactName,
      manifest: manifestName,
      artifact_sha256: artifactCopy.sha256,
      manifest_sha256: manifestCopy.sha256,
      artifact_bytes: artifactCopy.bytes,
      manifest_bytes: manifestCopy.bytes,
      destination_directory: destinationRoot,
      destination_device: destinationInfo.dev,
      source_device: (await stat(sourceDirectory)).dev,
      separate_device: destinationInfo.dev !== (await stat(sourceDirectory)).dev
    };
  } catch (error) {
    // Do not leave a misleading half-pair at the destination.
    await rm(artifactDestination, { force: true });
    throw error;
  }
}

export async function verifyCustomerBackupPair({ artifactPath, manifestPath, destinationDirectory }) {
  const artifactName = path.basename(artifactPath);
  const manifestName = path.basename(manifestPath);
  const copiedArtifact = path.join(destinationDirectory, artifactName);
  const copiedManifest = path.join(destinationDirectory, manifestName);
  const [sourceArtifactHash, copiedArtifactHash, sourceManifestHash, copiedManifestHash] =
    await Promise.all([
      sha256(artifactPath), sha256(copiedArtifact), sha256(manifestPath), sha256(copiedManifest)
    ]);
  if (sourceArtifactHash !== copiedArtifactHash || sourceManifestHash !== copiedManifestHash) {
    throw new Error("Customer backup copy no longer matches the verified local backup");
  }
  return { artifact_sha256: copiedArtifactHash, manifest_sha256: copiedManifestHash };
}
