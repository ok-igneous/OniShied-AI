import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { copyVerifiedBackupPair, verifyCustomerBackupPair } from "./backup-customer-copy.mjs";

test("customer backup copy is atomically published and independently checksum-verified", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "onishield-customer-copy-"));
  const source = path.join(root, "source");
  const destination = path.join(root, "customer-destination");
  await mkdir(source);
  const artifact = "backup-001.pgdump.enc";
  const manifest = "backup-001.manifest.json";
  const artifactPath = path.join(source, artifact);
  const manifestPath = path.join(source, manifest);
  await writeFile(artifactPath, Buffer.from("encrypted-backup-payload"));
  await writeFile(manifestPath, JSON.stringify({
    backup_id: "backup-001",
    artifact,
    encrypted_bytes: 24
  }));
  try {
    const result = await copyVerifiedBackupPair({
      artifactPath, manifestPath, destinationDirectory: destination
    });
    assert.equal(result.artifact, artifact);
    assert.equal(result.manifest, manifest);
    assert.equal(result.artifact_bytes, 24);
    assert.equal(result.artifact_sha256.length, 64);
    assert.equal(result.manifest_sha256.length, 64);
    const verified = await verifyCustomerBackupPair({
      artifactPath, manifestPath, destinationDirectory: destination
    });
    assert.equal(verified.artifact_sha256, result.artifact_sha256);
    assert.equal(verified.manifest_sha256, result.manifest_sha256);
    await assert.rejects(copyVerifiedBackupPair({
      artifactPath, manifestPath, destinationDirectory: destination
    }), /EEXIST/);
    await writeFile(path.join(destination, artifact), "tampered");
    await assert.rejects(verifyCustomerBackupPair({
      artifactPath, manifestPath, destinationDirectory: destination
    }), /does not match/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("customer backup destination cannot overlap the local backup directory", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "onishield-copy-overlap-"));
  const artifactPath = path.join(root, "backup-002.pgdump.enc");
  const manifestPath = path.join(root, "backup-002.manifest.json");
  await writeFile(artifactPath, "encrypted");
  await writeFile(manifestPath, JSON.stringify({ backup_id: "backup-002", artifact: path.basename(artifactPath) }));
  try {
    await assert.rejects(copyVerifiedBackupPair({
      artifactPath, manifestPath, destinationDirectory: path.join(root, "nested")
    }), /separate from the local backup directory/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
