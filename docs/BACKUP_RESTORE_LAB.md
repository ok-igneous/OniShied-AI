# Encrypted PostgreSQL Backup and Restore Lab

**Status:** Draft implementation on an unmerged branch; integration drill is wired into CI but has not yet passed.  
**Scope:** One PostgreSQL database, encrypted local artifact, authenticated manifest, archive verification, isolated restore, and optional S3-compatible immutable upload/download.  
**Not included:** Scheduler, WAL/PITR, object/evidence backup, tenant-level selective restore, production dashboard, or measured RPO/RTO.

## Prerequisites

- Node.js 22 or later.
- PostgreSQL client utilities compatible with the source server: `pg_dump`, `pg_restore`, and `psql`.
- A dedicated backup operator identity with read-only access sufficient for `pg_dump`. Do not use the application runtime role or a superuser for routine backups.
- A versioned set of 32-byte random encryption keys held in a secrets manager or another recovery-controlled location, separate from the backup destination. Keep every historical key needed by retained backups.
- A protected destination directory with restricted filesystem permissions. This lab writes encrypted files locally; it does not provide off-site isolation.

Generate a key once using a trusted secrets-management process (example only):

```sh
openssl rand -hex 32
```

Store each value in a secrets manager. Preserve each key and its ID separately from backup files. Losing a historical key makes every backup encrypted under that key unrecoverable. The key ID in the authenticated manifest selects the exact key used for verification and restore.

## Create a backup

Set the source database URL and key material in the process environment, not in command-line arguments or committed files:

```sh
export DATABASE_URL='postgresql://backup_user:REDACTED@127.0.0.1:5432/onishield_lab'
export BACKUP_KEYRING_JSON='{"onishield-lab-key-01":"64_HEX_CHARACTERS_FROM_SECRET_STORE"}'
export BACKUP_ACTIVE_KEY_ID='onishield-lab-key-01'
export BACKUP_DIRECTORY='/secure/backups/onishield'
node scripts/backup-postgres.mjs create
```

The command streams PostgreSQL custom-format output through AES-256-GCM encryption. It writes a restricted-permission `.pgdump.enc` artifact and a JSON sidecar manifest containing the source database identity, PostgreSQL server/tool versions, artifact size, SHA-256 digest, creation time and key ID. The manifest is HMAC-authenticated using a separately derived key. Plaintext dump files are not written to disk.

A completed command means the encrypted artifact and manifest were written. It does not mean the backup is off-site, immutable, or restorable until verification and a restore drill pass.

## Verify an artifact

Provide a keyring containing the historical key ID named by the authenticated manifest. The active key may be newer; verification and restore select the historical key by manifest key ID. Then identify the exact matching artifact and manifest:

```sh
export BACKUP_ARTIFACT='/secure/backups/onishield/backup-id.pgdump.enc'
export BACKUP_MANIFEST='/secure/backups/onishield/backup-id.manifest.json'
node scripts/backup-postgres.mjs verify
```

Verification authenticates the manifest, checks the encrypted-file SHA-256 digest, decrypts the stream, verifies the AES-GCM authentication tag, and asks `pg_restore --list` to parse the PostgreSQL archive. This is an integrity/archive check, not a complete database restore test.

## Restore to an isolated empty database

1. Create a new database with a name different from the source database.
2. Keep it isolated from production connectors, application traffic and response credentials.
3. Set the target URL and explicit confirmation value.
4. Run restore only after reviewing the selected backup and its incident/forensic context.

```sh
export BACKUP_ARTIFACT='/secure/backups/onishield/backup-id.pgdump.enc'
export BACKUP_MANIFEST='/secure/backups/onishield/backup-id.manifest.json'
export RESTORE_TARGET_DATABASE_URL='postgresql://restore_user:REDACTED@127.0.0.1:5432/onishield_restore'
export RESTORE_CONFIRMATION='RESTORE_TO_ISOLATED_DATABASE'
node scripts/backup-postgres.mjs restore
```

Remote restore targets are rejected by default. For a controlled isolated remote lab, the operator must explicitly set `RESTORE_ALLOW_REMOTE_TARGET=YES_I_UNDERSTAND`. The target must be empty. The restore command refuses a target database with the same database name as the source, never uses `pg_restore --clean`, excludes source ownership/ACL restoration, and uses a single transaction so failed restores roll back. It authenticates and parses the full archive before connecting to the restore target.

The restore target must have required PostgreSQL roles and extensions provisioned separately. Database dumps do not include cluster-wide roles or tablespaces. After restore, apply any required environment-specific configuration and run schema, tenant-isolation, identity, audit, and application smoke tests. Do not point production traffic at the restored database based only on a successful `pg_restore` exit.

## Operational limits and next gates

- `npm run backup:run` now orchestrates backup creation, local verification, and (when `S3_BUCKET` is configured) immutable-vault upload. It writes a secret-free `backup-status.json` and uses an exclusive lock to prevent overlapping runs. A stale lock is intentionally not auto-cleared: an operator must inspect the host/process before removing it.
- This is a scheduler-ready runner, not a scheduler service. Configure cron or the hosting platform's scheduled-job facility only after selecting a cadence and validating runtime/cost. Example cron entry (load the protected environment file; keep it owner-readable only): `0 2 * * * cd /opt/onishield && set -a && . /etc/onishield/backup.env && set +a && /usr/bin/node scripts/backup-runner.mjs >> /var/log/onishield-backup.log 2>&1`. Ensure the runtime identity can read the secrets file and write the backup directory, but cannot delete immutable remote versions.
- Copy artifacts to a separate account/project or immutable object-lock vault using a dedicated backup identity. Never let the production application identity delete backup history.
- Add retention only after legal, customer and storage-cost requirements are decided.
- Add WAL archiving/PITR only after selecting and testing the actual PostgreSQL hosting model.
- CI now includes a disposable PostgreSQL 16 create → verify → restore integration test with recovered-row and authentication-invalidation assertions. This test is authored and wired, not yet observed passing. A separate application/tenant-isolation drill is still required. Record measured duration and data-loss window before publishing RPO/RTO.
- Keep encryption keys outside the backup destination and test key recovery/rotation. `BACKUP_KEYRING_JSON` maps up to 32 key IDs to 64-character hexadecimal 32-byte keys; `BACKUP_ACTIVE_KEY_ID` selects the key used only for new backups. Verification and restore resolve the key ID from the authenticated manifest and fail closed if that historical key is unavailable. Never place key material in the manifest, repository, backup directory, status file, or logs. The legacy `BACKUP_ENCRYPTION_KEY` plus `BACKUP_ENCRYPTION_KEY_ID` pair remains supported for migration, but it cannot decrypt backups from other key IDs.
- Do not treat local encrypted artifacts as ransomware-resistant: an attacker with write/delete access to the host can still destroy them.


## Off-site S3-compatible immutable vault

The optional uploader stores an already-created local backup artifact and its authenticated manifest in an S3-compatible bucket. It uses the AWS SDK v3 default credential provider chain (for example, an attached workload role); no access key is stored in this repository or passed on a command line.

Before enabling uploads, provision a dedicated bucket with **versioning enabled** and **Object Lock enabled**. Object Lock must be enabled when the bucket is created on providers that make this a creation-time setting. The uploader fails closed unless it can confirm both settings. It applies per-object **COMPLIANCE** retention; objects cannot be deleted or shortened during that retention period, including by privileged bucket administrators. Choose the retention period only after legal, privacy, and storage-cost review.

Required environment:
- `S3_BUCKET`: destination bucket.
- `S3_REGION`: bucket region (defaults to `us-east-1`).
- `S3_ENDPOINT`: optional provider endpoint for an S3-compatible service.
- `S3_FORCE_PATH_STYLE=true`: optional path-style addressing for compatible endpoints that require it.
- `S3_PREFIX`: optional object prefix (defaults to `onishield/postgres`).
- `S3_RETENTION_DAYS`: compliance retention in days (defaults to 90; accepted range 1–3650).
- Standard AWS SDK credentials: prefer workload identity/role credentials; never commit static credentials. A custom endpoint must use HTTPS. Scope the uploader identity to the backup prefix with bucket-versioning/object-lock read permissions, object upload and multipart-abort permissions, object-retention permission, and object read permission for post-upload HEAD checks; do not grant delete, retention-bypass, or bucket-configuration mutation permissions.

After a local backup has been created, run the uploader with the exact artifact and manifest paths:

```sh
export BACKUP_ARTIFACT='/secure/backups/onishield/backup-id.pgdump.enc'
export BACKUP_MANIFEST='/secure/backups/onishield/backup-id.manifest.json'
export S3_BUCKET='your-locked-backup-bucket'
export S3_REGION='your-bucket-region'
export S3_PREFIX='onishield/postgres'
export S3_RETENTION_DAYS='90'
node scripts/backup-s3.mjs upload
```

The uploader first invokes the local verifier, which checks manifest HMAC, encrypted artifact SHA-256, AES-GCM authentication and PostgreSQL archive parsing. It then checks bucket versioning and Object Lock configuration, uploads both files using multipart-capable streaming, and checks remote object metadata, size, version ID and COMPLIANCE retention. It has no delete operation. An upload is not a restore drill: periodically retrieve both objects to an isolated environment and run the documented verification and PostgreSQL restore procedure.

Use a separate cloud account/project from production where practical. The backup identity should be limited to the dedicated bucket/prefix and upload/verification operations; production application identities must not be able to delete backups or alter bucket retention. Configure alerts for failed uploads, missing expected backups, and retention/configuration drift. S3-compatible providers vary: the destination must implement bucket versioning, Object Lock configuration, COMPLIANCE retention and the multipart APIs used by the AWS SDK. A generic endpoint alone does not prove those guarantees.


### Retrieve and verify a remote backup

The remote copy can be retrieved by the exact backup ID printed by the upload command. Choose destination paths whose filenames match the original artifact and manifest names; the command refuses to overwrite existing files.

```sh
export S3_BACKUP_ID='backup-id-from-upload-output'
export BACKUP_ARTIFACT='/secure/restore/backup-id-from-manifest.pgdump.enc'
export BACKUP_MANIFEST='/secure/restore/backup-id.manifest.json'
node scripts/backup-s3.mjs download
```

The downloader obtains a version ID from the object metadata and passes that exact ID to GetObject. For deterministic recovery from a recorded upload, optionally set `S3_MANIFEST_VERSION_ID` and `S3_ARTIFACT_VERSION_ID` to the two version IDs printed by the upload command; the downloader pins its HEAD and GET operations to those versions and fails if the requested version does not match. It checks object identity and unexpired COMPLIANCE retention metadata, verifies downloaded bytes against remote SHA-256 metadata and the authenticated manifest, then runs the full local archive verifier. The opt-in S3 integration drill records the upload version IDs and explicitly pins both downloads to those exact versions. A successful download is still not a restore drill; use the isolated PostgreSQL restore procedure above afterward.


## Verification record (2026-11-16)

The repository contains PostgreSQL and opt-in S3 recovery integration tests, but this record does not claim either test has passed. A real S3 recovery run requires a dedicated versioned Object-Lock bucket, AWS-compatible credentials, and a PostgreSQL 16 admin test connection. The GitHub Actions workflow can execute the PostgreSQL integration test with its ephemeral PostgreSQL service; the S3 scenario remains skipped unless its explicit opt-in and provider environment are provisioned as protected repository secrets/variables. Do not use a production bucket for this drill: the test intentionally leaves COMPLIANCE-locked objects in place until their one-day retention expires. Capture the workflow run URL, provider name/version, bucket configuration evidence, PostgreSQL version, and successful restore assertions before marking remote recovery verified.

## Immutable S3 vault recovery integration drill

`scripts/backup-s3.integration.test.mjs` is an opt-in end-to-end test. It creates disposable PostgreSQL databases, creates an encrypted backup using an old active key, uploads the artifact and authenticated manifest to a dedicated versioned Object-Lock bucket, downloads and locally verifies the remote copy, and restores it into isolated databases. It then rotates the active key while retaining the historical key, repeats the historical remote restore, creates/uploads/downloads/restores a new-key backup, checks recovered application data and post-restore authentication invalidation, and confirms that removing the historical key makes the old artifact unverifiable.

The test is deliberately skipped unless all of the following are explicitly configured:

- `BACKUP_S3_TEST_ENABLE=YES_I_UNDERSTAND_IMMUTABLE_UPLOADS`
- `BACKUP_S3_TEST_BUCKET`: a dedicated test bucket with versioning and Object Lock enabled; never point this at a production backup bucket.
- `BACKUP_S3_TEST_PREFIX`: a dedicated prefix containing an `integration-tests` path segment.
- `BACKUP_TEST_ADMIN_DATABASE_URL`: a PostgreSQL 16 test admin connection.
- AWS SDK default credential-chain settings and, when needed, `S3_REGION`, `S3_ENDPOINT`, and `S3_FORCE_PATH_STYLE`.

Example invocation in a protected test environment:

```sh
BACKUP_S3_TEST_ENABLE=YES_I_UNDERSTAND_IMMUTABLE_UPLOADS \
BACKUP_S3_TEST_BUCKET='dedicated-test-bucket' \
BACKUP_S3_TEST_PREFIX='onishield/integration-tests' \
BACKUP_TEST_ADMIN_DATABASE_URL='postgresql://test_admin:REDACTED@127.0.0.1:5432/postgres' \
node --test scripts/backup-s3.integration.test.mjs
```

The test uses one-day COMPLIANCE retention and intentionally does not delete remote objects; Object Lock makes that history immutable until retention expires. Each run generates unique backup IDs and database names, so it incurs storage cost and leaves test objects in the dedicated prefix. Apply a separately reviewed lifecycle policy after retention expires. Never grant the test identity permission to bypass retention or delete objects during their retention period.

The regular CI workflow runs the test file, but it skips the live S3 scenario unless the explicit opt-in and dedicated test environment are supplied. A skipped test is not evidence that the remote vault works. Record a successful run against the actual intended provider before claiming remote recovery has been validated. S3-compatible implementations differ; only the real provider test can establish that versioning, COMPLIANCE retention, multipart upload, exact-version retrieval, and restore work together.

## Scheduled backup runner

The runner is deliberately separate from the API process. Do not start a timer inside each Fastify worker: multiple application replicas could create duplicate schedules and make backups dependent on API uptime. Use exactly one dedicated host scheduler or managed scheduled-job instance.

Configure these environment variables in the scheduler's protected secret/environment facility:
- All local backup variables: `DATABASE_URL`, `BACKUP_KEYRING_JSON`, `BACKUP_ACTIVE_KEY_ID`, and `BACKUP_DIRECTORY`. Keep keyring JSON in the scheduler secret store; do not put it in a checked-in `.env` file.
- For mandatory off-site protection, set `S3_BUCKET`, `S3_REGION`, provider endpoint settings if required, and the AWS SDK workload identity/credentials.
- Set `BACKUP_UPLOAD_REQUIRED=true` so a missing `S3_BUCKET` causes the run to fail rather than silently accepting a local-only copy.

Run:

```sh
npm run backup:run
```

The runner executes create → local verify → optional S3 upload. It writes `backup-status.json` atomically with run ID, timestamps, backup ID, artifact/manifest names, local verification result, remote-upload state and a non-secret failure summary. It does not record connection URLs, encryption keys, or cloud credentials. Exit code is non-zero if any required stage fails. A local backup that verifies but fails mandatory upload is recorded as a failed overall run.

The exclusive lock prevents concurrent invocations. If the host crashes or the process is killed, the lock directory may remain. The runner refuses to remove it automatically because doing so could permit overlapping backups while an earlier process is still active. Inspect the process and host first; only then may an operator remove a stale lock.

The runner does not configure a schedule, send alerts, or delete old backups. The scheduler must alert on non-zero exit, stale `backup-status.json`, and missing expected run windows. Do not implement local retention deletion until off-site recovery, legal holds, and minimum-copy policy are tested.


## Backup health check

Run the health check from the same protected host and environment used by the scheduler:

```sh
BACKUP_MAX_AGE_HOURS=26 npm run backup:health
```

It checks that the latest run is marked successful, the completion timestamp is within the configured age limit, the artifact and manifest still exist, the manifest identity matches the status record, and the encrypted artifact size matches the manifest. When `BACKUP_UPLOAD_REQUIRED=true`, it also requires the latest run to record a successful immutable-vault upload.

The health check is suitable for a host monitor or external alerting system: exit code 0 means the recorded backup is fresh and structurally present; non-zero means the backup should be treated as unhealthy and investigated. It does not re-run full cryptographic verification or retrieve/restore the remote object. Schedule it more frequently than the backup cadence, and alert on every non-zero result.

```sh
npm run backup:health
```

## CLI actions

- `node scripts/backup-postgres.mjs create`
- `node scripts/backup-postgres.mjs verify`
- `node scripts/backup-postgres.mjs restore`
- `node scripts/backup-s3.mjs upload`
- `node scripts/backup-s3.mjs download`
- `npm run backup:run`
- `npm run backup:health`

All commands fail closed on missing key material, invalid manifest authentication, checksum mismatch, unknown artifact format, failed archive parsing, or unsafe restore target conditions.


## Controlled encryption-key rotation

Rotation changes the active key for future backups; it does not rewrite existing artifacts. Use a secrets-manager version or deployment change with an explicit operator approval:

1. Generate a new independent 32-byte key and assign a new, never-reused key ID.
2. Add the new key to `BACKUP_KEYRING_JSON` while retaining every old key still referenced by a retained or legal-hold backup. Set `BACKUP_ACTIVE_KEY_ID` to the new ID.
3. Deploy the updated secret atomically to the backup runner and every restore environment. Do not print the keyring or expose it in deployment logs.
4. Create a synthetic backup with the new active key and verify it. Separately verify and, where practical, restore representative older backups encrypted under each retained key ID.
5. Record the rotation date, key ID, approver, secret-manager version, and the backup retention population covered by each key. Record no key material.
6. Retire an old key only after an inventory proves that no retained, legal-hold, or otherwise required backup references it, and the recovery owner approves destruction. Never remove a key merely because a newer key is active.

The keyring accepts 1–32 entries. IDs are restricted to 1–64 safe characters. A missing ID, malformed key, absent active key, or invalid keyring fails closed. The legacy single-key variables remain a temporary compatibility path; migrate to the keyring before performing multi-key rotation. Keyring parsing occurs in the backup CLI process, not in the API service. Do not auto-rotate keys or generate replacement keys at runtime.


## Key-rotation recovery integration drill

The PostgreSQL 16 integration test now exercises the complete rotation sequence against disposable databases: create and verify a backup with the old active key; switch the active key while retaining the old key; verify and restore that historical artifact; create a new backup and assert its manifest names the new key ID; verify and restore the new artifact; and finally remove the historical key from the test keyring and assert that verification fails closed. Both restored databases are checked for the expected application row and post-restore authentication-state invalidation. This test is authored and wired into the existing PostgreSQL integration-test step; it has not been observed passing in this environment.
