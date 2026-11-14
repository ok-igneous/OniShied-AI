# Encrypted PostgreSQL Backup and Restore Lab

**Status:** Initial CLI implementation authored on an unmerged branch; not executed or operationally verified.  
**Scope:** One PostgreSQL database, encrypted local artifact, authenticated manifest, archive verification, and restore into a new empty isolated database.  
**Not included:** Scheduler, remote/off-site vault, immutable retention, WAL/PITR, object storage, tenant-level selective restore, production dashboard, or measured RPO/RTO.

## Prerequisites

- Node.js 22 or later.
- PostgreSQL client utilities compatible with the source server: `pg_dump`, `pg_restore`, and `psql`.
- A dedicated backup operator identity with read-only access sufficient for `pg_dump`. Do not use the application runtime role or a superuser for routine backups.
- A 32-byte random encryption key held in a secrets manager or another recovery-controlled location, separate from the backup destination.
- A protected destination directory with restricted filesystem permissions. This lab writes encrypted files locally; it does not provide off-site isolation.

Generate a key once using a trusted secrets-management process (example only):

```sh
openssl rand -hex 32
```

Store the value in a secrets manager. Preserve the key and its key ID separately from backup files. Losing the key makes these backups unrecoverable; rotating it does not re-encrypt older backups.

## Create a backup

Set the source database URL and key material in the process environment, not in command-line arguments or committed files:

```sh
export DATABASE_URL='postgresql://backup_user:REDACTED@127.0.0.1:5432/onishield_lab'
export BACKUP_ENCRYPTION_KEY='64_HEX_CHARACTERS_FROM_SECRET_STORE'
export BACKUP_ENCRYPTION_KEY_ID='onishield-lab-key-01'
export BACKUP_DIRECTORY='/secure/backups/onishield'
node scripts/backup-postgres.mjs create
```

The command streams PostgreSQL custom-format output through AES-256-GCM encryption. It writes a restricted-permission `.pgdump.enc` artifact and a JSON sidecar manifest containing the source database identity, artifact size, SHA-256 digest, creation time, tool version and key ID. The manifest is HMAC-authenticated using a separately derived key. Plaintext dump files are not written to disk.

A completed command means the encrypted artifact and manifest were written. It does not mean the backup is off-site, immutable, or restorable until verification and a restore drill pass.

## Verify an artifact

Set the same encryption key and key ID, then identify the exact matching artifact and manifest:

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
export RESTORE_TARGET_DATABASE_URL='postgresql://restore_user:REDACTED@127.0.0.1:5432/onishield_restore'
export RESTORE_CONFIRMATION='RESTORE_TO_ISOLATED_DATABASE'
node scripts/backup-postgres.mjs restore
```

Remote restore targets are rejected by default. For a controlled isolated remote lab, the operator must explicitly set `RESTORE_ALLOW_REMOTE_TARGET=YES_I_UNDERSTAND`. The target must be empty. The restore command refuses a target database with the same database name as the source, never uses `pg_restore --clean`, excludes source ownership/ACL restoration, and uses a single transaction so failed restores roll back. It authenticates and parses the full archive before connecting to the restore target.

The restore target must have required PostgreSQL roles and extensions provisioned separately. Database dumps do not include cluster-wide roles or tablespaces. After restore, apply any required environment-specific configuration and run schema, tenant-isolation, identity, audit, and application smoke tests. Do not point production traffic at the restored database based only on a successful `pg_restore` exit.

## Operational limits and next gates

- Schedule this command externally only after the operator has selected a cadence and tested runtime/cost; this PR does not add a scheduler.
- Copy artifacts to a separate account/project or immutable object-lock vault using a dedicated backup identity. Never let the production application identity delete backup history.
- Add retention only after legal, customer and storage-cost requirements are decided.
- Add WAL archiving/PITR only after selecting and testing the actual PostgreSQL hosting model.
- Run a real PostgreSQL 16 create → verify → restore → application/tenant-isolation drill in a disposable environment. Record measured duration and data-loss window before publishing RPO/RTO.
- Keep encryption keys outside the backup destination and test key recovery/rotation. Do not place the key in the manifest, repository, backup directory, or logs.
- Do not treat local encrypted artifacts as ransomware-resistant: an attacker with write/delete access to the host can still destroy them.

## CLI actions

- `node scripts/backup-postgres.mjs create`
- `node scripts/backup-postgres.mjs verify`
- `node scripts/backup-postgres.mjs restore`

All commands fail closed on missing key material, invalid manifest authentication, checksum mismatch, unknown artifact format, failed archive parsing, or unsafe restore target conditions.
