# Backup and Disaster Recovery — Technical Contract

**Status:** Normative design contract; partial lab CLI authored on an unmerged branch and not verified.  
**Initial deployment:** Disposable lab with synthetic data.  
**Objective:** Recover OniShield service and customer security records after accidental deletion, corruption, infrastructure failure, ransomware, or compromised credentials.

## 1. Recovery is a security control, not a backup checkbox

A backup that has never been restored is an assumption, not a recovery capability. OniShield must demonstrate that backups are complete, isolated from production credentials, integrity-checked, recoverable to a known point in time, and protected against unauthorized deletion or overwrite.

Backups reduce recovery time and data loss; they do not prevent compromise, prove an environment is clean, or guarantee every encrypted file can be recovered.

## 2. Data classes and scope

The backup inventory must explicitly classify and assign retention to:
- Tenant configuration, policies, memberships, and required identity metadata.
- Security events, findings, investigation records, and evidence references.
- Threat-intelligence records and their provenance/review history.
- Response intents, execution outcomes, and audit records.
- Connector/device inventory and enrollment metadata.
- Required application configuration and deployment manifests.

Plaintext secrets, live bearer/session tokens, plaintext passwords, MFA encryption keys, recovery-code peppers, and raw API credentials must never be exported into operator-accessible archives. A full encrypted database recovery copy may contain password hashes, opaque session/action-token digests, and application-encrypted MFA-secret ciphertext where required to restore identity records. Treat these as high-sensitivity material: encrypt the complete archive, keep backup keys separate, and invalidate restored sessions and pending one-time tokens before any operator access is re-enabled. Key material itself must be recovered separately through a controlled key-management procedure.

The team must document which records are reconstructable, which are authoritative, and which are intentionally excluded. Tenant data must remain tenant-isolated in backup access and restore operations.

## 3. Backup architecture

Use layered recovery rather than one backup destination:

1. **Database point-in-time recovery (PITR):** base backups plus continuous write-ahead-log (WAL) archiving, where supported by the selected PostgreSQL hosting model.
2. **Scheduled encrypted snapshots:** database snapshots at a documented cadence.
3. **Object/evidence backup:** versioned copies of any separately stored evidence and attachments, with integrity manifests.
4. **Configuration backup:** version-controlled non-secret configuration, deployment manifests, and documented secret/key recovery references.
5. **Offline or logically isolated copy:** a separate account/project or offline destination that production credentials cannot delete or rewrite.

At least one recovery copy must be outside the production administrative boundary. Replication alone is not a backup: deletion or corruption can replicate.

## 4. Isolation, encryption, and integrity

- Use a dedicated backup identity with write-only or append-only permissions where supported; production application credentials must not delete backup history.
- Separate backup administration from ordinary operator and application roles.
- Encrypt in transit and at rest using managed or envelope-encryption keys.
- Keep key-encryption keys separate from backup data and document break-glass recovery.
- Rotate credentials and keys with a tested procedure; do not store keys beside the backups they protect.
- Use immutable/WORM retention or equivalent object-lock controls where available.
- Record backup ID, tenant/data scope, source database identity, start/end time, schema/migration version, encryption-key reference, size, checksum/manifest, and completion status.
- Alert on missed, delayed, incomplete, unusually small, or integrity-failed backups.
- Never log backup credentials, encryption keys, or sensitive data.

## 5. Recovery objectives

Recovery Point Objective (RPO) and Recovery Time Objective (RTO) are service commitments, not guesses. They must be configurable by service tier only after measuring the hosting platform and cost.

Before production onboarding, publish and test:
- Maximum acceptable data loss (RPO) for each data class.
- Maximum acceptable service restoration time (RTO).
- Backup frequency, retention, and geographic/account separation.
- Recovery dependencies, including keys, DNS, identity, connectors, and external providers.

Until measured, RPO/RTO are **TBD**. Do not advertise zero data loss or instant recovery.

## 6. Restore and disaster-recovery workflow

1. Declare an incident and assign an authorized recovery lead.
2. Pause Autopilot and all response dispatch; revoke or suspend potentially compromised connector and service credentials.
3. Preserve relevant audit and forensic evidence before rebuilding, where safe.
4. Select a known-good recovery point from an isolated backup catalogue; do not trust the newest backup automatically.
5. Verify backup signature/checksum, manifest, encryption-key availability, schema version, and malware/compromise context.
6. Restore into an isolated clean environment with no production connectors or response credentials.
7. Apply required migrations and run integrity, tenant-isolation, identity, and audit-consistency checks.
8. Determine whether the recovery point contains attacker-controlled persistence, poisoned configuration, or compromised credentials.
9. Invalidate all restored operator sessions and pending one-time authentication/action tokens before application startup; rotate credentials and keys as required; re-enroll connectors and devices instead of blindly restoring trust.
10. Obtain an authorized recovery approval and switch traffic in a controlled manner.
11. Re-enable collection first; keep Autopilot and response execution disabled until explicitly reviewed.
12. Verify service health, event continuity, audit continuity, and customer-visible status; document data loss and recovery actions.

Never restore a potentially compromised backup directly over a live production environment without isolation and validation.

## 7. Tenant-safe recovery

- Restore scope must be explicit: full service, one tenant, or selected data classes.
- Tenant identity and ownership constraints must be revalidated after restore.
- A tenant restore must not overwrite another tenant's records or bypass RLS.
- Cross-tenant export/restore requires separate authorization and audited approval.
- Reconcile event IDs and idempotency keys to avoid duplicate ingestion or duplicate response actions.
- Preserve original event timestamps and provenance; record recovery timestamps separately.
- Define how deletions, legal holds, and retention obligations behave across backup copies.

## 8. Backup monitoring and operator experience

The product should expose:
- Last successful backup and last verified restore.
- Backup age, protected data classes, retention window, and integrity status.
- Configured RPO/RTO targets and current measured performance.
- Alerts for missed backups, failed integrity checks, expiring keys, and restore-test failures.
- A guided recovery status view with clear approval gates.

Do not expose raw backup credentials or encryption material in the dashboard. Recovery initiation must require privileged authentication and step-up verification.

## 9. Restore testing and release gates

- Automated backup completion and integrity checks.
- Scheduled restore drills into isolated infrastructure.
- Full disaster-recovery exercise before production launch and at a documented recurring cadence.
- Tenant-isolation tests after full and tenant-scoped restore.
- WAL/PITR recovery to selected timestamps.
- Backup deletion/overwrite denial tests using production application credentials.
- Key-loss and key-rotation recovery exercises.
- Corruption, partial backup, missing WAL, unavailable provider, and compromised-admin simulations.
- Measured RPO/RTO and documented recovery gaps.

A backup is not marked healthy solely because the provider reports upload success. A verified restore is required.

## 10. Initial implementation exclusions

The initial lab CLI provides encrypted single-database PostgreSQL dump creation, authenticated manifests, archive verification, and guarded restore into a new empty isolated database. The archive necessarily contains high-sensitivity database authentication verifiers and encrypted MFA secret material; restored sessions and one-time tokens must be invalidated before service startup. It does not provide a customer-facing dashboard, scheduler, off-site/immutable vault, WAL/PITR, object/evidence backup, tenant-selective restore, cross-region recovery, automated ransomware-clean restore, or guaranteed RPO/RTO. The CLI is authored but not executed; see [BACKUP_RESTORE_LAB.md](BACKUP_RESTORE_LAB.md).
