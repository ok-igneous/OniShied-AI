# Backup Storage, Custody, Retention and Recovery Policy

**Status:** Normative product/architecture policy. This is a design contract, not a claim that hosted storage, customer onboarding, billing, or recovery automation is implemented.
**Applies to:** Every OniShield tenant and all backup data handled by OniShield.
**Decision:** Dual-custody is the target operating model: the customer retains a customer-controlled recovery copy, and OniShield provides an independently administered off-site copy when the selected plan and deployment support it. A third isolated/immutable copy is the enterprise target.

## 1. Responsibility model

| Responsibility | Customer | OniShield |
|---|---|---|
| Maintain access to its own local backup destination | Owns and controls it | Supplies tooling and guidance |
| Produce encrypted backup artifacts | May operate the customer-side agent/job | Provides and maintains backup software |
| Operate OniShield-managed remote storage | No infrastructure administration | Owns provider account, storage operations and monitoring |
| Pay for included remote allowance | Pays subscription | Funds allowance within plan economics |
| Pay for storage above allowance | Pays agreed add-on/overage | Measures usage and bills transparently |
| Protect encryption-key recovery material | Owns customer-controlled key in customer-managed mode | Operates managed-key option only under documented policy |
| Authorize restore and define acceptable downtime | Approves customer-impacting recovery | Executes approved workflow and records evidence |
| Test restore capability | Participates in application acceptance | Runs scheduled technical restore drills and reports results |

Customer-hosted storage is not automatically trustworthy: it can be lost with the production site or compromised by the same administrator. OniShield-managed storage is not automatically independent: it must be outside the production administrative boundary and protected from production credentials.

## 2. Storage layers

### Layer A — Customer-controlled copy

- Encrypted backup written to a customer-controlled server, NAS, or other supported destination.
- Customer controls physical custody, access and local retention.
- The backup process must not require the customer to expose a public storage endpoint.
- Local copy is a fast-recovery layer, not the sole disaster-recovery copy.
- Customer is responsible for physical security, capacity, availability and independent testing of this destination.

### Layer B — OniShield-managed off-site copy

- OniShield operates the remote storage account/project and backup service.
- Tenant data must be isolated by authorization and storage namespace; object identifiers must not be treated as authorization.
- Encrypt artifacts before transfer. Use TLS in transit and authenticated encryption at rest.
- Remote storage administration must be separate from production application administration.
- Production application credentials must not delete, overwrite, shorten retention, or disable protection for backup history.
- The service must monitor backup age, upload/verification failures, quota, retention and storage-provider health.
- Storage provider is an implementation choice. S3-compatible storage is an adapter, not a mandatory dependency. No specific provider, including AWS, is required by this policy.

### Layer C — Independent recovery copy (Enterprise target)

- Separate account, project, provider or offline custody boundary from both production and the primary backup vault.
- Prefer immutable/WORM retention where available and verified against the actual provider.
- Use a separate administrative identity and recovery procedure.
- Do not claim immutability merely because a provider supports versioning. Verify retention mode, permissions, deletion resistance and actual restore behavior.

## 3. Product tiers and commercial rules

These are proposed packaging rules; exact quotas, retention periods, prices and overage rates require cost modelling and approval before publication.

| Tier | Target backup entitlement |
|---|---|
| Basic | Customer-controlled encrypted backup tooling; no promise of OniShield-hosted off-site copy unless explicitly included |
| Professional | Customer copy plus an included, quota-limited OniShield-managed off-site allowance |
| Enterprise | Dual custody plus a separately isolated/immutable recovery copy, extended retention options and recovery-drill reporting |

Commercial requirements:
- Publish included storage capacity, retention window, backup frequency, protected data scope and restore support per plan.
- Measure storage using a documented basis (stored encrypted bytes and retained versions); expose current usage and forecasted overage.
- Never silently stop protecting data when a quota is reached. Alert before exhaustion and apply a documented policy: paid expansion, customer-approved retention adjustment, or an explicit failed/degraded state.
- Never delete the only recoverable copy to enforce billing.
- Define egress, restore labor, emergency recovery and long-term retention charges before offering the service.
- Keep backup storage costs and AI usage charges separate and transparent.

## 4. Encryption-key custody

Support two explicit modes; do not mix their promises:

1. **Customer-controlled key mode:** the customer controls the key-encryption/recovery material. OniShield must not be able to decrypt customer backups unilaterally. Loss of the customer's key can make backups unrecoverable; this limitation must be explicit and tested.
2. **OniShield-managed key mode:** OniShield operates keys in a dedicated KMS/HSM or equivalent secret-management boundary, separate from production and storage administration. Access is tightly scoped, audited, recoverable under dual control, and never exposed to tenant application roles.

For both modes:
- Encrypt before upload; use authenticated encryption and integrity-authenticated manifests.
- Keep key material separate from backup data and retain historical keys for every retained backup.
- Use versioned key IDs, controlled rotation and documented retirement approval.
- Never put plaintext keys in manifests, logs, status files, source control, support tickets or customer-visible URLs.
- Test key recovery and historical restore before retiring a key.
- A customer-managed key feature is not complete until key escrow/recovery, tenant offboarding, legal hold and disaster scenarios are specified.

## 5. Tenant isolation and authorization

- Every backup record, artifact, manifest, object key, status entry, retention policy and restore request is bound to a tenant identifier on the server side.
- Tenant identifiers supplied by clients are not authoritative; derive scope from authenticated server-side membership and authorization.
- Enforce tenant isolation at both metadata/database and storage access layers.
- Use opaque object names; do not expose tenant names, database names or secrets in public object paths.
- Cross-tenant backup access is prohibited except through a separately authorized, audited break-glass process.
- Backup operators receive only the minimum permissions needed for their task. Routine upload identities must not have delete, retention-bypass or bucket-configuration permissions.
- Log actor, tenant, backup ID, action, approval, outcome and timestamp without logging keys, credentials or backup contents.

## 6. Restore and incident responsibilities

- Customer requests/approves customer-impacting recovery; OniShield validates authorization and executes only within the approved scope.
- Emergency actions must require strong operator authentication and step-up verification, record the reason and preserve an immutable audit trail.
- Restore into an isolated environment first. Verify integrity, schema/migration compatibility, tenant isolation, identity and audit continuity, and compromise context before cutover.
- Invalidate restored sessions, pending one-time authentication material and other trust that must not survive recovery; rotate credentials and re-enroll devices/connectors where incident context requires it.
- Keep Autopilot and response dispatch paused during recovery. Re-enable collection first; response execution requires separate authorization.
- State clearly whether recovery is self-service, assisted, or a separately billed professional service.

## 7. Monitoring, retention and deletion

- Track last successful backup, last integrity verification, last successful restore drill, backup age, stored bytes, retention expiry, key ID and failure reason.
- Alert on missed schedules, stale backups, quota thresholds, failed verification, failed restore drills, expiring keys and provider/immutability drift.
- Retention is tenant- and plan-configurable only within approved legal and operational bounds.
- Customer deletion requests must be reconciled with backup retention, legal holds and applicable obligations. Document when deleted records age out of retained backup generations and how restore re-applies deletion/tombstone policy.
- Do not promise immediate physical erasure from immutable copies where retention legally/technically prevents it; disclose the actual expiry behavior.
- A backup is not healthy because an upload succeeded. Health requires integrity checks and recurring isolated restore evidence.

## 8. Rollout gates

1. Verify local PostgreSQL create → cryptographic verify → isolated restore, including key rotation.
2. Verify customer-side destination handling and permissions.
3. Select and cost a remote provider only after provider-neutral storage interfaces and threat model are reviewed.
4. Run real remote upload → exact-version download → verification → isolated restore against the selected provider.
5. Demonstrate tenant-isolation and cross-tenant denial tests.
6. Demonstrate deletion resistance and retention behavior using the actual provider and identities.
7. Add scheduling, alerts, quota enforcement, retention lifecycle and customer-visible status.
8. Complete application-level recovery including tenant data, identity, audit, event continuity and object/evidence inventory.
9. Measure RPO/RTO before publishing service commitments.

Until these gates pass, describe the feature as a backup/restore lab or planned capability, not a production managed backup service. Local-only backups are not protection against loss or compromise of the host that stores them.
