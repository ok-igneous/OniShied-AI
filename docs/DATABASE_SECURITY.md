# Database Security Standard

**Status:** Mandatory security baseline  
**Applies to:** Local lab, development, staging, production, cloud PostgreSQL, and customer-managed databases.

## 1. Core principles

- Deny by default; grant only the permissions required for a component's function.
- Enforce tenant isolation in the application and, where appropriate, reinforce it with PostgreSQL Row-Level Security (RLS).
- Treat the database as a sensitive security boundary. A valid API request must not automatically receive broad database privileges.
- Do not claim production readiness until the controls in this document have been implemented, tested, and reviewed.

## 2. Database identities and privileges

Use separate database roles for distinct duties:

- **Migration role:** owns schema changes and runs approved migrations; never used by the running API.
- **Application role:** only the required connect, schema usage, and table/sequence privileges; must not own tables or have superuser, CREATEDB, CREATEROLE, replication, or bypass-RLS privileges.
- **Read-only/reporting role:** limited to approved views or explicitly granted read access.
- **Backup/operations role:** separately controlled and used only by the backup/restore process.

Do not run the application as PostgreSQL superuser or table owner. Rotate credentials and revoke unused roles. Use separate credentials per environment and service.

## 3. Tenant isolation

- Derive the effective tenant identity from authenticated server-side identity and authorization context; never trust a client-supplied tenant ID as authority.
- Every tenant-owned query, update, delete, background job, cache key, and object-storage path must be tenant-scoped.
- Add tenant-aware foreign keys and uniqueness constraints where they protect ownership and idempotency.
- Evaluate PostgreSQL RLS for tenant-owned tables. If used, enable and force RLS where appropriate, define restrictive policies, and ensure the application role cannot bypass them.
- Set tenant context transaction-locally (for example with `SET LOCAL`) and use a connection-pool-safe approach. Never leave tenant context attached to a pooled connection across requests.
- Test cross-tenant reads, writes, updates, deletes, joins, exports, and background jobs. A test that only checks the API happy path is insufficient.
- RLS is defense in depth, not a replacement for application authorization or correct query design.

## 4. Query and transaction safety

- Use parameterized statements or a safely parameterized query builder for all untrusted values.
- Never construct SQL by concatenating user input, event fields, tenant identifiers, or AI output.
- Use transactions for operations that must succeed or fail together.
- Define transaction boundaries and isolation requirements for security-sensitive state changes.
- Handle unique-constraint conflicts deliberately. Detect event-ID reuse with different content rather than silently treating it as an identical duplicate.
- Apply query timeouts and connection limits. Avoid unbounded queries and uncontrolled N+1 access.
- Use migrations with reviewable, versioned SQL. Avoid destructive migrations without a tested backup and rollback/recovery plan.

## 5. Sensitive data protection

- Encrypt database connections using TLS in hosted or networked deployments; verify certificates rather than disabling verification.
- Use encrypted storage/volumes and managed key handling for database files, snapshots, and backups.
- Store secrets in a secret manager or protected deployment environment, not in the database as plaintext configuration.
- Minimize collection of personal data and credentials. Do not store passwords, access tokens, private keys, or session secrets in event payloads.
- Define retention, deletion, legal hold, and export behavior before real customer data is accepted.
- Restrict database logs and query diagnostics so they do not expose secrets or full sensitive payloads.

## 6. Backup, recovery, and availability

- Establish automated encrypted backups and, where required, point-in-time recovery.
- Restrict backup access independently from application access.
- Define recovery point objective (RPO) and recovery time objective (RTO) before production launch.
- Test restoration on a schedule; a backup that has never been restored is unverified.
- Monitor connection saturation, storage growth, failed backups, replication lag where applicable, and database availability.
- Document incident response for suspected database credential compromise or data exposure.

## 7. Development and lab safeguards

- Use synthetic data only in the initial lab.
- Keep local database ports bound to loopback unless network access is explicitly required and protected.
- Use disposable, non-production credentials. Never commit real `.env` files or database dumps.
- Do not copy production data into development or test environments without an approved, documented sanitization process.
- Test migrations and tenant boundaries against a disposable PostgreSQL instance in CI or a controlled integration environment.

## 8. Production launch gate

Before production customer data is stored, verify and record evidence for:

- [ ] Separate migration and runtime roles; runtime is not owner or superuser.
- [ ] Tenant authorization and cross-tenant isolation tests.
- [ ] RLS design decision documented; policies tested if enabled.
- [ ] TLS and encryption-at-rest configuration verified.
- [ ] Secret storage, rotation, and revocation process.
- [ ] Parameterized queries and safe transaction boundaries.
- [ ] Backups, restore test, RPO/RTO, and access controls.
- [ ] Retention, deletion, export, and audit requirements.
- [ ] Database monitoring, alerting, and incident runbook.
- [ ] Independent security review of the deployment configuration.

The current prototype does not yet satisfy this production gate. Its database controls must be assessed and implemented incrementally before customer onboarding.
