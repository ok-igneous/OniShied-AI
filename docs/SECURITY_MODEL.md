# Security Model and Threat Boundaries

## Security objectives

Protect customer systems, tenant data, operator identities, connector credentials, response integrity, and audit evidence. Prevent OniShield itself from becoming a privileged attack path.

## Threat actors and failure sources

- External attackers targeting APIs, connectors, endpoints, or operator accounts.
- Malicious or compromised tenant users.
- Compromised endpoint connectors or integration credentials.
- Prompt injection embedded in logs, documents, tickets, websites, or threat-intelligence feeds.
- Incorrect, hallucinated, or overconfident model output.
- Insider misuse or accidental privilege escalation.
- Supply-chain compromise and vulnerable dependencies.
- Operational failures such as retries, stale policy, clock skew, or partial outages.

## Required controls

### Identity and access
- Strong authentication for operators, including TOTP for privileged operator roles; MFA secrets must be encrypted with a separately managed key, challenges must be one-use, and TOTP counters must be replay-protected.
- Role-based access with least privilege.
- Short-lived, scoped connector credentials and revocation.
- Tenant-scoped authorization on every request and background job.
- Separation of administrative, investigative, approval, and execution permissions.

### Telemetry and data
- Authenticate sources and validate schemas.
- Enforce size limits, rate limits, and parser isolation.
- Redact secrets and minimize personal data.
- Encrypt transport and stored sensitive data.
- Apply tenant isolation and documented retention/deletion rules.

### Threat intelligence safety
- Treat indicators and feed content as untrusted until validated and provenance-reviewed.
- Record source, license/handling restrictions, confidence rubric, collection time, validity, and expiry.
- Tenant intelligence is private by default; global intelligence uses a separately authorized namespace.
- Exact indicator matches are contextual evidence only and cannot authorize blocking or remediation.
- Enforce TLP:CLEAR, GREEN, AMBER, and RED handling restrictions on every read, report, and export; TLP never overrides tenant isolation.
- Derive actor identity, tenant, community, organization, and named-recipient membership from trusted server-side authorization, never caller-supplied fields.
- Expired, revoked, pending, or rejected indicators must not match.

### AI safety
- Treat model responses as untrusted proposals.
- Treat all retrieved content as untrusted data; never allow it to redefine system policy.
- Keep investigation read-only with bounded, tenant-authorized evidence tools; no shell, arbitrary network, arbitrary SQL, or response tools.
- Use structured output validation and evidence references.
- Limit tools to task-specific read operations unless a separate policy gate authorizes an action.
- Detect missing evidence and state uncertainty.
- Never allow model confidence alone to authorize a response.

### Configurable Autopilot safety
- Autopilot is tenant opt-in and disabled by default; provide explicit mode, risk ceiling, per-action allowlist, target scope, and emergency pause.
- Enforce configuration in a deterministic server-side policy service before every execution; never trust UI state or model output.
- Tier 2 actions always require human approval; Tier 3 actions are excluded from the initial product and cannot be enabled by tenant configuration.
- Reject stale policy, ambiguous targets, missing evidence, unavailable audit, and uncertain execution outcomes.
- Apply rate, concurrency, time-window, and blast-radius limits; use idempotency and bounded retries.

### Response safety
- Maintain an explicit allowlist of action types and targets.
- Use dry-run mode by default.
- Require precondition checks and least-privilege execution.
- Require human approval for destructive, disruptive, irreversible, or high-impact actions.
- Make actions idempotent where possible; define timeout and rollback behavior.
- Verify outcomes and log failures.
- Provide emergency pause and credential revocation.

### Backup and recovery safety
- Keep at least one encrypted recovery copy outside the production administrative boundary; replication alone is not a backup.
- Separate backup credentials from application and ordinary operator credentials; use immutable/versioned retention where available.
- Keep encryption keys separate from backup data and test key recovery/rotation.
- Restore into an isolated clean environment before returning to service; rotate potentially compromised credentials and re-enroll connectors.
- Verify tenant isolation, audit continuity, schema integrity, and recovery-point provenance after restore.
- Define and measure RPO/RTO; never promise zero data loss or instant recovery without evidence.
- Run recurring restore drills; provider upload success alone is not a verified backup.

### Audit integrity
Record who or what initiated an action, tenant, target, evidence references, policy version, approval identity, execution identity, timestamps, result, and errors. Protect audit records from ordinary operator modification.

## Risk tiers (initial proposal)

- **Tier 0 — Observe:** read-only collection and analysis; may run automatically within consent and policy.
- **Tier 1 — Low impact / reversible:** narrowly scoped, reversible actions; automation only after explicit tenant opt-in and tested policy.
- **Tier 2 — Disruptive:** actions that interrupt accounts, devices, or services; require human approval.
- **Tier 3 — Destructive / irreversible:** wiping, deleting, broad isolation, or irreversible changes; excluded from the initial product and require exceptional controls if ever introduced.

Risk tier is determined by impact and reversibility, not by the model's confidence score.

## Safe testing rules

Use synthetic telemetry, intentionally vulnerable local labs, or systems with documented authorization. No production or third-party scanning, exploitation, credential attacks, persistence, or data extraction without explicit written authorization and a scoped test plan.

## Minimum security test cases

- Cross-tenant access attempts are denied.
- Expired/revoked connector credentials are denied.
- Malformed and oversized events are rejected safely.
- Prompt injection in event content cannot change tool permissions.
- Invalid model output cannot trigger execution.
- Missing approval blocks Tier 2 actions.
- Replayed requests do not duplicate response actions.
- Audit records show denied and failed actions.
- Emergency pause prevents new executions.
- Connector compromise can be contained by revoking its identity.


## Code and database security standards

Implementation must comply with [CODE_STANDARDS.md](CODE_STANDARDS.md) and [DATABASE_SECURITY.md](DATABASE_SECURITY.md). The 500-line source-file ceiling is mandatory. Database controls must include least-privilege roles, tenant isolation tests, parameterized queries, encrypted connections and storage, controlled backups, tested restoration, and documented retention/deletion. RLS is defense in depth and must be correctly configured and tested if adopted. The initial prototype is not production-ready merely because these requirements are documented.
