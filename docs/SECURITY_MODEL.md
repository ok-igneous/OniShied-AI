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
- Strong authentication for operators.
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

### AI safety
- Treat model responses as untrusted proposals.
- Treat all retrieved content as untrusted data; never allow it to redefine system policy.
- Use structured output validation and evidence references.
- Limit tools to task-specific read operations unless a separate policy gate authorizes an action.
- Detect missing evidence and state uncertainty.
- Never allow model confidence alone to authorize a response.

### Response safety
- Maintain an explicit allowlist of action types and targets.
- Use dry-run mode by default.
- Require precondition checks and least-privilege execution.
- Require human approval for destructive, disruptive, irreversible, or high-impact actions.
- Make actions idempotent where possible; define timeout and rollback behavior.
- Verify outcomes and log failures.
- Provide emergency pause and credential revocation.

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
