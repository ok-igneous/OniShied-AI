# Proposed System Architecture

**Status:** Initial proposal for prototyping. Validate each boundary with a working vertical slice before treating this document as a final architecture.

## Deployment direction

Hybrid deployment is the target: a cloud control plane for organization management, policy distribution, coordination, and centralized reporting; local or customer-controlled components for telemetry access and selected response operations. Desktop and mobile clients provide operator experiences. Mobile is initially a management and alert-review client, not a privileged endpoint response agent.

## Logical components

1. **Endpoint / data connectors** — collect only explicitly authorized telemetry from a documented source.
2. **Ingestion API** — authenticate connector identity, validate payloads, rate-limit, and attach provenance.
3. **Event normalization** — convert source-specific records into a versioned canonical event schema.
4. **Detection engine** — deterministic rules and signals produce reproducible findings.
5. **Threat intelligence service** — validates, versions, expires, and matches provenance-backed indicators as contextual signals; it never authorizes response. See [THREAT_INTELLIGENCE_CONTRACT.md](THREAT_INTELLIGENCE_CONTRACT.md).
6. **Investigation orchestrator** — gathers bounded context and asks AI to summarize evidence, identify gaps, and propose next steps. See [INVESTIGATION_ENGINE_CONTRACT.md](INVESTIGATION_ENGINE_CONTRACT.md).
7. **Policy and approval service** — checks actor, tenant, action, target, risk, approval, and policy version before any execution.
8. **Autopilot policy service** — evaluates tenant opt-in, autonomy mode, risk ceiling, action allowlist, target scope, approvals, rate limits, and emergency pause. AI cannot grant permissions. See [AUTOPILOT_CONTRACT.md](AUTOPILOT_CONTRACT.md).
9. **Response executor** — runs a narrow allowlisted set of actions with least privilege, idempotency, timeout, verification, and rollback where possible.
10. **Backup and recovery service** — coordinates encrypted snapshots, isolated backup copies, integrity verification, restore drills, and clean-room recovery. See [BACKUP_AND_RECOVERY.md](BACKUP_AND_RECOVERY.md).
11. **Audit service** — records event references, model/prompt version where applicable, policy decision, approver, action, result, and timestamps.
12. **Operator clients** — desktop-first operational console and mobile alert/approval experience, including Autopilot controls and recovery status.
13. **Identity and tenant control plane** — organization membership, roles, device enrollment, policy, configuration, and subscription lifecycle.

## Trust boundaries

- Endpoint/customer environment to ingestion boundary.
- Cloud control plane to customer-local connector boundary.
- Deterministic detection to probabilistic AI analysis boundary.
- AI recommendation to policy enforcement boundary.
- Operator identity to privileged response executor boundary.
- Tenant boundary for every customer-owned record and action.

AI output is advisory data. It must never bypass authorization or policy enforcement. Autopilot is opt-in and default-off; policy checks are deterministic and server-side. Backups must be isolated from production administrative credentials, and recovery must begin in a clean environment.

## Core workflow

`Telemetry → Validate → Normalize → Detect → Investigate → Policy check → Approval (when required) → Execute → Verify → Audit`

Each stage must emit a correlation identifier. Failed stages must be visible and must not silently advance to execution.

## Data design principles

- Version all event schemas.
- Preserve source event identity and provenance.
- Store timestamps in UTC and retain source timezone metadata when available.
- Separate tenant-owned data and enforce tenant scope at every query and job boundary.
- Minimize retention and redact secrets and unnecessary personal data.
- Encrypt data in transit and at rest.
- Define retention, export, and deletion behavior before onboarding real customers.

## AI orchestration constraints

- Use structured outputs validated against schemas.
- Give the model read-only investigation tools by default.
- Apply tool allowlists, argument validation, timeouts, and per-run budgets.
- Treat retrieved logs, files, websites, and threat intelligence as untrusted data, not instructions.
- Require the policy service to independently authorize every action.
- Record model and prompt versions plus cited evidence identifiers.
- Fall back safely when the model is unavailable or returns invalid output.

## Reliability and operations

Design for retries, idempotency, queue back-pressure, dead-letter handling, connector offline states, clock skew, partial failures, and safe recovery. Never interpret missing telemetry as proof that a system is safe. A backup is not considered verified until a restore drill succeeds. Autopilot fails closed whenever policy, audit, target identity, or outcome verification is unavailable.

## Open architecture decisions

- First telemetry source and supported operating system.
- Backend language/framework and database.
- Queue/event transport.
- Local connector packaging and update mechanism.
- Cloud provider and customer data residency requirements.
- Key management and device identity lifecycle.
- Model provider, data-processing terms, and fallback strategy.

Record decisions as ADRs under `docs/DECISIONS/`.


## Implementation structure and database boundary

All implementation work must follow [CODE_STANDARDS.md](CODE_STANDARDS.md). Source files have a hard 500-line ceiling and should be split into cohesive modules by responsibility. Keep API transport, domain services, persistence, validation, policy enforcement, and integrations separate.

Database design and operations must follow [DATABASE_SECURITY.md](DATABASE_SECURITY.md). Tenant scope must be enforced on every data access path; PostgreSQL RLS should be evaluated as defense in depth. Runtime database credentials must be least-privileged and separate from migration credentials. Production data must not be accepted until the documented database launch gate is satisfied.
