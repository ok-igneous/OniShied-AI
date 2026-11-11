# Proposed System Architecture

**Status:** Initial proposal for prototyping. Validate each boundary with a working vertical slice before treating this document as a final architecture.

## Deployment direction

Hybrid deployment is the target: a cloud control plane for organization management, policy distribution, coordination, and centralized reporting; local or customer-controlled components for telemetry access and selected response operations. Desktop and mobile clients provide operator experiences. Mobile is initially a management and alert-review client, not a privileged endpoint response agent.

## Logical components

1. **Endpoint / data connectors** — collect only explicitly authorized telemetry from a documented source.
2. **Ingestion API** — authenticate connector identity, validate payloads, rate-limit, and attach provenance.
3. **Event normalization** — convert source-specific records into a versioned canonical event schema.
4. **Detection engine** — deterministic rules and signals produce reproducible findings.
5. **Investigation orchestrator** — gathers bounded context and asks AI to summarize evidence, identify gaps, and propose next steps.
6. **Policy and approval service** — checks actor, tenant, action, target, risk, approval, and policy version before any execution.
7. **Response executor** — runs a narrow allowlisted set of actions with least privilege, idempotency, timeout, and rollback where possible.
8. **Audit service** — records event references, model/prompt version where applicable, policy decision, approver, action, result, and timestamps.
9. **Operator clients** — desktop-first operational console and mobile alert/approval experience.
10. **Identity and tenant control plane** — organization membership, roles, device enrollment, policy, configuration, and subscription lifecycle.

## Trust boundaries

- Endpoint/customer environment to ingestion boundary.
- Cloud control plane to customer-local connector boundary.
- Deterministic detection to probabilistic AI analysis boundary.
- AI recommendation to policy enforcement boundary.
- Operator identity to privileged response executor boundary.
- Tenant boundary for every customer-owned record and action.

AI output is advisory data. It must never bypass authorization or policy enforcement.

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

Design for retries, idempotency, queue back-pressure, dead-letter handling, connector offline states, clock skew, partial failures, and safe recovery. Never interpret missing telemetry as proof that a system is safe.

## Open architecture decisions

- First telemetry source and supported operating system.
- Backend language/framework and database.
- Queue/event transport.
- Local connector packaging and update mechanism.
- Cloud provider and customer data residency requirements.
- Key management and device identity lifecycle.
- Model provider, data-processing terms, and fallback strategy.

Record decisions as ADRs under `docs/DECISIONS/`.
