# OniShield AI Investigation Layer

## Status
Architecture contract for the first investigation milestone. This document does not claim that an investigation service, database schema, API, AI provider integration, or operator UI has been implemented. Existing capabilities include deterministic findings, tenant-scoped evidence references, threat-intelligence match links, replay, and operator-controlled finding status transitions.

## Objective
Turn related detection findings into an operator-readable investigation case: a durable workspace for understanding an incident, not a new detector and not an autonomous response authority.

A case should answer: what happened; which deterministic rules fired; which exact events support each statement; what threat-intelligence matches are relevant; what is known, unknown, or conflicting; and what operators decided.

## Trust boundaries
- Deterministic detection and database records remain authoritative for event identity, finding identity, timestamps, rule versions, and threat-match references.
- AI output is untrusted analysis. It may summarize supplied evidence and propose hypotheses; it cannot create evidence, change source records, change finding status, or authorize response actions.
- Every factual assertion in generated reports must cite exact evidence references already present in the case. Unsupported assertions must be labeled hypotheses or omitted.
- Threat-intelligence matches are contextual signals, not proof of compromise. Preserve indicator confidence, TLP, source, version, validity interval, and review status.
- Tenant identity comes from the authenticated operator session, never request data or model output.
- All case, finding, evidence, note, report, and audit operations remain tenant-scoped and RLS-protected.
- No public unauthenticated investigation, replay, or lifecycle endpoint.
- No autonomous containment, account disabling, firewall changes, host isolation, data deletion, or other disruptive action in this milestone.

## Domain model

### Investigation case
- case_id: opaque server-generated UUID or digest.
- tenant_id: server-derived tenant scope.
- title: bounded, operator-editable.
- status: open, investigating, contained, resolved, closed.
- priority: derived from highest contributing finding severity; operator override is separately audited.
- created_at, updated_at, last_activity_at.
- created_by_membership_id and optional assigned_to_membership_id.
- correlation_version: deterministic policy version.
- optional generated summary with provider/model/template metadata and generation timestamp.

A case may contain multiple findings. A finding may belong to at most one active case in the first release. Future case merges must preserve old IDs and write an auditable merge record.

### Case-finding association
Store exact tenant + case + finding identity with a uniqueness constraint. Record correlation reason, policy version, timestamp, and actor membership for human-created links.

### Evidence manifest
Reference canonical records rather than copying event payloads:
- tenant_id + connector_id + event_id
- finding_id
- evidence role: trigger, supporting, or context
- first-associated timestamp
- association source: detector, operator, or replay

Use composite foreign keys to canonical events and findings. Evidence additions must be idempotent under retries and concurrent requests. Never use delimiter-concatenated identity keys.

### Investigation activity
Append-only records capture case creation, finding association, assignment, status changes, operator notes, report generation, and decisions. Record actor type, actor membership where applicable, timestamp, request ID, and reason or payload digest. AI activity identifies provider, model, template version, and input evidence-manifest digest. Do not copy credentials, secrets, or unnecessary sensitive event payloads into activity rows.

## Deterministic correlation policy
Do not begin with an LLM deciding which findings belong together. The first policy must be conservative:
1. Same tenant is mandatory.
2. Require an exact shared detector grouping identity or explicit operator association.
3. Require overlapping or adjacent event-time windows within a documented bound.
4. Require compatible entity references (for example, normalized host and principal) when present.
5. Never correlate solely on shared public IP, indicator, severity, or text similarity.
6. Keep ambiguous candidates separate and expose suggested links for operator review.
7. Persist policy version and machine-readable reasons for every automatic association.

Cross-tenant correlation is prohibited in tenant workspaces. Any future global threat-intelligence network is a separately governed, privacy-reviewed subsystem.

## AI investigation workflow
1. Authenticate operator and derive tenant scope from session.
2. Load case, findings, canonical event metadata, evidence links, and exact threat matches within tenant scope.
3. Build a bounded evidence package with field allowlists, size limits, redaction, and prompt-injection isolation for untrusted event strings.
4. Request structured analysis: timeline, observed facts with evidence references, hypotheses, confidence, gaps, contradictions, and human-review recommendations.
5. Validate against a strict schema. Reject unknown evidence references, unsupported factual claims, oversized output, malformed fields, and tool/action requests.
6. Persist each report as an immutable version with provider/model/template metadata and exact evidence-manifest digest.
7. Require operator review, edit, acceptance, or rejection. Acceptance does not execute disruptive actions.

The model receives no database credentials, connector tokens, operator session tokens, MFA material, or direct database/network tools. Event content is untrusted data, never instructions.

## Planned API boundary
All endpoints require operator bearer authentication and explicit permissions:
- GET /v1/operator/investigations — paginated tenant-scoped case list.
- POST /v1/operator/investigations — create from selected existing findings; require reason.
- GET /v1/operator/investigations/:caseId — case, findings, evidence manifest, activity.
- POST /v1/operator/investigations/:caseId/findings — associate an existing finding with an auditable reason.
- POST /v1/operator/investigations/:caseId/notes — append operator note.
- POST /v1/operator/investigations/:caseId/analyze — enqueue analysis; rate-limited and idempotent.
- GET /v1/operator/investigations/:caseId/reports — immutable report versions.

Do not expose arbitrary SQL, arbitrary cross-tenant evidence IDs, model tools, or free-form response commands. Use pagination and hard limits. The connector-authenticated findings route is not an operator UI.

## Database and concurrency requirements
- Create tenant-scoped case, association, evidence, activity, report, and analysis-job tables as needed.
- Enable and FORCE RLS on every tenant-owned table.
- Use composite tenant-aware foreign keys to findings, events, and operator memberships.
- Add uniqueness constraints for case/finding links, evidence identity, and analysis idempotency keys.
- Grant runtime roles only minimum required operations. Operator mutations use authenticated service methods or narrowly scoped database functions.
- Activity is append-only for runtime roles.
- Use row locks or transaction-scoped advisory locks for associations and state transitions.
- Analysis jobs use leases, bounded retries, and crash recovery. Never hold a DB transaction open during provider calls.
- Store provider request IDs and evidence digests, not secrets or sensitive full prompts.
- Define retention/deletion policy before storing reports or notes containing sensitive data.

## Failure handling
- Provider outage must not make deterministic case evidence unavailable.
- Invalid model output is discarded; record only a bounded failure event.
- Retries use idempotency keys and evidence digests to prevent duplicate reports.
- New evidence does not silently rewrite an existing report. Mark it stale against its evidence-manifest digest and offer a new version.
- Uncertain correlation never auto-merges cases.

## First implementation acceptance criteria
- Authorized operator can create a tenant-isolated case from existing findings.
- Case read returns exact findings, evidence references, threat context, and append-only activity.
- Duplicate association requests are idempotent; concurrent requests cannot duplicate links.
- Cross-tenant case/finding/event/membership references fail at constraints and RLS.
- Server-side permissions; sensitive mutations require recent step-up where appropriate.
- Notes and state changes record actor, reason, request ID, and timestamp.
- Case create/read works without any AI provider integration or response execution.
- Unit tests cover correlation and validation; SQL smoke tests cover RLS, constraints, append-only activity, and idempotency.
- Tests, typecheck, build, and migrations must actually execute before merge. Authored tests are not verification.

## Deliberate exclusions
This milestone is not an AI SOC replacement, autonomous incident response, endpoint remediation, backup/restore, customer dashboard, cross-tenant threat graph, or production-readiness claim. Those require separate threat models, operational controls, and verification.
