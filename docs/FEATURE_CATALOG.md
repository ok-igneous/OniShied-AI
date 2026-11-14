# OniShield AI — Product Feature Catalogue

**Last updated:** 2026-11-14  
**Document type:** Product scope and capability register  
**Product status:** Early-stage foundation; not production-ready.

This catalogue records the intended product capabilities and their current implementation status. A feature appearing here is not evidence that it has been built. See [Implementation Status](IMPLEMENTATION_STATUS.md) for repository-level evidence and verification blockers.

## 1. Product definition

OniShield AI is an intended **Autonomous Cybersecurity Platform** for individuals, small and medium-sized businesses, and larger organizations. Its purpose is to help users collect authorized security telemetry, detect suspicious activity, investigate evidence, apply policy-controlled responses, and recover safely after incidents.

The target deployment is hybrid:
- A cloud control plane for identity, tenant administration, policy, coordination, and reporting.
- Customer-controlled or local components for telemetry collection and selected response operations.
- Desktop clients for security operations.
- Mobile clients for alerts, review, approvals, and administration; mobile is not initially a privileged endpoint-response agent.

OniShield is intended to operate standalone and to integrate with the wider OniVend ecosystem where a customer chooses to connect them. Neither integration nor shared identity should weaken tenant isolation or make OniVend a dependency for core security operation.

## 2. Status vocabulary

- **Implemented — unverified:** code or tests are present in the repository, but the required CI or independent runtime verification has not passed.
- **Design documented:** requirements and contracts exist; implementation is not present.
- **Partial:** some components exist, but the complete user-facing or end-to-end capability is missing.
- **Planned:** accepted product direction, not yet specified or implemented sufficiently.
- **Not implemented:** no working implementation is currently claimed.

No item should be promoted to verified or production-ready without repeatable tests and evidence.

## 3. Platform capability map

| Capability | Intended function | Current status |
|---|---|---|
| Identity and tenant control plane | Operator identity, organizations, memberships, roles, tenant boundaries, policy and device enrollment | Partial; backend foundation implemented, unverified |
| Security event ingestion | Authenticated ingestion, validation, canonical event format, provenance and deduplication | Implemented in repository, unverified |
| Event normalization | Normalize supported source events into a versioned canonical schema | Partial; schema and initial paths exist, end-to-end verification pending |
| Deterministic detection | Explainable rules, severity, confidence, evidence references and false-positive handling | Partial; authentication burst and failure-then-success rules exist in unmerged code, unverified; no process/network/file/service rules |
| Threat intelligence | Normalize and match indicators, preserve provenance, review indicator status | Partial; internal matching and reviewer controls implemented in code, unverified; not wired into ingestion |
| AI investigation | Evidence-linked summaries, correlation, uncertainty, investigation recommendations | Backend case store, authenticated routes, leased analysis worker, citation validation and immutable reports authored; unverified; no dashboard or automatic case correlation |
| Policy and approvals | Server-side authorization, risk evaluation, approvals and action governance | Design documented; complete policy service not implemented |
| Response execution | Narrow typed actions, idempotency, verification, rollback and audit | Not implemented |
| Configurable Autopilot | Tenant-controlled, risk-bounded automation with OFF default and emergency pause | Technical contract documented; no policy schema, UI or executor |
| Backup and recovery | Encrypted, isolated backups, integrity checks, restore and disaster recovery | Technical contract documented; no scheduler, vault or restore tooling |
| Operator experience | Desktop operations console and mobile alert/approval experience | Not implemented |
| Reporting and audit | Searchable security history, action decisions, evidence and recovery records | Partial audit foundations; complete operator reporting not implemented |
| Endpoint connectors | Authorized Windows/Linux telemetry collection and controlled local actions | Partial; enrollment and credential-authenticated ingestion exist on unmerged branches, but no endpoint agent binary, installer, inventory UI or production deployment is claimed |
| Integrations | Customer-approved security, identity, cloud and business-system integrations | Planned; integration framework and supported providers need design |
| Subscription and OniVend integration | Optional product licensing/account integration | Product direction only; not part of the verified security foundation |

## 4. Security operations capabilities

### 4.1 Asset and endpoint protection

Target capabilities:
- Enroll and identify authorized Windows and Linux endpoints.
- Maintain device inventory, ownership, operating-system and agent health.
- Collect explicitly authorized authentication, process, service and network telemetry.
- Detect missing or stale telemetry and report agent health.
- Apply narrowly scoped, policy-approved endpoint actions in later releases.
- Support customer-controlled deployment and removal.

**Status:** Enrollment and telemetry ingestion foundations are implemented in unmerged PR branches, not verified. Device inventory UI, credential rotation, agent health monitoring, signed binaries, installers and deployment remain outstanding. No production endpoint protection agent is claimed.

### 4.2 Event pipeline

Target workflow:
1. Authenticate the connector.
2. Validate and rate-limit incoming data.
3. Preserve source identity and provenance.
4. Normalize into the canonical event schema.
5. Enforce tenant isolation.
6. Deduplicate safely and retain event lineage.
7. Make validated events available to detection and investigation services.

**Status:** Authenticated ingestion, strict Zod validation, database-side kind-specific validation, canonical persistence, idempotency, durable replay enqueue and a per-agent database event-attempt budget are authored on unmerged branches. Route and PostgreSQL tests are authored but unexecuted; a separate ingestion DB role and IP/request-level abuse controls remain outstanding.

### 4.3 Detection and alert triage

Target capabilities:
- Deterministic, versioned detection rules.
- Explainable match conditions and source-event references.
- Severity distinct from confidence.
- Correlation across related events and assets.
- Benign counterexamples and false-positive handling.
- Suppression, escalation and analyst disposition with audit.

**Status:** Two deterministic authentication rules and finding persistence/lifecycle foundations exist in unmerged code, unverified. Endpoint heartbeat/process/network/file/service events are stored but not covered by dedicated detection rules. False-positive evaluation and a complete triage workflow remain outstanding.

### 4.4 Threat intelligence

Target capabilities:
- Indicator validation, canonical normalization and provenance.
- Exact matching against explicitly mapped event fields.
- Expiry, confidence, source quality and review status.
- Reviewer-controlled state transitions and audit.
- Tenant-scoped access and disclosure controls.
- Future controlled feed ingestion and carefully governed sharing.

**Status:** Initial deterministic normalization/matching, tenant-scoped persistence and reviewer audit controls exist in code but are unverified. Matching is not wired into ingestion or response. Automatic feeds, global intelligence and cross-tenant sharing are not implemented.

### 4.5 AI investigation assistant

Target capabilities:
- Retrieve only authorized, tenant-scoped evidence.
- Produce structured findings with event/evidence references.
- Separate observed facts, hypotheses, confidence and unknowns.
- Explain likely impact and recommend proportionate next steps.
- Identify missing evidence and potential false positives.
- Record model, prompt and tool versions.
- Treat logs, documents, websites and indicators as untrusted input.

**Non-negotiable boundary:** AI is advisory. It cannot grant permissions, alter tenant scope, approve its own recommendations or directly execute arbitrary commands.

**Status:** First backend slice authored: tenant-scoped cases, operator-triggered OpenAI analysis, strict structured output, evidence-reference validation, retry queue and immutable reports. Migration and code verification remain outstanding; no dashboard, automatic finding correlation, or response execution.

## 5. Configurable OniShield Autopilot

Autopilot is intended to let an authorized organization choose how much bounded automation it accepts. It is not an unrestricted autonomous agent.

### User controls

- Master enable/disable switch; default is **OFF**.
- Autonomy mode.
- Maximum permitted risk tier.
- Per-action allow/deny list from a server-owned catalogue.
- Approved device, group and environment scope.
- Time windows, rate limits and concurrency/blast-radius limits.
- Human approval requirements.
- Notifications for decisions and execution.
- Emergency pause and platform kill switch.
- Versioned policy and auditable policy changes.

### Defined modes

| Mode | Behavior |
|---|---|
| Off | No response action executes; detection and investigation may continue. |
| Observe | Simulates proposed actions and records decisions; executes nothing. |
| Low-risk autopilot | Executes only explicitly enabled Tier 0 and individually approved Tier 1 actions. |
| Guarded autopilot | Executes the same allowlisted low-risk actions; Tier 2 actions wait for human approval. |

### Risk boundaries

- **Tier 0 — Observe:** read-only collection, enrichment, investigation and alerting.
- **Tier 1 — Low impact/reversible:** narrowly scoped, reversible actions that have been individually reviewed and tested.
- **Tier 2 — Disruptive:** actions such as account disablement, production endpoint isolation or service interruption; human approval is mandatory.
- **Tier 3 — Destructive/irreversible:** wiping devices, deleting data, destructive remediation or irreversible broad changes; excluded from initial Autopilot and cannot be enabled by a user or AI.

Every action must pass deterministic server-side policy, target identity, evidence freshness, approval, rate-limit, audit and verification checks. Any ambiguity or unavailable safety dependency must fail closed. AI confidence is never authorization.

**Status:** Normative technical contract documented in [AUTOPILOT_CONTRACT.md](AUTOPILOT_CONTRACT.md). Policy storage, configuration UI, simulator and executor are not implemented.

## 6. Backup, recovery and business continuity

OniShield must protect both its own service data and, in later customer-controlled deployments, explicitly selected customer data. Backup is a recovery control, not a promise that compromise cannot happen.

### Target capabilities

- Data-class inventory, scope selection and retention policy.
- Scheduled full and incremental snapshots; database point-in-time recovery where supported.
- Encrypted backups in transit and at rest.
- Versioned, immutable or logically isolated copies.
- A separate backup identity and administrative boundary.
- Integrity manifests, checksums and backup-health monitoring.
- Alerts for missed, delayed, incomplete or failed backups.
- Isolated restore and tenant-safe recovery.
- Recovery approval, audit trail and post-restore validation.
- Recovery drills, key-loss exercises and documented RPO/RTO.

### Ransomware and compromise safeguards

- Production application credentials must not be able to delete backup history.
- At least one copy must be outside the production administrative boundary.
- Replication alone is not considered a backup.
- Restore must begin in a clean isolated environment.
- Potentially compromised credentials must be revoked or rotated.
- Re-enroll connectors rather than blindly trusting restored credentials.
- Autopilot and response dispatch remain paused during recovery until explicitly reviewed.

### Recovery objectives

- **RPO:** maximum tolerable data loss.
- **RTO:** target time to restore service.

Both remain TBD until measured through actual restore drills. Do not advertise zero data loss, instant recovery or guaranteed recovery before evidence exists.

**Status:** Normative contract documented in [BACKUP_AND_RECOVERY.md](BACKUP_AND_RECOVERY.md). Backup scheduling, vault integration, immutable storage configuration, restore tooling and verified recovery are not implemented.

## 7. Identity, access and operator security

Target capabilities:
- Operator invitation and verified email lifecycle.
- Password authentication and secure session management.
- Tenant membership and role-based authorization.
- TOTP MFA and one-use recovery codes.
- Privileged step-up authentication.
- Session inventory, rotation and revocation.
- Persistent login throttling.
- Attributable review and administrative audit.
- Secure browser/mobile token handling and origin/TLS controls.

**Status:** Significant backend foundations, including scrypt password verification, opaque sessions, tenant-bound authorization, TOTP MFA, recovery codes, throttling and invitation/verification/reset workflows, exist in code. They remain unverified. Frontend token pages, live Resend delivery/configuration, remote token transport, TLS/origin controls, secure client storage and other lifecycle hardening remain outstanding. Do not expose the current loopback-bound operator routes remotely.

## 8. Operator applications and notifications

Target experience:
- Desktop security operations console for alerts, evidence, investigations, assets, policy and audit.
- Mobile experience for alert review, notifications, approval and emergency pause.
- Clear status for endpoint health, backup health, Autopilot state and recovery readiness.
- Notifications for important detections, policy changes, approvals, automatic actions, backup failures and recovery events.
- Accessible layouts and explicit failure states.

**Status:** Not implemented as a complete operator product. Mobile is a management surface, not an endpoint agent with privileged response authority in the initial design.

## 9. Reporting, audit and governance

Target capabilities:
- Searchable event, finding, investigation and response history.
- Evidence and source-event references.
- Actor, tenant, policy version, approval and execution identity.
- Append-only or tamper-evident audit records.
- Export controls that enforce recipient and disclosure policy.
- Retention, deletion, legal-hold and privacy controls.
- Backup and recovery audit reporting.

**Status:** Some database audit mechanisms and a TLP policy primitive exist in code. TLP enforcement is not wired into authenticated read/report/export paths; a complete reporting and audit experience is not implemented.

## 10. Optional ecosystem integration

OniShield is a standalone security product. It may integrate with OniVend products where explicitly enabled, for example to support account/security notifications or organization administration. Integration must be opt-in, documented, least-privileged and tenant-safe. OniShield's security controls must remain functional if OniVend is unavailable.

No integration may expose POS, inventory, customer, payment or other business data to security services unless the customer has explicitly authorized the specific data flow and purpose.

**Status:** Product direction only; no production OniVend integration is claimed.

## 11. Delivery sequence and release gates

1. **Foundation verification:** resolve CI account billing restriction; establish reproducible dependency installation; pass migrations, database smoke tests, unit tests, type-check and build.
2. **Event pipeline:** verify authenticated ingestion, deduplication and tenant isolation in a disposable lab.
3. **Deterministic detection:** implement a small set of evidence-linked rules and benign counterexamples.
4. **AI investigation:** implement read-only evidence retrieval and structured, evidence-cited outputs.
5. **Autopilot simulation:** implement policy storage and dry-run decisions; execution remains disabled.
6. **Backup foundation:** select provider, isolate credentials, implement encrypted backups and integrity checks.
7. **Recovery verification:** implement clean-room restore, tenant-safety checks and measured RPO/RTO.
8. **Controlled response:** implement one reversible lab action, approval, verification, rollback and audit.
9. **Bounded Autopilot:** enable only explicitly approved low-risk actions after independent security review.
10. **Operator clients and integrations:** build desktop/mobile operations experience and add integrations based on validated customer needs.
11. **Hardening and competition demonstration:** conduct threat-model review, failure injection, restore drills and repeatable end-to-end demonstrations.

A phase advances only when its exit criteria are demonstrated. Do not start broad production automation before detection, investigation, backup, recovery and policy controls are verified.

## 12. Explicit exclusions and prohibited claims

Until separately designed, implemented and reviewed, OniShield must not claim:
- Complete protection against all cyber threats.
- Zero false positives or guaranteed threat detection.
- Production-ready autonomous response.
- Guaranteed recovery, zero data loss or instant restoration.
- Compliance certification or regulatory approval.
- Safe arbitrary shell execution by an AI agent.
- That a documented feature is already available to customers.

The product must be described according to tested capability, not roadmap ambition.
