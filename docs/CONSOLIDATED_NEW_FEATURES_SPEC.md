# OniShield AI — Consolidated New Features Specification

**Status:** Accepted product and architecture direction; implementation varies by feature.  
**Last updated:** 2026-11-14  
**Authority:** This document consolidates the product decisions made for the next OniShield development stages. It does not override the narrower security contracts linked below.  
**Product maturity:** Early-stage foundation. Not production-ready.

## 1. Product principle

OniShield must own its security decisions, evidence model, policy enforcement, and recovery process. External AI models are optional reasoning services—not the security control plane, not the source of authorization, and not a runtime dependency for native protection.

The platform has two cooperating intelligence paths:

1. **Native intelligence:** deterministic, testable, tenant-scoped security logic that operates without an AI provider.
2. **AI-assisted intelligence:** bounded model-assisted investigation, explanation, enrichment, and candidate generation.

Both paths must preserve evidence provenance, tenant isolation, auditability, and explicit authorization boundaries.

## 2. Native autonomous intelligence

### 2.1 Required capabilities

The native path is intended to provide:
- Canonical event ingestion, validation, normalization, deduplication, and provenance.
- Deterministic signatures and versioned detection rules.
- Behavioral and statistical baselines where sufficient data and evaluation justify them.
- Event correlation across time, identities, hosts, and other explicitly mapped entities.
- Threat-indicator matching against validated, approved intelligence.
- Risk scoring with separate severity, confidence, and evidence-quality dimensions.
- Finding lifecycle, evidence references, suppression, triage, and audit.
- Policy evaluation and narrowly scoped response execution after the response controls are implemented.
- Continued operation when AI providers are unavailable or an AI credit allowance is exhausted.

### 2.2 Detection quality requirements

- Every finding must identify the rule and version that produced it.
- Findings must link to source event references and explain the match conditions.
- Missing or ambiguous evidence must reduce confidence or prevent a match; it must not be silently invented.
- Detection windows, query limits, and evaluation failures must be explicit. Truncated evidence must never be treated as a complete successful evaluation.
- Rules require malicious and benign fixtures, regression tests, false-positive measurement, and documented coverage limitations.
- Statistical anomalies are signals for investigation, not proof of compromise.
- No single risk score or model confidence value grants permission to execute a response.

### 2.3 Operating modes

| Mode | Native protection | AI assistance |
|---|---|---|
| AI + Native | Active | Available within configured budget and policy |
| Native-only | Active | Disabled or unavailable |
| Restricted/degraded | Safe native functions continue; unsafe or unavailable dependencies are reported | Disabled, limited, or queued |

The system must degrade safely. Exhausting AI credits, losing a provider connection, or receiving malformed model output must not disable event ingestion, deterministic detection, audit, or already-approved native knowledge.

**Status:** Event ingestion and initial detection code exist but remain unverified. Full behavioral analytics, correlation coverage, risk engine, and end-to-end native autonomous protection remain incomplete.

## 3. Multi-model AI and provider gateway

### 3.1 Provider abstraction

Implement a provider-neutral gateway so application services do not depend directly on one model vendor's SDK or response format.

The gateway should own:
- Provider/model registry and capability metadata.
- Task-based model routing.
- Structured input/output validation.
- Timeout, bounded retry, rate-limit, and provider-failure handling.
- Per-tenant usage attribution and cost accounting.
- Redaction/minimization rules before external submission.
- Model, provider, prompt-contract, and policy version logging.
- Evaluation fixtures and quality/cost comparisons.
- Fallback behavior that never elevates permissions.

### 3.2 Task routing

Use the least expensive model that meets the measured quality requirement:
- Routine classification, extraction, and summarization: lightweight model.
- Evidence-based incident investigation: stronger reasoning model where needed.
- Complex multi-event or ambiguous cases: escalation to a higher-capability model only when policy and budget permit.
- Provider outage or budget exhaustion: native-only processing and a clear degraded status.

Exact model IDs and prices are intentionally not fixed in this specification. Select them only after checking current official provider catalogues, regional availability, data-processing terms, and measured evaluation results. Do not hard-code an unverified model name or price.

### 3.3 AI trust boundary

- AI receives only the minimum authorized evidence needed for a task.
- Customer logs, files, URLs, indicators, and model outputs are untrusted data.
- AI output must conform to a strict schema and cite evidence references for factual claims.
- AI may recommend or submit a learning candidate; it cannot approve or activate it.
- AI cannot change tenant scope, access control, Autopilot policy, risk ceilings, secrets, or provider billing limits.
- AI cannot execute arbitrary shell commands, SQL, network requests, or unrestricted tools.
- Provider failure, malformed output, prompt injection, and refusal must be handled as ordinary failure states.

**Status:** Investigation contract/design exists; provider gateway, routing, and investigation service are not yet implemented.

## 4. Adaptive intelligence learning

OniShield should improve from validated evidence and outcomes without allowing a model to rewrite production behavior.

### 4.1 Approved learning sources

- AI investigation candidates.
- Confirmed incident outcomes and later corrections.
- Authenticated operator feedback and false-positive dispositions.
- Licensed, approved external threat intelligence.
- Authorized synthetic lab tests and replay results.

### 4.2 Knowledge artifact types

- Indicator candidates.
- Declarative detection-rule proposals.
- Behavioral pattern and correlation candidates.
- Enrichment mappings.
- Investigation playbook suggestions.
- Benign-pattern and suppression candidates.

### 4.3 Mandatory lifecycle

Acquisition → schema/provenance validation → tenant-scoped quarantine → deduplication and conflict analysis → historical and synthetic replay → human review → immutable versioned publication → monitoring → expiry/revocation/rollback.

Rules must be declarative and bounded, not arbitrary executable code or arbitrary SQL. Every active artifact must have provenance, version, integrity digest, evidence lineage, expiry where applicable, and a rollback path.

### 4.4 Human and privacy controls

- AI cannot approve its own candidates.
- Human approval is mandatory for initial publication.
- Tenant-derived knowledge remains private to that tenant by default.
- Cross-customer sharing is disabled by default.
- Any future sharing requires explicit opt-in, contractual rights, data minimization, re-identification risk review, licensing review, a separate global namespace, authorization, audit, and revocation.
- Ordinary API use does not permanently train or fine-tune a provider model.
- Initial learning means knowledge learning, not model-weight training. Fine-tuning is future research only after consent, data-rights, privacy, evaluation, and rollback safeguards.

**Detailed normative contract:** [Adaptive Intelligence Learning](ADAPTIVE_INTELLIGENCE_LEARNING.md).  
**Status:** Design documented; no candidate quarantine/review/replay/publishing pipeline is implemented.

## 5. Configurable Autopilot

Autopilot is a tenant-controlled policy system for bounded response—not an unrestricted AI agent.

### 5.1 Customer controls

- Master enable/disable; default OFF.
- Observe/dry-run and bounded automation modes.
- Maximum permitted risk tier.
- Per-action allow/deny list from a server-owned action registry.
- Device, asset, group, and environment scope.
- Time windows, concurrency, rate, and blast-radius limits.
- Required approver roles and approval expiry.
- Notifications, audit history, and policy version.
- Emergency pause and platform-level kill switch.

### 5.2 Risk tiers

| Tier | Meaning | Initial policy |
|---|---|---|
| Tier 0 | Read-only observation, enrichment, investigation, alerting | May run without response authorization |
| Tier 1 | Low-impact, narrowly scoped, reversible action | May run only when explicitly allowlisted and enabled |
| Tier 2 | Disruptive action such as account/session/device containment | Human approval required |
| Tier 3 | Destructive, broad, or difficult-to-reverse action | Excluded from initial release; explicit human authorization and separate design required before future consideration |

### 5.3 Execution safeguards

- Server-side policy evaluation; never trust client or model-supplied authorization.
- Precondition and target-scope validation immediately before execution.
- Dry-run preview before enabling execution.
- Idempotency keys, bounded retries, concurrency limits, and execution deadlines.
- Independent outcome verification and evidence capture.
- Rollback/compensation where technically possible.
- Immutable decision and execution audit.
- Emergency pause that blocks new work and safely handles in-flight work.
- Stale policy, missing evidence, provider failure, and authorization ambiguity must fail closed.
- Numerical confidence or risk scores alone never authorize destructive actions.

**Detailed normative contract:** [Autopilot Contract](AUTOPILOT_CONTRACT.md).  
**Status:** Design contract only; policy schema, UI, approval workflow, action registry, and executor are not implemented.

## 6. Backup and disaster recovery

Recovery is a security capability. It must be designed before production customer data is accepted.

### 6.1 Backup scope

Inventory and classify:
- Tenant business/security data and event history.
- Configuration, policies, approved knowledge packages, and audit records.
- Identity and membership metadata, excluding recoverable plaintext credentials or session secrets.
- Encryption/key-management metadata and documented key recovery procedures.
- Application configuration and deployment artefacts needed to rebuild service.

Define exclusions explicitly, including ephemeral caches, transient queues, and secrets that must be reissued rather than restored.

### 6.2 Backup architecture

- Encrypted scheduled snapshots.
- Point-in-time recovery/WAL where supported by the database platform.
- Separate backup identity and isolated destination/account.
- Immutable or version-locked copies with retention and deletion controls.
- Integrity manifests, checksums, backup inventory, and success/failure alerts.
- Key separation, rotation, escrow/recovery policy, and tested access procedures.
- Tenant-aware retention and deletion policy.
- Documented recovery dependencies and clean-room restore instructions.

A backup stored only beside the production system is not a disaster-recovery strategy.

### 6.3 Restore and drills

- Restore into an isolated clean environment before any production cutover.
- Verify database integrity, schema compatibility, tenant boundaries, event lineage, audit continuity, and active knowledge package integrity.
- Re-enroll or rotate credentials and device secrets where safe restoration is not possible.
- Require explicit operator authorization for tenant or full-environment restore.
- Record restore actor, reason, source snapshot, integrity result, duration, and outcome.
- Run scheduled restore drills and key-loss exercises.
- Measure and publish actual Recovery Point Objective (RPO) and Recovery Time Objective (RTO); do not promise targets before drills demonstrate them.

**Detailed normative contract:** [Backup and Recovery](BACKUP_AND_RECOVERY.md).  
**Status:** Design contract only; no scheduler, backup vault integration, PITR configuration, restore tooling, or verified recovery capability is implemented.

## 7. AI subscription allowance and paid credits

### 7.1 Commercial decision

OniShield centrally pays AI providers and sells customers an allowance as part of their OniShield subscription. Customers may purchase additional AI credits when their included allowance is exhausted.

This is the selected default commercial model. Bring-your-own-key (BYOK) may be considered later for enterprise customers, but is not the initial default.

### 7.2 Required billing controls

- A tenant-scoped AI usage ledger with immutable usage entries.
- Subscription allowance, billing period, reset time, and entitlement version.
- Separate included allowance and purchased-credit balances.
- Provider/model, task type, token or provider usage units, estimated/settled cost, and request outcome.
- Idempotent usage recording and payment reconciliation.
- Verified payment before purchased credits become spendable.
- Per-tenant and per-user spending caps, rate limits, and abuse detection.
- Configurable alerts at usage thresholds and before exhaustion.
- Model routing based on task need, allowance, and margin controls.
- Cost, revenue, and gross-margin monitoring by tenant, plan, provider, and model.
- Refund, chargeback, expiry, and credit-adjustment audit rules.

### 7.3 Exhaustion behavior

When included allowance and paid credits are exhausted:
- Stop new billable AI requests or require explicit top-up/authorized BYOK.
- Do not incur hidden provider spend on the tenant's behalf.
- Keep native ingestion, deterministic detection, local policy checks, audit, and recovery available.
- Clearly show the tenant that AI assistance is limited and why.
- Never silently downgrade privacy, bypass budgets, or disable core protection.

No subscription prices, token-to-credit exchange rates, or provider costs are fixed here. Those require current provider pricing, payment fees, taxes, currency treatment, and unit-economics testing.

**Status:** Commercial and technical direction accepted; allowance ledger, credit wallet, payment integration, metering, and billing UI are not implemented.

## 8. Shared threat intelligence

Shared intelligence can improve coverage, but it creates privacy, licensing, poisoning, and tenant-boundary risks.

Initial product behavior:
- Tenant intelligence is isolated by default.
- External feeds require source validation, licensing/redistribution review, provenance, expiry, and quality controls.
- Internal matching uses only explicitly mapped event fields and approved indicator states.
- TLP/handling labels inform disclosure policy but do not replace authorization.
- No raw tenant events or customer-specific investigation text are shared across tenants by default.
- No global indicator or shared knowledge namespace is enabled merely by using a null tenant identifier.

Future shared intelligence requires a separate global namespace, explicit sharing authorization, de-identification and re-identification assessment, reviewer governance, abuse/poisoning controls, revocation, and auditable distribution.

**Status:** Partial internal indicator normalization/matching and reviewer controls exist in code but are unverified and not wired into ingestion. Automatic feed ingestion and cross-tenant sharing are not implemented.

## 9. Intelligence and operations dashboard

The dashboard should expose operational truth, not vanity metrics.

### 9.1 Required views

- Event ingestion health, lag, rejected events, duplicates, and pending evaluations.
- Active detections and findings with severity, confidence, evidence, rule version, and status.
- Detection performance, false-positive rate, replay coverage, and known blind spots.
- Native versus AI contribution, with the distinction clearly defined.
- AI provider availability, latency, failures, task volume, model usage, and spend.
- Included allowance, purchased credits, current consumption, and reset date.
- Learning candidates by source/status, review backlog, active knowledge versions, expiry, and rollback history.
- Autopilot mode, policy version, enabled actions, approvals, execution outcomes, and emergency-pause status.
- Backup freshness, last successful integrity check, restore-drill date, and measured RPO/RTO.
- Tenant and connector health, stale telemetry, and audit events.

### 9.2 Metric integrity

- Display only measured values with a defined time window and denominator.
- Show unavailable/unknown separately from zero.
- Do not fabricate detection rates, prevented attacks, cost savings, or recovery readiness.
- Record metric definition and source query/version.
- Restrict tenant dashboards to tenant-authorized data; platform-wide views require privileged operator authorization.

**Status:** Not implemented as a complete operator dashboard.

## 10. Cross-feature security invariants

These requirements apply across every feature:
1. Tenant identity and authorization are derived from authenticated server-side context.
2. AI providers and model outputs are untrusted dependencies.
3. Native protection remains available without AI.
4. No AI output directly changes permissions, production rules, Autopilot policy, or response authorization.
5. All material decisions and state transitions are attributable and auditable.
6. Evidence and learned knowledge retain provenance and version lineage.
7. Failures are explicit; no silent truncation, silent authorization fallback, or false success.
8. External data sharing is disabled unless explicitly authorized and governed.
9. Destructive actions require human authorization and separate safeguards.
10. Recovery must be independently tested, not inferred from successful backup jobs.

## 11. Dependency-ordered implementation plan

Do not implement attractive downstream features ahead of their security dependencies.

| Order | Workstream | Exit evidence |
|---|---|---|
| 1 | Canonical event pipeline, provenance, replay, durable pending-work handling | Repeatable ingestion/replay, tenant isolation, bounded load behavior |
| 2 | Deterministic detection, evidence correlation, severity/confidence, false-positive fixtures | Reproducible findings with tests and measured limitations |
| 3 | Threat-intelligence integration into event/detection flow | Approved indicators match only mapped fields; expiry and tenant boundaries tested |
| 4 | Read-only investigation contract and AI provider gateway | Schema-validated, evidence-linked results; budgets, timeouts, outage fallback |
| 5 | Candidate quarantine, human review, replay, versioned learning publication | AI cannot self-approve; rollback and tenant isolation demonstrated |
| 6 | Policy engine, approvals, Autopilot dry-run | Fail-closed policy simulation, audit, pause, and scope checks |
| 7 | One reversible lab-only response adapter | Verified preconditions, idempotency, outcome checks, rollback/compensation |
| 8 | Backup/PITR, isolated restore, recovery drills | Measured RPO/RTO and verified tenant-safe restore |
| 9 | AI usage ledger, allowance/credit wallet, payment reconciliation | Correct metering, idempotent credits, spend caps, native-only exhaustion behavior |
| 10 | Operator dashboard and reporting | Metrics trace to tested queries and enforce tenant authorization |
| 11 | Opt-in shared intelligence | Separate global namespace, consent, licensing, privacy, poisoning and revocation controls |

The provider gateway and AI metering can be developed as supporting services in parallel with the native foundation, but neither may become a dependency for native protection. Backup design begins early; production rollout is blocked until restore drills pass.

## 12. Release and claim discipline

A feature may be described as:
- **Design documented** when its contract and acceptance criteria exist.
- **Implemented — unverified** when code exists but required tests/runtime evidence have not passed.
- **Verified in lab** only after repeatable tests and recorded evidence pass in a controlled environment.
- **Production-ready** only after security review, operational monitoring, restore testing, deployment hardening, and documented support procedures.

A GitHub commit is not proof of runtime correctness. A passing unit test is not proof of end-to-end security. A successful backup job is not proof of recoverability. A model response is not proof that an incident is real.

Until the required release gates pass, OniShield must not be marketed as production-ready, fully protective, self-learning, or autonomously responding to threats.
