# OniShield Product Strategy and Roadmap

**Status:** Strategic proposal — not a claim that all capabilities are implemented  
**Repository:** `ok-igneous/OniShied-AI`  
**Last updated:** 2026-11-13

## 1. Product direction

### Proposed positioning

**OniShield — Autonomous Business Security & Recovery Platform**

OniShield aims to help businesses detect, investigate, contain and recover from cyber incidents without requiring every customer to operate its own cybersecurity department.

The product should combine security monitoring, controlled response, AI-agent oversight, accountability and business recovery in one coherent platform.

This is a product direction, not a claim of current production readiness. Marketing and sales material must distinguish implemented, tested, beta and planned capabilities.

### Core promise

Help a business:

1. **Know** what is happening across its systems.
2. **Protect** systems and data from threats.
3. **Control** what users, services and AI agents are permitted to do.
4. **Recover** business operations when prevention fails.

## 2. Strategic rationale

The market opportunity is not simply to build another AI-powered alerting or blocking tool. Small and medium-sized businesses often lack dedicated security personnel and need security outcomes that are understandable and operationally manageable.

Potential differentiators to validate:

- Risk-based automation with customer-defined limits and human approval options.
- Auditable decisions and traceability for human and automated actions.
- Recovery workflows that are tested, trustworthy and independent of compromised systems.
- Monitoring and governance of AI agents operating with business permissions.
- Plain-language security guidance tied to actionable remediation.

These are hypotheses to validate with customer interviews, pilot deployments and measurable outcomes. They should not be presented as proven market gaps or defensible advantages without evidence.

## 3. Product capability pillars

### 3.1 Threat visibility and detection

Build a reliable security foundation before expanding autonomy.

Planned capability areas:

- Endpoint and host telemetry collection.
- Security event ingestion, normalization and correlation.
- Deterministic detection rules for known behaviors and indicators.
- Threat intelligence matching and controlled intelligence updates.
- Anomaly detection as a supplementary signal, not the sole basis for destructive action.
- AI-assisted investigation, summarization and recommended remediation.
- Evidence preservation and incident timelines.

**Engineering principle:** Detection and response must not depend entirely on an LLM. Deterministic controls should enforce security boundaries; AI may help interpret evidence and recommend actions.

### 3.2 Configurable Autopilot

Autopilot is a policy-controlled response system. It must be explicitly enabled by the customer and configurable by risk level, action type, asset criticality and business context.

Proposed operating modes:

| Mode | Behavior |
|---|---|
| Observe | Detect and report; take no response action |
| Recommend | Propose actions for an administrator |
| Approval required | Prepare an action and wait for authorized approval |
| Guarded autopilot | Automatically execute only pre-approved, reversible, low-risk actions |
| Restricted emergency policy | Execute narrowly defined containment actions under explicit customer policy |

The customer must be able to disable Autopilot and move to a safer mode. Provide an emergency stop and a clear record of who changed the policy and when.

#### Risk-based action policy

Risk scores should be explainable and should consider:

- Confidence and quality of detection evidence.
- Severity and likely impact.
- Asset criticality and business function.
- Scope of affected users, devices and data.
- Reversibility of the proposed action.
- Potential operational disruption.
- Whether a backup or recovery path has been verified.

Suggested action classes:

- **Low risk:** notify, enrich an event, collect additional evidence, or request a scan.
- **Moderate risk:** temporarily restrict a session or apply a reversible control, subject to policy.
- **High risk:** isolate a device, revoke credentials or block a service only under explicit policy and appropriate safeguards.
- **Critical/destructive:** delete data, wipe a device, restore over production data or make irreversible changes. Require explicit human authorization; do not permit unrestricted AI execution.

A numerical risk score alone must never authorize a destructive action. Use policy gates, evidence thresholds, asset context and approval requirements.

#### Autopilot safety requirements

- Least-privilege service identities and scoped permissions.
- Allowlisted action catalogue; no arbitrary shell execution from model output.
- Precondition checks before execution.
- Idempotency and duplicate-action protection.
- Timeouts, rate limits and circuit breakers.
- Dry-run or simulation mode.
- Human approval for high-impact actions.
- Rollback plans for reversible changes.
- Tamper-evident audit events.
- Notifications for actions, failures and policy changes.
- Emergency stop and safe fallback behavior.
- Tests for false positives, model errors, prompt injection and compromised control channels.

### 3.3 Backup, disaster recovery and business continuity

Backup and recovery should be an independent subsystem, not merely a dashboard feature or a capability controlled solely by the potentially compromised endpoint.

Planned capabilities:

- Scheduled and policy-driven backups.
- Versioned backups and retention policies.
- Encryption in transit and at rest.
- Separate backup credentials and administrative boundaries.
- Immutable or write-protected backup copies where supported.
- Backup integrity checks and malware scanning.
- Recovery-point objective (RPO) and recovery-time objective (RTO) configuration.
- Restore previews and isolated test restores.
- File, database, device and service-level recovery where supported.
- Recovery approval workflows and detailed audit logs.
- Backup health monitoring, failure alerts and capacity reporting.
- Documented incident recovery plans.

#### Recovery workflow

1. Detect and scope the incident.
2. Contain affected assets without unnecessarily disrupting unaffected operations.
3. Identify impacted files, databases, credentials and services.
4. Locate a known-good recovery point.
5. Verify backup integrity and assess whether the backup may also be compromised.
6. Restore into an isolated environment where feasible.
7. Validate data integrity and system behavior.
8. Obtain required approval before production cutover.
9. Restore business services in a controlled order.
10. Record the recovery actions, outcomes and remaining risks.

**Non-negotiable:** A backup is not proven useful until restore tests succeed. Never describe a customer as recoverable merely because backup jobs report success.

### 3.4 AI-agent security and accountability

As businesses deploy AI agents with access to email, databases, customer records and internal applications, those agents create a new identity and authorization surface.

Planned controls:

- Inventory registered AI agents and their owners.
- Record agent identity, purpose, model/provider where known, tools and granted permissions.
- Apply least privilege and scoped credentials.
- Monitor tool calls and sensitive resource access where integration permits.
- Detect unusual activity, privilege escalation and policy violations.
- Require approval for sensitive or high-impact operations.
- Revoke or suspend an agent's access when authorized policy conditions are met.
- Preserve an audit trail of agent activity and administrative changes.

#### Accountability record

For each material action, capture where technically available:

- Initiating human, service or agent identity.
- Target resource and operation.
- Permission or policy that allowed the operation.
- Relevant evidence and event identifiers.
- Whether AI suggested the action or a system executed it.
- Human approval identity and timestamp, if applicable.
- Execution result and affected resources.
- Reversal or remediation details.

Do not claim that logs establish legal responsibility or prove intent. They provide technical traceability and evidence for investigation.

### 3.5 Security advisor for SMBs

Provide plain-language explanations that connect a finding to a business consequence and a concrete next step.

Each recommendation should include:

- What was detected.
- Why it matters.
- Affected asset or account.
- Evidence and confidence.
- Recommended action.
- Operational impact and urgency.
- Whether the action is reversible.
- Whether approval is required.
- How to verify remediation.

Avoid alarmist language and unsupported claims that a business is safe or fully protected.

### 3.6 Shared threat intelligence — later-stage capability

A privacy-preserving intelligence-sharing network may eventually help customers benefit from relevant threats observed elsewhere.

This is not an initial release priority. Before building it, resolve:

- Validation and provenance of submitted indicators.
- Poisoning, spam and malicious submissions.
- Confidence scoring, expiry and revocation.
- Customer consent and data minimization.
- Tenant isolation and privacy guarantees.
- False-positive propagation and dispute handling.
- Abuse monitoring and governance of shared feeds.

Start with trusted external feeds and local intelligence management. Consider customer-contributed intelligence only after validation and privacy controls are mature.

## Detection engineering design

- [Finding Lifecycle and Durable Replay Design](FINDING_LIFECYCLE_AND_REPLAY_DESIGN.md) — stable incident identity, evidence history, analyst workflow, and replay architecture.

## 4. Recommended delivery sequence

### Stage 1 — Trustworthy security foundation

Priority: highest.

- Complete reliable endpoint/host telemetry collection.
- Harden event ingestion, normalization and tenant isolation.
- Build deterministic detection and correlation.
- Integrate threat intelligence with provenance and review.
- Deliver AI-assisted investigation with evidence-linked explanations.
- Implement a controlled response catalogue.
- Establish auditability, operational monitoring and security testing.

**Exit criteria:**
- Supported telemetry sources are documented.
- Detection tests include true positives, false positives and evasive cases.
- Tenant isolation is tested.
- Response actions are permission-scoped and audited.
- AI output cannot directly bypass deterministic policy enforcement.
- Pilot users can understand and investigate alerts.

### Stage 2 — Safe autonomy and recovery

- Add Autopilot modes and risk/action policies.
- Implement approval queues, emergency stop and safe fallback.
- Add simulation/dry-run and reversible-action workflows.
- Build independent backup architecture and retention controls.
- Implement integrity verification and isolated restore testing.
- Add recovery runbooks and customer-facing recovery status.

**Exit criteria:**
- Customers can disable automation reliably.
- High-impact actions require appropriate authorization.
- Policy changes and automated actions are auditable.
- Backup credentials and control paths are separated from protected endpoints.
- Restore drills demonstrate documented RPO/RTO performance.
- Recovery is tested against ransomware and compromised-credential scenarios.

### Stage 3 — AI-agent protection and governance

- Build agent inventory and ownership mapping.
- Integrate with selected AI-agent platforms and tool gateways.
- Monitor permissions, tool use and sensitive data access.
- Add approval and revocation workflows.
- Extend accountability records to agent actions.
- Validate demand with SMB customers before broadening integrations.

**Exit criteria:**
- At least one supported agent integration produces reliable, attributable activity records.
- Permission boundaries are enforced outside the model.
- Revocation and approval workflows are tested.
- Customers can explain which agents have access to which resources.

### Stage 4 — Intelligence network and advanced services

- Evaluate privacy-preserving customer intelligence sharing.
- Add validated contribution and reputation mechanisms.
- Improve cross-customer detection using privacy-safe signals.
- Expand integrations and managed security advisory capabilities.

Proceed only if customer demand, data quality and privacy requirements justify the cost.

## 5. Architecture and security principles

1. **Policy before autonomy:** AI proposes; deterministic policy and authorization controls decide what may execute.
2. **Least privilege:** every collector, agent and response worker receives only the permissions it needs.
3. **Tenant isolation:** customer data, events, credentials and backups must not cross tenant boundaries.
4. **Independent recovery:** backup administration and recovery credentials must remain protected if an endpoint or primary account is compromised.
5. **Evidence-linked AI:** investigation conclusions should reference underlying events and clearly distinguish fact from inference.
6. **Fail safely:** when model, network or policy services are unavailable, do not silently widen permissions or perform destructive actions.
7. **Auditable changes:** record policy edits, approvals, executions, failures and reversals.
8. **Data minimization:** collect only what is needed, define retention, and protect sensitive telemetry.
9. **Secure updates:** sign releases, verify integrity and support controlled rollback.
10. **No absolute security claims:** communicate supported coverage, limitations and residual risk.

## 6. Commercial strategy and validation

Initial target: SMBs that depend on Windows/Linux endpoints and business-critical files or databases but lack dedicated security operations staff.

Potential initial pilot segments include pharmacies, retail businesses, professional services and other small organizations with meaningful operational dependence on digital systems. Select one segment for the first pilots rather than attempting to serve every industry simultaneously.

Validate these assumptions before scaling:

- Which incidents cause customers the greatest financial or operational harm?
- What devices, applications and data must be protected first?
- Who has authority to approve automated actions?
- What recovery time can the business tolerate?
- What security budget is realistically available?
- Which integrations are mandatory for adoption?
- Will customers pay for monitoring, response, recovery, or a combined service?

Measure outcomes such as:

- Detection precision and false-positive rate.
- Time to detect and time to contain.
- Percentage of response actions completed safely.
- Rate of actions requiring rollback.
- Backup job success and verified restore success.
- Measured RPO/RTO in recovery drills.
- Time required for an owner to understand and act on an alert.
- Pilot conversion and customer retention.

Do not use unverified market statistics or competitor funding figures as the basis for product decisions. Validate market claims against primary sources and customer research.

## 7. Explicit non-goals for the early releases

- Do not build a global threat-sharing network before local detection quality and privacy controls are mature.
- Do not allow unrestricted AI shell access or arbitrary model-generated commands.
- Do not automatically delete, wipe or overwrite customer data.
- Do not promise complete protection or guaranteed recovery.
- Do not build broad AI governance features without a concrete customer workflow and integration.
- Do not expand to many industries before proving value in a focused pilot segment.

## 8. Current implementation status discipline

This document defines strategic direction and proposed work. It does not certify that the listed capabilities are implemented.

For every capability, maintain a separate implementation status:

- **Planned:** documented but not implemented.
- **In progress:** active development; not ready for customer reliance.
- **Implemented:** code exists; not necessarily production validated.
- **Tested:** defined tests passed in a documented environment.
- **Pilot:** used by selected customers under stated limitations.
- **Production-ready:** security, reliability, operational and recovery requirements have been reviewed and accepted.

Before public launch, maintain a capability matrix with supported operating systems, data sources, response actions, known limitations and test evidence.

## 9. Immediate next actions

1. Audit the current repository and map existing code to the capability pillars above.
2. Produce an implementation-status matrix: implemented, partial, missing and unverified.
3. Identify the smallest supported endpoint telemetry and detection path for a working pilot.
4. Define the response action catalogue and permission model before enabling Autopilot.
5. Write the backup threat model and recovery requirements before selecting storage architecture.
6. Interview prospective SMB customers and run a narrow pilot.
7. Convert each approved workstream into small, testable GitHub issues.

---

**Decision:** Keep OniShield's core mission focused on business security. Treat configurable autonomy, independent recovery, and AI-agent accountability as connected product capabilities, delivered in stages and validated with evidence.
