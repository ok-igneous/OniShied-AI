# OniShield AI

**Autonomous Cybersecurity Platform — early-stage development.**

OniShield AI is being developed to help individuals, businesses and organizations collect authorized security telemetry, detect suspicious activity, investigate evidence, apply policy-controlled responses, and recover safely after incidents.

> **Project status:** Foundation and design stage. Some backend components exist in the repository but are not yet verified by a successful CI run. This repository does not contain a production-ready endpoint protection agent or a production-ready autonomous response system. Feature descriptions are targets unless explicitly marked implemented and verified.

## Product direction

OniShield is designed as a hybrid platform:
- Cloud control plane for identity, tenant administration, policy, coordination and reporting.
- Local or customer-controlled components for telemetry collection and selected response operations.
- Desktop operations experience and mobile alert/review/approval experience.
- Standalone operation, with optional, explicitly authorized OniVend ecosystem integration.

Its intended workflow is:

`Telemetry → Validate → Normalize → Detect → Investigate → Policy check → Approval (when required) → Execute → Verify → Audit`

AI investigation is advisory. Deterministic server-side policy—not model output—must authorize every response action.

## Operator investigation console

The early operator investigation workspace is available at `/operator` when the API server is running. It requires an existing operator session token and supports case review, creating cases from supplied finding IDs, associating additional findings, analyst notes, finding-status transitions, AI analysis requests, job status, and immutable report history. Mutations require the server-enforced role and recent step-up checks. It is not a production SOC dashboard and has not yet been browser-tested.

## Product features

The full capability register, including Autopilot, Backup and Recovery, endpoint protection, threat intelligence, AI investigation, identity, reporting and planned integrations, is maintained in [Feature Catalogue](docs/FEATURE_CATALOG.md).

Key design contracts:
- [Configurable Autopilot](docs/AUTOPILOT_CONTRACT.md) — tenant opt-in, OFF by default, bounded modes, risk tiers, approvals and emergency pause.
- [Backup and Disaster Recovery](docs/BACKUP_AND_RECOVERY.md) — encrypted and isolated backups, integrity checks, clean-room restore and recovery testing.

These are designs, not implemented customer-facing features.

## Initial demonstrator

The first demonstrator should use synthetic events in a controlled lab:
1. Ingest an authenticated synthetic security event.
2. Preserve provenance and normalize the event.
3. Detect a documented suspicious pattern deterministically.
4. Present evidence-linked investigation cases and advisory AI analysis (implementation exists; verification is outstanding).
5. Show a policy decision and approval boundary.
6. Execute a reversible lab action only after its implementation and tests pass.
7. Verify and audit the outcome.

A repeatable end-to-end workflow is more valuable than a broad dashboard mock-up or an unbounded autonomous agent.

## Safety and trust principles

- Authorized environments only.
- Least privilege and tenant isolation.
- Evidence before claims; facts, inferences and unknowns remain distinct.
- AI is advisory and cannot authorize or execute arbitrary actions.
- Autopilot is opt-in and default OFF; Tier 2 requires human approval and Tier 3 is excluded from the initial product.
- Backups are isolated from production administrative credentials and are not considered healthy until restore testing succeeds.
- Human override, emergency pause and auditable decisions.
- Secrets and customer data must not be committed to this repository.

## Repository map

- `docs/FEATURE_CATALOG.md` — product-wide feature inventory and implementation status.
- `docs/INVESTIGATION_CASES_IMPLEMENTATION.md` — investigation cases, AI analysis worker, evidence validation, and limitations.
- `docs/PRODUCT_VISION.md` — mission, target users, initial scope and demonstrator.
- `docs/SYSTEM_ARCHITECTURE.md` — proposed components and trust boundaries.
- `docs/SECURITY_MODEL.md` — threat model and security requirements.
- `docs/THREAT_INTELLIGENCE_CONTRACT.md` — threat-intelligence design.
- `docs/THREAT_INTELLIGENCE_REVIEW.md` — reviewer authorization and audit controls.
- `docs/OPERATOR_IDENTITY.md` — operator authentication and authorization.
- `docs/AUTOPILOT_CONTRACT.md` — configurable automation contract.
- `docs/BACKUP_AND_RECOVERY.md` — backup and recovery contract.
- `docs/DEVELOPMENT_ROADMAP.md` — staged implementation plan.
- `docs/IMPLEMENTATION_STATUS.md` — implemented code, unverified work and blockers.
- `docs/REPOSITORY_CAPABILITY_AUDIT.md` — static repository audit, capability matrix, CI evidence and prioritized engineering gaps.
- `docs/DEMO_RUNBOOK.md` — controlled demonstration plan.
- `docs/TEAM_ROLES.md` — contributor responsibilities.
- `CONTRIBUTING.md` — development workflow.
- `SECURITY.md` — vulnerability reporting and safe research boundaries.

## Engineering constraints

- Follow [Code Standards](docs/CODE_STANDARDS.md), including the hard 500-line source-file ceiling.
- Follow [Database Security](docs/DATABASE_SECURITY.md) for tenant isolation, least-privilege roles and production launch gates.
- Follow [Repository Governance](docs/REPOSITORY_GOVERNANCE.md) for CI and contribution controls.
- Use [Local Lab](docs/LOCAL_LAB.md) only with disposable test data.
- Review [Public Repository Review](docs/PUBLIC_REPOSITORY_REVIEW.md) before adding sensitive implementation details.

## Verification and limitations

GitHub Actions has previously failed before runner allocation because of an account billing restriction. Until a successful CI run is observed, migrations, RLS tests, unit tests, type-checking and build are not claimed as passing. Making the repository public does not resolve an account-level billing restriction.

Do not describe OniShield as production-ready, fully protective, or autonomously responding to real threats.

## License

All rights reserved unless a license is added by the project owner. Repository visibility does not grant permission to reuse, distribute or deploy the code.
