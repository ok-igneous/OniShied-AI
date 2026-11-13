# OniShield AI

**AI-assisted cybersecurity operations for businesses and organizations.**

OniShield AI is an early-stage cybersecurity product intended to help organizations detect, investigate, explain, and respond to security threats across supported desktop and mobile environments.

> **Project status:** Planning and foundation setup. This repository does not yet contain a production-ready security agent. All capabilities described here are goals until implemented, tested, and documented.

## Product direction

OniShield AI is designed around a bounded security-operation workflow:

1. Collect authorized security telemetry from a controlled environment.
2. Detect suspicious events using deterministic rules and supporting signals.
3. Let AI investigate and correlate evidence; AI output must be traceable to source events.
4. Assign severity and explain the reasoning, confidence, and uncertainty.
5. Recommend a proportionate response.
6. Execute only actions permitted by explicit policy and the configured approval level.
7. Record the event, evidence, decision, approval, action, and outcome in an auditable log.

The product is intended for both businesses and other organizations, with desktop and mobile access and a hybrid deployment model.

## Safety and trust principles

- **Authorized environments only:** no scanning, testing, or intervention against systems without explicit authorization.
- **Least privilege:** agents and integrations receive only the permissions needed for their assigned tasks.
- **Bounded autonomy:** low-risk, reversible actions may be automated under policy; destructive, disruptive, or high-impact actions require explicit human approval.
- **Evidence before claims:** investigations must distinguish observed facts, inferences, confidence, and unknowns.
- **Human override:** operators can pause automation, revoke credentials, and review action history.
- **Auditability:** security-relevant decisions and response actions must be attributable and tamper-evident.
- **Secure by default:** secrets are never committed; customer data is isolated and access-controlled.

## Initial demonstrator

The first demonstrator should use synthetic events or a deliberately controlled lab:

- ingest a known suspicious event;
- preserve the raw event and its provenance;
- detect and classify it;
- produce an evidence-backed investigation;
- recommend a safe containment action;
- require approval for any disruptive action;
- execute the approved action in the lab;
- show the complete audit trail.

A successful demo is a reproducible end-to-end workflow, not a dashboard mock-up or an unbounded autonomous agent.

## Repository map

- `docs/PRODUCT_VISION.md` — target users, problem, product scope, and demo definition.
- `docs/SYSTEM_ARCHITECTURE.md` — proposed components and trust boundaries.
- `docs/SECURITY_MODEL.md` — threat model, safety controls, and security requirements.
- `docs/THREAT_INTELLIGENCE_CONTRACT.md` — threat intelligence schema, normalization, matching, and service boundaries.
- `docs/THREAT_INTELLIGENCE_REVIEW.md` — reviewer authorization, status transitions, and append-only audit controls.
- `docs/OPERATOR_IDENTITY.md` — operator authentication service, isolated database role, authorization matrix, and release gates.
- `docs/DEVELOPMENT_ROADMAP.md` — staged implementation plan.
- `docs/TEAM_ROLES.md` — founding team responsibilities and working agreements.
- `CONTRIBUTING.md` — development workflow and contribution rules.
- `SECURITY.md` — vulnerability reporting and safe research boundaries.

## Current status

This repository is the project foundation. Architecture and implementation choices must be validated through small prototypes and documented decisions before being treated as final. No production deployment, customer protection, or security certification is claimed.

## Working principles

1. Build a narrow, testable vertical slice before expanding scope.
2. Prefer deterministic controls for enforcement; use AI for analysis and explanation, not unchecked authority.
3. Test in isolated labs with synthetic data first.
4. Require code review for changes to detection, permissions, response, and data handling.
5. Document limitations and failure modes honestly.

## License

All rights reserved unless a license is added by the project owner. No permission to reuse, distribute, or deploy this code is granted by this repository's visibility or contents.

## Engineering and database standards

- [Code standards](docs/CODE_STANDARDS.md): mandatory modular design and a hard maximum of 500 lines per source file.
- [Database security](docs/DATABASE_SECURITY.md): least-privilege roles, PostgreSQL tenant isolation, transaction safety, encryption, backup, and production launch gates.
- [Repository governance](docs/REPOSITORY_GOVERNANCE.md): GitHub Actions, pull-request workflow, branch-protection status, and contributor controls.
- [Local lab](docs/LOCAL_LAB.md): PostgreSQL setup, RLS smoke test, and synthetic event replay.
- [Implementation status](docs/IMPLEMENTATION_STATUS.md): implemented controls, unverified work, and current blockers.
- [Public repository review](docs/PUBLIC_REPOSITORY_REVIEW.md): current visibility risks and the limits of the history review.
