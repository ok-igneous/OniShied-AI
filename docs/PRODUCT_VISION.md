# Product Vision

## Mission

Help individuals, businesses and organizations understand security events, investigate threats using evidence, respond under explicit policy, and recover safely after incidents.

## Product category

OniShield AI is intended to be an **Autonomous Cybersecurity Platform**: a hybrid security platform combining authorized telemetry, deterministic detection, evidence-linked AI investigation, policy-governed response, and tested backup/recovery capabilities.

"Autonomous" describes the long-term goal of bounded, user-configured automation. It does not mean unrestricted AI authority. The platform must fail closed when policy, identity, evidence, audit or verification controls are unavailable.

## Intended users

- Individuals who need understandable security visibility and practical protection.
- Small and medium-sized businesses without a large in-house security operations team.
- Organizations that need consistent endpoint/account security monitoring and auditable response.
- Security operators who want investigation assistance, policy controls, recovery readiness and repeatable incident workflows.

These are target segments, not validated paying customers. Customer discovery is required before committing to a broad feature set.

## Deployment and ecosystem direction

- Hybrid deployment: cloud control plane plus local/customer-controlled components.
- Windows and Linux are the initial desktop endpoint targets.
- Desktop is the primary operational experience; mobile initially supports alerts, review, approvals and administration, not privileged endpoint response.
- OniShield must work as a standalone product. Optional OniVend integration must be explicit, least-privileged and tenant-safe.

## Core problem

Many users and organizations lack the people, time and tooling to interpret security alerts consistently, respond safely and recover from incidents. A useful product must reduce investigation effort without creating new risk through false positives, opaque AI decisions, unsafe automation or untested backups.

## Product promise

OniShield AI aims to provide:
- Authorized endpoint and account telemetry.
- Prioritized, explainable security alerts.
- Deterministic detections linked to source evidence.
- AI-assisted investigations that distinguish facts, hypotheses and unknowns.
- Proportionate response recommendations and policy-controlled execution.
- Configurable Autopilot with risk ceilings, explicit opt-in, approvals and emergency pause.
- Encrypted, isolated backup and tested recovery workflows.
- Tenant-scoped identity, access controls and audit history.
- Desktop and mobile operator experiences.

These are product goals, not claims of current availability. See [Feature Catalogue](FEATURE_CATALOG.md) and [Implementation Status](IMPLEMENTATION_STATUS.md).

## Initial scope

The first milestone remains intentionally narrow: one controlled telemetry source, a small set of explainable detections, an evidence-linked investigation workflow, and one reversible lab-only response action. Backup and Autopilot are designed as later gated capabilities; they must not delay proving the core event-to-evidence workflow.

## Initial demonstrator acceptance criteria

A reviewer must be able to:
1. Generate or replay a documented synthetic security event.
2. See the original event and its normalized representation.
3. See why a detection fired, including the rule or signals involved.
4. Review an AI investigation that cites event identifiers and separates facts from hypotheses.
5. See severity, confidence and unresolved questions.
6. Approve or reject a safe containment action.
7. Observe the action result and a complete audit record.
8. Replay the scenario and obtain a consistent deterministic detection result.

The demo must include benign events and false-positive handling, not only a successful attack simulation.

## Non-goals for the first demonstrator

- Unrestricted autonomous remediation.
- Offensive security operations or exploitation of third-party systems.
- Claims of guaranteed protection or complete threat coverage.
- Production endpoint agent deployment across arbitrary customer devices.
- Compliance certification claims.
- Autonomous deletion, wiping, account lockout or network-wide isolation.
- Guaranteed backup recovery or unmeasured RPO/RTO commitments.

## Product principles

Evidence first; least privilege; safe defaults; explainable decisions; human override; tenant isolation; privacy by design; measured recovery; honest capability claims.
