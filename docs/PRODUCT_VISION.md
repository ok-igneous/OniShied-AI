# Product Vision

## Mission

Help businesses and organizations understand security events and respond to threats through evidence-backed AI assistance and controlled automation.

## Intended users

- Small and medium-sized businesses without a large in-house security operations team.
- Organizations that need a clearer view of endpoint and account security events.
- Security operators who want investigation assistance, consistent triage, and auditable response workflows.

These are target segments, not validated paying customers. Customer discovery is required before committing to a broad feature set.

## Core problem

Many organizations lack the people, time, and tooling to interpret security alerts consistently. A useful product must reduce investigation effort without creating a new source of risk through false positives, opaque AI decisions, or unsafe automated actions.

## Product promise

OniShield AI aims to turn authorized security telemetry into:
- prioritized alerts;
- evidence-linked investigations;
- understandable severity and confidence;
- proportionate response recommendations;
- policy-controlled execution;
- a searchable audit trail.

## Initial scope

The first milestone is intentionally narrow: one controlled telemetry source, a small set of explainable detections, an AI-assisted investigation workflow, and one reversible lab-only response action.

Do not attempt to support every attack type, operating system, cloud provider, or enterprise integration in the first release.

## Initial demonstrator acceptance criteria

A reviewer must be able to:
1. Generate or replay a documented synthetic security event.
2. See the original event and its normalized representation.
3. See why a detection fired, including the rule or signals involved.
4. Review an AI investigation that cites event identifiers and separates facts from hypotheses.
5. See severity, confidence, and unresolved questions.
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
- Autonomous deletion, wiping, account lockout, or network-wide isolation.

## Product principles

Evidence first; least privilege; safe defaults; explainable decisions; human override; tenant isolation; privacy by design; measurable outcomes.
