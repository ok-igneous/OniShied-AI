# Development Roadmap

This roadmap is staged. Each phase has a measurable exit gate; do not move forward because a calendar date has arrived.

## Phase 0 — Foundation
- [x] Create private repository.
- [x] Establish initial product and security documentation.
- [ ] Confirm founding contributors and responsibilities.
- [ ] Select the first supported telemetry source and lab environment.
- [ ] Record initial technology decisions as ADRs.

**Exit gate:** scope, ownership, threat boundaries, and test environment are agreed.

## Phase 1 — Event pipeline
- [ ] Define versioned canonical security event schema.
- [ ] Build synthetic event generator/replay fixture.
- [ ] Implement authenticated ingestion and validation.
- [ ] Normalize events and preserve provenance.
- [ ] Add unit and integration tests.

**Exit gate:** repeatable ingestion of valid events and safe rejection of invalid events.

## Phase 2 — Detection and triage

Design artefacts: [initial detection scenario catalogue](DETECTION_SCENARIOS.md). This is a specification, not an implemented detector.
- [ ] Implement a small deterministic detection rule set.
- [ ] Link findings to source event identifiers.
- [ ] Add severity rubric and confidence semantics.
- [ ] Test benign events and false positives.

**Exit gate:** deterministic findings with explainable evidence.

## Phase 3 — AI investigation
- [ ] Define structured investigation result schema.
- [ ] Add read-only evidence retrieval tools.
- [ ] Require event references for factual claims.
- [ ] Add prompt-injection and invalid-output tests.
- [ ] Record model/prompt version and uncertainty.

**Exit gate:** AI produces bounded, evidence-linked investigation summaries without action privileges.

## Phase 4 — Policy-gated response
- [ ] Define action registry and risk tiers.
- [ ] Implement dry-run and policy checks.
- [ ] Add approval workflow for disruptive actions.
- [ ] Implement one reversible lab-only action.
- [ ] Verify outcomes and audit every decision.

**Exit gate:** a full safe lab workflow from event to approved response and audit record.

## Phase 5 — Operator experience
- [ ] Build desktop operational view.
- [ ] Add alert details, evidence, approvals, and audit history.
- [ ] Add mobile alert review and approval experience.
- [ ] Test accessibility and failure states.

**Exit gate:** a reviewer can operate and understand the demonstrator without developer intervention.

## Phase 6 — Hardening and competition readiness

Demonstration planning: [controlled demonstration runbook](DEMO_RUNBOOK.md). This is a planned sequence; only verified capabilities may be presented as working.
- [ ] Threat-model review and security test report.
- [ ] Reproducible deployment and demo scripts.
- [ ] Performance and failure-mode measurements.
- [ ] Clear product limitations and roadmap.
- [ ] Competition narrative backed by a live, repeatable demonstration.

**Exit gate:** demo can be repeated from a clean environment and withstands skeptical technical review.
