# OniShield AI — Controlled Demonstration Runbook

**Status:** Planned demonstration; not evidence of a working end-to-end product.  
**Audience:** Technical judges, security reviewers, and prospective design partners.  
**Environment:** Disposable local Linux lab, synthetic events, isolated PostgreSQL database.

## Demonstration objective

Show a narrow, defensible workflow: ingest synthetic identity events, identify a deterministic suspicious pattern, present source evidence, explain uncertainty, and record an operator decision. Do not imply that OniShield currently protects arbitrary endpoints or autonomously stops real attacks.

## Pre-demo requirements

- A clean, disposable Linux lab with no customer data.
- PostgreSQL configured with a non-owner runtime role and tenant row-level security.
- A successful automated test run for schema, database isolation, idempotency, type-check, and build.
- Synthetic fixtures only; use documentation IP ranges.
- A reset procedure that clears only the disposable lab database.
- Network access restricted to the lab; no public targets.
- A visible statement of implemented versus simulated capabilities.

If any required test fails, demonstrate the architecture and test plan only. Do not present a simulated result as a live product capability.

## Proposed 5–7 minute sequence

### 1. Establish the baseline

Show a benign successful login and a small number of isolated failures. Explain that a single failed login is common and should not automatically be called an attack.

**Expected demonstration:** events are visible with source, timestamp, tenant scope, and event ID.

### 2. Replay a synthetic authentication burst

Replay the documented synthetic fixture set for one test principal and one test host.

**Expected demonstration:** ingestion validates the contract, preserves provenance, and handles a repeated event without duplicating it.

### 3. Explain the deterministic finding

Show the configured threshold, time window, grouping fields, matched event IDs, and rule version.

**Expected demonstration:** the finding explains exactly which conditions matched. It does not claim that an account was compromised.

### 4. Show a benign counterexample

Replay a benign scenario, such as a user mistyping a password and then successfully authenticating.

**Expected demonstration:** the reviewer sees why the signal may be benign and what additional context is missing.

### 5. Show investigation boundaries

If an AI investigation module has been implemented and independently tested by demo day, show it producing a structured summary with event ID citations, facts separated from hypotheses, and explicit uncertainty.

If it has not passed those tests, show the proposed interface as a design mock or omit this step. Never label a mock as functioning AI.

### 6. Show response governance

For the current foundation milestone, show the response policy design and audit requirements only. A future lab-only response may be demonstrated only after its implementation, approval gate, rollback, and audit tests pass.

No account lockout, endpoint isolation, deletion, or destructive action is part of this first demo.

## Judge questions to prepare for

- What is the source of each event, and how is it authenticated?
- How is tenant identity derived and enforced?
- How do you prevent duplicate events and duplicate actions?
- What happens when the model is wrong or receives prompt injection in a log?
- How are confidence and severity kept separate?
- What is the measured false-positive rate on the demo fixture set?
- Which capabilities are implemented, simulated, or only planned?
- What does the system do when the database, model, or connector is unavailable?

## Honest claims

Safe: "The demonstrator is designed to correlate authenticated synthetic security events and produce explainable, evidence-linked findings."

Unsafe unless independently proven: "OniShield prevents all cyberattacks", "fully autonomous protection", "zero false positives", or "production-ready enterprise security."

## Demo exit checklist

- [ ] Clean lab setup documented and repeatable.
- [ ] Automated foundation checks pass.
- [ ] Tenant isolation test passes.
- [ ] Duplicate and conflicting event replay tests pass.
- [ ] Benign and suspicious scenarios both demonstrated.
- [ ] Every finding links to evidence and rule version.
- [ ] Implemented, simulated, and planned features are clearly distinguished.
- [ ] No real credentials, customer data, or external targets are used.
