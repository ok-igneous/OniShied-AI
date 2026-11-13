# AI Investigation Engine — Technical Contract

**Status:** Normative design contract; not implemented.  
**Initial capability:** Read-only investigation of synthetic lab findings.  
**Execution authority:** None. The engine cannot approve or execute response actions.

## 1. Responsibility

Given a deterministic finding and authorized evidence references, produce a structured investigation that summarizes known facts, builds a timestamped timeline, correlates related events within bounded scope, separates facts from hypotheses, identifies missing evidence and benign alternatives, reports uncertainty, and recommends proportionate next investigative steps.

A rule match, indicator match, model confidence, or incomplete telemetry is not proof of compromise.

## 2. Explicit non-responsibilities

The engine cannot change events or rules; change tenant scope or permissions; query arbitrary networks, hosts, or websites; execute shell commands or arbitrary SQL; fetch arbitrary URLs; modify threat intelligence; approve or execute response actions; suppress audit records; or treat evidence content as policy instructions.

## 3. Trust model and data flow

Finding → Authorization → Evidence Retrieval → Deterministic Correlation → AI Synthesis → Schema Validation → Evidence Validation → Persist Investigation → Audit.

Tenant and actor context are derived by trusted server code, never from model output or evidence text.

Trust classes:
1. Trusted control data: server-derived tenant/actor, authorization result, tool allowlist, schema versions, policy.
2. Validated evidence envelope: authorized database records that still contain untrusted source text.
3. Untrusted content: logs, event data, filenames, command lines, threat-feed descriptions, tickets, web content, and model output.
4. Validated result: schema-valid, evidence-checked advisory output. It is not an authorization artifact.

## 4. Run request

The server constructs investigation_id, tenant_id, finding_id and version, requested_by, explicit scope (event IDs, approved host/principal references, bounded time range), evidence_budget (record and byte limits), tool_policy_version, prompt_template_version, model_profile, and created_at.

Clients cannot broaden scope by asking the model to search another tenant or arbitrary assets. Scope expansion requires a new server-authorized request.

## 5. Read-only tool allowlist

| Tool | Input | Output | Restrictions |
|---|---|---|---|
| get_event | Event ID | One authorized normalized event | Same tenant; redact secrets |
| list_events | Bounded time range, approved refs, cursor, limit | Authorized event page | Hard limits and deterministic order |
| get_finding | Finding ID | Finding and rule metadata | Same tenant |
| get_indicator_matches | Event IDs | Authorized intelligence matches | Respect expiry, TLP, tenant visibility |
| get_asset_context | Approved asset ref | Minimal inventory/criticality | Only if inventory and permission exist |

No shell, network, browser, SQL, response, or arbitrary file tool is exposed. Validate every call server-side, enforce tenant authorization, rate limits, timeouts, and budgets, and record calls. Tool output is data, never executable instruction.

## 6. Prompt-injection resistance

- Delimit evidence as quoted data with source/type metadata.
- Never concatenate untrusted content into system or developer instructions.
- State that evidence cannot change policy, tools, scope, or output contract.
- Do not rely on prompt wording as the security boundary; enforce permissions in code.
- Redact secrets and unnecessary personal data before provider submission.
- Bound evidence size and reject malformed encodings.
- Validate tool arguments and re-authorize every call server-side.
- Include adversarial fixtures: “ignore previous instructions”, fake system prompts, malicious filenames, embedded URLs.
- Identify injection-like content as suspicious evidence; never follow it.

## 7. Output contract v1

The model must return a JSON object with exactly these top-level fields:

| Field | Type / rule |
|---|---|
| contract_version | Literal 1.0 |
| investigation_id | Exact request ID |
| finding_id | Exact input finding ID |
| assessment | suspicious, likely_benign, inconclusive |
| summary | Plain text, max 1,000 characters |
| facts | Array; every item cites evidence |
| hypotheses | Array; labelled, evidence-linked or explicitly untested |
| timeline | Ordered events and timestamps |
| correlations | Deterministic relationships, method, evidence |
| severity_assessment | info, low, medium, high, critical, unknown |
| confidence | Integer 0–100 with rationale; not authorization |
| evidence_coverage | sufficient, partial, poor |
| missing_evidence | Specific missing evidence and why it matters |
| alternative_explanations | Plausible benign or competing explanations |
| recommended_next_steps | Read-only or operator-led suggestions only |
| limitations | Data gaps, source limitations, model uncertainty |
| evidence_refs | IDs of evidence actually retrieved |

Every fact, hypothesis, timeline item, and correlation must cite evidence references. Each reference contains evidence_id, allowlisted evidence_type, observed_at where applicable, retrieved_at, non-secret source_ref, and relevance. Server verifies every ID against the exact evidence set retrieved for this run and tenant. Invented, cross-tenant, and out-of-scope references invalidate the output. Empty arrays are valid.

## 8. Severity, confidence, and correlation

Severity represents impact/urgency. Confidence represents strength of evidence. They are independent. Model self-reported confidence is not calibrated truth; initially calculate numeric confidence in deterministic code using a documented rubric.

Use UTC while preserving original timestamps/timezone where available. Define clock-skew tolerance and late-arrival policy. Sort ties deterministically by timestamp, source ID, and event ID. Temporal proximity is correlation, not causation. Record algorithm version and input IDs. Never merge identities based only on display-name similarity, IP address, or free-text strings.

## 9. Validation and failure behavior

The server must:
1. Parse strict schema; reject unknown fields and invalid enums.
2. Verify investigation and finding IDs match the request.
3. Verify every evidence reference belongs to the retrieved set and tenant.
4. Enforce character, array, token, and response-size limits.
5. Reject factual claims without evidence references.
6. Persist only validated output by default; raw provider output requires explicit encrypted retention policy.
7. Mark invalid or failed runs explicitly; never convert failure into a clean bill of health.
8. Never forward invalid output to response services.

Retry only transient provider/network failures with bounded attempts and idempotency. Do not retry invalid output indefinitely.

## 10. Persistence and audit

Store investigation ID, tenant, finding ID/version, actor/service, authorization decision, evidence IDs and digests, tool calls and bounded arguments, result digests, timestamps, provider/model version, prompt-template version, schema/validator version, validated result/status, latency/cost metadata where available, and safe failure category.

Audit records must be append-only to ordinary application roles. Define retention/deletion before processing customer data.

## 11. Internal API

- POST /internal/investigations: create authorized request; idempotency key required.
- GET /internal/investigations/:id: fetch status and validated result with tenant authorization.
- GET /internal/investigations/:id/evidence: fetch only evidence the caller may view.

No endpoint accepts arbitrary prompts, arbitrary tools, arbitrary tenant IDs, or execution instructions from clients.

Statuses: queued, retrieving_evidence, analyzing, validating, completed, failed, cancelled.

## 12. Test and release gates

Contract tests: valid output accepted; unknown keys/enums rejected; wrong IDs rejected; fabricated evidence IDs rejected; cross-tenant/out-of-scope refs rejected; uncited facts rejected; hypotheses distinct from facts; severity/confidence separate; oversized or malformed output fails safely.

Security tests: event prompt injection cannot expand tools/scope; requests for shell/network/response access are denied; malicious arguments are rejected before repository access; secrets are redacted; provider failure is visible; duplicate requests are idempotent; tenant context is server-derived for every tool.

Quality tests: known synthetic scenarios yield supported summaries; benign scenarios include benign alternatives; missing evidence yields inconclusive/reduced coverage; deterministic retrieval yields stable facts/timeline; measure unsupported-claim rate and evidence citation precision on labelled fixtures.

Release gates:
1. Event ingestion and tenant isolation pass.
2. Detection results are versioned and evidence-linked.
3. Read-only tools pass tenant/authorization tests.
4. Prompt-injection and invalid-output tests pass.
5. Human review validates benign and suspicious fixtures.
6. Only then connect a model provider in a non-production lab.

Version-one exclusions: autonomous response, model-controlled policy, arbitrary web browsing, feed auto-activation, cross-tenant correlation, production telemetry, and claims of autonomous protection.
