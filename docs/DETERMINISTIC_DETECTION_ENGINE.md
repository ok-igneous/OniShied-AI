# Deterministic Detection Engine v1

**Status:** Implemented in repository code as a pure, batch-oriented evaluator, tenant-isolated finding persistence, ingestion-triggered bounded evaluation, connector-scoped threat-intelligence enrichment, and an authenticated findings query. Runtime/CI verification remains pending; customer alert delivery is not implemented.

## Implemented rules

### AUTH_FAILURE_BURST (1.0.0)
- Eight or more `identity.authentication.failure` events.
- Five-minute inclusive lookback.
- Grouped by tenant, host, principal, and source address.
- Requires `source.host_ref`, `data.principal_ref`, and `data.source_address`.

### AUTH_FAILURE_THEN_SUCCESS (1.0.0)
- Five or more failures followed by `identity.authentication.success`.
- Ten-minute inclusive lookback before the success.
- Grouped by tenant, host, and principal.
- Source address may differ between failures and success.

## Finding guarantees
- Stable SHA-256 finding identifier for the same rule version, grouping key, and evidence IDs.
- Evidence event IDs plus structured `{connector_id,event_id}` references, first/last observed timestamps, matched conditions, severity, confidence, and limitations.
- Exact active-indicator matches are attached to the finding through tenant-scoped relational links. The link has composite foreign keys to the exact finding and connector-qualified event match; it cannot attach another connector's match.
- Event ordering is normalized across timestamps, connector IDs and event IDs; duplicate event identities in a supplied batch are ignored. A regression test covers equal-timestamp events from separate connectors.
- Tenant ID is part of every grouping key. Events from different tenants are never combined.
- Missing principal or host data is not guessed; affected events are skipped.

## Finding persistence
Migrations `013_detection_findings.sql` and `015_finding_threat_intel_enrichment.sql` create tenant-RLS-protected findings and threat-match association tables. Migration 015 backfills structured event references only when every legacy reference resolves to exactly one canonical event; ambiguous or missing references abort the migration. `src/detection-finding-store.ts` persists findings and associated indicator matches in one tenant transaction. The active indicator set is loaded once per evaluation batch, and matches are attached only to findings that cite the exact event. The findings query returns match metadata (indicator type, confidence, TLP, status and source reference) without exposing raw indicator values. CI includes PostgreSQL smoke coverage for exact connector identity, match replay, finding association and tenant isolation; execution remains pending.

A changed evidence set currently creates a distinct finding snapshot. This can produce multiple findings for one ongoing burst across overlapping evaluations. Episode correlation, update/merge semantics, resolution, and alert deduplication are deliberately not claimed as solved.

## Explicit limitations / next engineering gate
This is a **batch evaluator plus persistence layer**, not a streaming detection service. `POST /v1/events` triggers re-evaluation of the stored event neighborhood within +/-10 minutes of the accepted or duplicate event, capped at 5,000 rows. This supports bounded out-of-order arrival but does not provide durable replay for older late events, watermarks, or a background replay worker. It does not merge findings across overlapping batches. `GET /v1/findings` is authenticated with the configured connector bearer token and returns findings for the configured tenant; it is not a customer-facing operator dashboard. Threat matches are supporting context only: they do not increase the deterministic rule severity, prove compromise, or authorize response. Do not describe detections as production-ready until CI/runtime verification, durable replay, episode correlation, alert delivery, and benign-event calibration are complete.

The engine only emits findings. It has no response executor and cannot block accounts, isolate hosts, or change customer systems.
