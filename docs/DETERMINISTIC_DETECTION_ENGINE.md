# Deterministic Detection Engine v1

**Status:** Implemented as a pure, batch-oriented evaluator with tenant-isolated finding persistence. Not yet wired into ingestion or customer alert delivery.

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
- Evidence event IDs, first/last observed timestamps, matched conditions, severity, confidence, and limitations.
- Event ordering is normalized; duplicate event identities in a supplied batch are ignored.
- Tenant ID is part of every grouping key. Events from different tenants are never combined.
- Missing principal or host data is not guessed; affected events are skipped.

## Finding persistence
Migration `013_detection_findings.sql` creates a tenant-RLS-protected findings table. `src/detection-finding-store.ts` writes findings inside `withTenantTransaction`, rejects tenant mismatches, and uses `(tenant_id, finding_id)` for exact replay idempotency. Listing is tenant-scoped and bounded to 1–500 rows. CI now includes a PostgreSQL smoke test for RLS and exact replay idempotency.

A changed evidence set currently creates a distinct finding snapshot. This can produce multiple findings for one ongoing burst across overlapping evaluations. Episode correlation, update/merge semantics, resolution, and alert deduplication are deliberately not claimed as solved.

## Explicit limitations / next engineering gate
This is a **batch evaluator plus persistence layer**, not a streaming detection service. The caller must supply the complete evaluation horizon. It does not maintain watermarks for late events, merge findings across overlapping batches, or run automatically from `POST /v1/events`. Do not describe detections as live or customer-ready until ingestion integration, authenticated finding queries, replay/late-arrival semantics, episode correlation, and end-to-end tests are implemented.

The engine only emits findings. It has no response executor and cannot block accounts, isolate hosts, or change customer systems.
