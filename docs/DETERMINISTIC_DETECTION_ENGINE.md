# Deterministic Detection Engine v1

**Status:** Implemented as a pure, batch-oriented evaluator; not yet wired into ingestion, persistence, or customer alert delivery.

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

## Explicit limitations / next engineering gate
This is a **batch evaluator**, not a streaming detection service. The caller must supply the complete evaluation horizon. It does not persist findings, maintain watermarks for late events, merge findings across overlapping batches, or enforce database tenant policies itself. It is not yet called by `POST /v1/events`. Do not describe detections as live or customer-ready until persistence, authenticated tenant-scoped querying, replay/late-arrival semantics, and end-to-end tests are implemented.

The engine only emits findings. It has no response executor and cannot block accounts, isolate hosts, or change customer systems.
