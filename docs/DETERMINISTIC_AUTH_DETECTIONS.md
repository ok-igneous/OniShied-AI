# Deterministic Authentication Detection Rules

This module is the first deterministic detection slice. It is a pure evaluator and does not execute response actions.

## Supported event contract

- `auth.login.failure`
- `auth.login.success`
- Principal in `data.user_id`, `username`, `email`, or `principal`
- Source address in `data.source_ip`, `ip_address`, or `client_ip`

Principal and IP values are normalized to lowercase. Events lacking either value or a valid timestamp are ignored rather than guessed.

## Rules

| Rule | Condition | Severity |
|---|---|---|
| AUTH_FAILURE_BURST | Five failures for the same tenant, principal and source IP in a rolling 10-minute window | Medium |
| AUTH_FAILURES_THEN_SUCCESS | At least three failures followed by success for the same tenant, principal and source IP within 15 minutes | High |

Each result includes tenant scope, principal, source IP, time bounds, sorted evidence event IDs and a SHA-256 fingerprint. Input ordering does not affect the output.

## Deliberate limitations

- These are correlation heuristics, not proof of compromise.
- This initial evaluator correlates the same principal and source IP; distributed password spraying across many accounts/IPs is not covered.
- It requires normalized authentication event types and fields. Existing generic ingestion does not automatically guarantee that every connector emits this contract.
- The evaluator is not yet wired to ingestion, a persisted findings table, alert delivery, or a response executor.
- The rolling-window burst emits a finding at the first threshold crossing; subsequent overlapping windows are intentionally not emitted as separate findings for the same evidence set.

## Next integration work

1. Add connector-specific normalization into the event contract.
2. Load a bounded tenant-scoped event window after ingestion.
3. Persist findings with a unique tenant/fingerprint constraint.
4. Add finding lifecycle, analyst review and audit records.
5. Add integration tests against PostgreSQL and cross-tenant isolation tests.

Do not describe this slice as end-to-end detection or production monitoring until those integration steps and CI tests pass.
