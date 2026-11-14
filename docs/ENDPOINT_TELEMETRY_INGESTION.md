# Endpoint telemetry ingestion

## Implemented contract

- `POST /v1/endpoints/telemetry` authenticates a device using the one-time-issued 256-bit enrollment credential. Only its SHA-256 verifier is queried; the plaintext credential is never stored.
- The tenant, agent ID and enrolled platform are derived from the credential-bound database row. The request cannot select a tenant or another agent.
- Requests use the strict telemetry discriminated union and are bounded to 1–100 events; the Fastify application body limit remains 256 KiB.
- Persistence is atomic per batch through one SECURITY DEFINER database function. Each event is unique by tenant + agent + boot + sequence and by tenant + agent + event ID.
- Exact retries are idempotent. Reuse of a sequence with different content or a different event ID is rejected as a conflict.
- Revoked and quarantined credentials are rejected. The device row is locked during ingestion so revocation and ingestion serialize.
- Device last-seen time is updated only after the complete batch has been accepted.

## Deliberate limitations

- Events are stored in the dedicated `endpoint_telemetry_events` table. They are **not yet normalized into `security_events`**, so this milestone does not claim endpoint events participate in existing detection rules.
- There is no signed agent binary, installer, update channel, device inventory UI, credential rotation, per-IP rate limiter, or abuse-monitoring pipeline.
- The database smoke test is authored but not executed. No migration, typecheck, build, unit test, or CI result is claimed.
- The app-level schema checks the event shape; database-side checks enforce credential status, agent identity, platform, and replay identity. Deployment still requires validation of PostgreSQL function ownership and runtime-role grants.

## Required next gate

Apply migrations 001–023 on a disposable PostgreSQL instance, run endpoint enrollment and telemetry smoke tests, then run typecheck/build/unit/source-line checks before enabling any real endpoint rollout.
