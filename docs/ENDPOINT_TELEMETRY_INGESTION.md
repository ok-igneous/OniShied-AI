# Endpoint telemetry ingestion and detection bridge

## Implemented contract

- `POST /v1/endpoints/telemetry` authenticates a device using its one-time-issued 256-bit enrollment credential. Only the SHA-256 verifier is queried; plaintext credentials are never stored.
- Tenant, agent ID, platform and agent version are bound to the credential-bound database row. Heartbeat hostname must match enrollment. The request cannot select a tenant or another agent; client-supplied future timestamps beyond five minutes are rejected.
- Requests use the strict telemetry discriminated union and are bounded to 1–100 events; Fastify's body limit is 256 KiB.
- Persistence is atomic per batch. Each event is unique by tenant + agent + boot + sequence and by tenant + agent + event ID.
- Exact retries are idempotent. Reuse of a sequence with different content or a different event ID is rejected.
- Revoked and quarantined credentials are rejected. The device row is locked during ingestion so revocation and ingestion serialize.
- Each newly accepted telemetry event is normalized into the canonical `security_events` envelope, using a stable connector identity `endpoint:<agent UUID>`. Authentication success/failure maps to the existing `identity.authentication.*` event types; other telemetry maps to namespaced endpoint event types.
- A detection replay job is enqueued in the same database transaction as both telemetry and canonical security-event persistence. The API then attempts synchronous deterministic evaluation. If evaluation fails, the durable replay job remains pending.
- Existing authentication rules can evaluate endpoint authentication events when the payload includes the required opaque principal reference and the enrolled host grouping key.

## Detection semantics and limitations

- Only authentication events currently match the existing deterministic authentication rules. Heartbeat, process, network, file-integrity and service events are canonicalized and stored, but there are no dedicated rules for those event kinds yet.
- The event source host reference currently uses the enrolled hostname. The endpoint contract permits a hostname; deployments should review this identifier under their customer privacy policy.
- The replay worker remains configured for one `LAB_TENANT_ID` per process. Run a worker for each tenant or implement tenant-fair scheduling before relying on asynchronous replay across multiple tenants.
- No signed agent binary, installer, update channel, device inventory UI, credential rotation, per-IP rate limiter, or abuse-monitoring pipeline exists.

## Verification gate

The SQL and route changes are authored but not executed. No migration, PostgreSQL smoke test, unit test, typecheck, build, or CI result is claimed. Apply migrations 001–023 to a disposable PostgreSQL 16 database with the exact bootstrap roles, then run all SQL smoke tests, concurrency tests, typecheck, build, and source-line checks before rollout.
