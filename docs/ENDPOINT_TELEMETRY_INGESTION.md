# Endpoint telemetry ingestion and detection bridge

## Implemented contract

- `POST /v1/endpoints/telemetry` authenticates a device using its one-time-issued 256-bit enrollment credential. Only the SHA-256 verifier is queried; plaintext credentials are never stored.
- Tenant, agent ID, platform and agent version are bound to the credential-bound database row. Heartbeat hostname must match enrollment. The request cannot select a tenant or another agent; client-supplied future timestamps beyond five minutes are rejected.
- Requests use the strict telemetry discriminated union and are bounded to 1–100 events; Fastify's body limit is 256 KiB. Migration 024 adds a database CHECK validator for exact envelope/data fields and kind-specific types, including explicit timestamp offsets, so direct SQL-function callers cannot bypass the event contract.
- Persistence is atomic per batch. Each event is unique by tenant + agent + boot + sequence and by tenant + agent + event ID.
- Exact retries are idempotent. Reuse of a sequence with different content or a different event ID is rejected. An exact retry can reset a dead-lettered detection job and re-run pending detection without creating a second telemetry or canonical event.
- Revoked and quarantined credentials are rejected. The device row is locked during ingestion so revocation and ingestion serialize.
- Each newly accepted telemetry event is normalized into the canonical `security_events` envelope, using a stable connector identity `endpoint:<agent UUID>`. Authentication success/failure maps to the existing `identity.authentication.*` event types; other telemetry maps to namespaced endpoint event types.
- A detection replay job is enqueued in the same database transaction as both telemetry and canonical security-event persistence. The API then attempts synchronous deterministic evaluation. If evaluation fails, the durable replay job remains pending.
- Migration 024 adds a durable per-agent database event-attempt budget of 1,000 inserts per minute. This protects the persistence boundary but does not replace request/IP rate limits, enrollment-claim throttling or abuse monitoring.
- Existing authentication rules can evaluate endpoint authentication events when the payload includes the required opaque principal reference and the enrolled host grouping key.

## Detection semantics and limitations

- Only authentication events currently match the existing deterministic authentication rules. Heartbeat, process, network, file-integrity and service events are canonicalized and stored, but there are no dedicated rules for those event kinds yet.
- The event source host reference currently uses the enrolled hostname. The endpoint contract permits a hostname; deployments should review this identifier under their customer privacy policy.
- The replay worker remains configured for one `LAB_TENANT_ID` per process. Run a worker for each tenant or implement tenant-fair scheduling before relying on asynchronous replay across multiple tenants.
- No signed agent binary, installer, update channel, device inventory UI, credential rotation, enrollment-claim throttling, per-IP/request rate limiter, or abuse-monitoring pipeline exists.
- The service still uses the existing `onishield_auth` database pool to invoke the ingestion SECURITY DEFINER function. A separate least-privilege ingestion database role/pool has not yet been provisioned; do not treat the current role boundary as final production hardening.
- The replay worker still processes one configured tenant per process. Multi-tenant fairness, bounded cross-tenant scheduling, queue metrics and backlog/dead-letter alerting remain unimplemented.

## Verification gate

The SQL, route and tests are authored but not executed. No migration, PostgreSQL smoke test, unit test, typecheck, build, or CI result is claimed. Apply migrations 001–024 to a disposable PostgreSQL 16 database with the exact bootstrap roles, then run all SQL smoke tests, route tests, concurrency tests, typecheck, build, and source-line checks before rollout.
