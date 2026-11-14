# Durable Detection Replay

## Scope

Migration 017 adds a tenant-scoped `detection_replay_jobs` table with one unique job per exact `(tenant_id, connector_id, event_id)`. Event ingestion enqueues accepted events in the same transaction as the security-event insert. Migration 017 also bulk-enqueues already-stored events idempotently to cover historical data.

## Worker behavior

Run `npm run start:replay-worker` as a separate process. It is intentionally separate from the API process. The worker claims one job at a time with `FOR UPDATE SKIP LOCKED`, assigns a UUID lease token, and uses a two-minute lease. Expired leases can be reclaimed after a crash. Detection evaluation uses the existing tenant-scoped service; completion and failure updates require the current lease token.

Failures use exponential retry delays capped at one hour and become `dead_letter` after ten attempts. A matching connector retry can release a dead-lettered job. Completed work is not reopened and active leases are not stolen.

## Security and rollout limitations

- The worker uses the deployment's configured `config.tenantId`; it does not claim arbitrary tenants.
- Queue rows have forced RLS and exact event foreign keys.
- The backfill is one bulk insert over the existing event table. On a large production table, schedule and monitor migration 017 because it can create substantial write and index-build load.
- Multi-tenant worker scheduling, bounded backfill batches, queue metrics/alerting, and PostgreSQL concurrency stress tests remain outstanding.
- SQL smoke and retry-policy unit tests are authored but have not been executed. The worker has not been built or run against a database here.
- No public replay endpoint, finding lifecycle endpoint, or disruptive Autopilot action is introduced.
