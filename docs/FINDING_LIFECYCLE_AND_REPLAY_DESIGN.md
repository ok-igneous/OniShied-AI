# Finding Lifecycle and Durable Replay Design

## Status

Stable finding episode identity and idempotent evidence persistence are implemented in the source and migration layer. Analyst lifecycle management and durable replay remain design-only.

## Why this work is required

The current detector derives `finding_id` from the exact evidence-event references. As an authentication burst grows, the evidence set can change, producing a different finding ID for the same underlying episode. The current persistence layer uses `ON CONFLICT DO NOTHING`, so it prevents exact duplicate inserts but does not merge evolving evidence into one incident.

The ingestion path also evaluates only a bounded +/-10-minute neighborhood around the event being ingested. It has no durable replay queue or worker. Events older than that evaluation horizon can remain stored without ever being evaluated if no later ingestion causes the relevant neighborhood to be revisited.

Adding analyst workflow states before correcting these identity and replay limitations would create operational noise and misleading completeness.

## Decision 1: Separate incident identity from evidence identity

A finding/incident must have a stable identity independent of its current evidence list.

The implemented identity key is SHA-256 over structured JSON containing tenant ID, rule ID, rule version, grouping-key hash, and the structured episode-anchor pair `(connector_id, event_id)`. The anchor is the first event that satisfies the rule: the eighth failure for a burst, or the qualifying success for a failure-then-success sequence. The evolving evidence set is excluded.

The identity must not include the complete evidence-event list. Evidence references remain structured pairs of `connector_id` and `event_id`; they must never be reconstructed by splitting the legacy `connector:event` display string.

### Episode boundary policy

A rule must explicitly define when activity belongs to the same episode and when a new episode begins. A quiet-period boundary is preferable to a calendar bucket because an arbitrary time bucket can split one continuous attack at midnight or merge separate episodes near a bucket edge.

Implemented episode policy:
- An authentication burst is anchored at the first event that completes the eight-failure threshold in a rolling five-minute window. Events whose observed time falls within five minutes after that anchor enrich that episode. A later threshold crossing after that post-trigger interval starts another episode.
- Each qualifying success after at least five failures in the preceding ten minutes is a separate sequence episode, anchored by that success.
- Late-arriving events after a burst anchor and inside its five-minute episode window enrich the same stable ID. A late event earlier than the anchor can change which event first crosses the threshold in a stateless recomputation; the finding records this limitation. Durable reconciliation of pre-anchor late events is deferred to the replay worker.
- Concurrent writes for the same finding are serialized by PostgreSQL's unique-key conflict row lock; evidence rows are independently deduplicated by `(tenant_id, finding_id, connector_id, event_id)`.
- Evidence is append-only at the structured evidence-link table. No per-finding retention cap is introduced in this milestone; operational retention and bounded replay remain future work.

Do not silently merge events across tenants, rules, grouping keys, or unrelated episodes.

## Decision 2: Preserve evidence as append-only history

When new qualifying events are found for an existing episode:
- retain the stable incident identity;
- append only previously unseen structured event references;
- update first/last observed timestamps using deterministic min/max rules;
- retain the rule version and detection explanation that produced each material change;
- link threat-intelligence matches to the exact connector/event identity;
- never overwrite the original evidence history to make the finding appear smaller.

The implementation must be idempotent under connector retries and worker retries. A repeated evaluation must not duplicate evidence links or create another incident for the same episode.

## Decision 3: Analyst lifecycle and authorization

The intended lifecycle is:
- `open`: newly detected and awaiting triage;
- `acknowledged`: an authorized analyst has accepted ownership;
- `investigating`: active investigation is underway;
- `resolved`: the analyst has recorded that the incident is no longer active;
- `reopened`: new qualifying evidence or an authorized analyst reopens a resolved incident.

A transition must be validated against an explicit transition table. A client must not be allowed to set arbitrary status values or change tenant ownership.

Every manual transition must record:
- tenant and stable finding ID;
- previous and new status;
- authenticated operator ID;
- timestamp;
- mandatory reason;
- request/correlation identifier where available.

The audit log must be append-only for the runtime application role. Status changes must be performed through a database function that validates the operator session, tenant membership, role, and recent step-up authentication. Connector bearer authentication is not analyst authentication and must not authorize lifecycle mutations.

The existing operator permission `detection:triage` is the intended application authorization gate. The database function must independently enforce the security boundary rather than trusting only the HTTP route.

## Decision 4: Durable replay

Replay must not be an unauthenticated public endpoint and must not depend on a connector sending another event to trigger evaluation.

The preferred architecture is a durable tenant-scoped work queue:
- enqueue work transactionally with event persistence or through a reliable database outbox;
- claim bounded work using row locking and `SKIP LOCKED`;
- use bounded batches and explicit retry/backoff;
- record attempts, last error category, and completion state;
- ensure worker retries are safe through stable incident identity and idempotent evidence writes;
- apply tenant isolation to queue reads and writes;
- expose operational metrics for backlog age, retries, and terminal failures.

Replay must cover stored events outside the current +/-10-minute ingestion neighborhood. It must use the same versioned deterministic rules as live evaluation, with a defined policy for historical rule versions and late-arriving events.

Do not add an HTTP route that lets a caller submit arbitrary tenant IDs, timestamps, or unbounded replay ranges. Worker scope must be established server-side.

## Required implementation sequence

1. ~~Add tests that demonstrate the current changing-evidence identity defect.~~ Completed with stable-anchor, episode-boundary, and out-of-order evidence tests.
2. ~~Implement stable episode identity and concurrency-safe evidence upserts.~~ Implemented stable anchor IDs, conflict-update evidence union, and structured evidence rows.
3. ~~Add migration constraints and indexes for episode uniqueness and evidence idempotency.~~ Migration 016 adds anchor columns, exact event foreign keys, tenant RLS, and unique evidence identity.
4. Add append-only lifecycle audit storage and a database-enforced transition function.
5. Add operator-authenticated lifecycle routes using `detection:triage`; require recent step-up for mutations.
6. Add a durable replay queue and bounded worker with retry semantics.
7. Add database smoke tests for tenant isolation, role denial, step-up expiry, transition validity, evidence idempotency, concurrent updates, and replay retry behavior.
8. Run the full CI pipeline, migration suite, typecheck, and build before claiming the milestone is verified.

## Explicit non-goals

This milestone does not authorize automatic blocking, account disabling, endpoint isolation, or other disruptive response actions. Detection findings and threat-intelligence matches are investigative signals, not proof of compromise. Autopilot remains disabled for disruptive actions until detection correctness, replay completeness, analyst controls, and response safeguards have been independently validated.

## Verification status

- Implemented: stable episode-anchor identity in the detector; explicit burst and sequence episode boundaries; deterministic tests for later and out-of-order evidence; conflict-safe JSON evidence union; structured evidence rows with tenant-scoped foreign keys, uniqueness, and RLS; migration 016 and migration smoke-test coverage.
- Not implemented: durable replay/reconciliation for events arriving before an existing episode anchor; analyst lifecycle transitions/audit; lifecycle routes; queue/worker; evidence retention controls.
- Tests, typecheck, build, and database migrations have not been executed in this environment.
- GitHub Actions has previously been blocked before runner allocation by the account billing/spending restriction. A workflow that never starts does not establish whether the code passes or fails.
