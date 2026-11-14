# Finding Lifecycle and Durable Replay Design

## Status

Design decision for the next detection-engine implementation milestone. This document is not evidence that lifecycle management or durable replay has been implemented.

## Why this work is required

The current detector derives `finding_id` from the exact evidence-event references. As an authentication burst grows, the evidence set can change, producing a different finding ID for the same underlying episode. The current persistence layer uses `ON CONFLICT DO NOTHING`, so it prevents exact duplicate inserts but does not merge evolving evidence into one incident.

The ingestion path also evaluates only a bounded +/-10-minute neighborhood around the event being ingested. It has no durable replay queue or worker. Events older than that evaluation horizon can remain stored without ever being evaluated if no later ingestion causes the relevant neighborhood to be revisited.

Adding analyst workflow states before correcting these identity and replay limitations would create operational noise and misleading completeness.

## Decision 1: Separate incident identity from evidence identity

A finding/incident must have a stable identity independent of its current evidence list.

The identity key should include:
- tenant ID;
- detection rule ID and rule version;
- the detector's normalized grouping dimensions (for example host, principal, and source address where applicable);
- a documented episode-boundary policy.

The identity must not include the complete evidence-event list. Evidence references remain structured pairs of `connector_id` and `event_id`; they must never be reconstructed by splitting the legacy `connector:event` display string.

### Episode boundary policy

A rule must explicitly define when activity belongs to the same episode and when a new episode begins. A quiet-period boundary is preferable to a calendar bucket because an arbitrary time bucket can split one continuous attack at midnight or merge separate episodes near a bucket edge.

The initial implementation must define and test:
- the inactivity interval for each rule;
- how late-arriving events affect an existing episode;
- whether a late event can reopen a resolved incident;
- how concurrent event ingestion is serialized for the same tenant/rule/group;
- retention and maximum evidence references per incident.

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

1. Add tests that demonstrate the current changing-evidence identity defect.
2. Implement stable episode identity and concurrency-safe evidence upserts.
3. Add migration constraints and indexes for episode uniqueness and evidence idempotency.
4. Add append-only lifecycle audit storage and a database-enforced transition function.
5. Add operator-authenticated lifecycle routes using `detection:triage`; require recent step-up for mutations.
6. Add a durable replay queue and bounded worker with retry semantics.
7. Add database smoke tests for tenant isolation, role denial, step-up expiry, transition validity, evidence idempotency, concurrent updates, and replay retry behavior.
8. Run the full CI pipeline, migration suite, typecheck, and build before claiming the milestone is verified.

## Explicit non-goals

This milestone does not authorize automatic blocking, account disabling, endpoint isolation, or other disruptive response actions. Detection findings and threat-intelligence matches are investigative signals, not proof of compromise. Autopilot remains disabled for disruptive actions until detection correctness, replay completeness, analyst controls, and response safeguards have been independently validated.

## Verification status

- Source inspection completed for the current detector, finding store, operator authorization map, operator session validation, migrations, and CI workflow.
- No database migration has been applied in a live environment as part of this design work.
- No automated tests, typecheck, or build have been executed in this environment.
- GitHub Actions has previously been blocked before runner allocation by the account billing/spending restriction. A workflow that never starts does not establish whether the code passes or fails.
