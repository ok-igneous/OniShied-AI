# Detection Finding Lifecycle and Audit

## State machine

A finding begins as `open`. Permitted transitions are:

- `open` → `acknowledged` or `suppressed`
- `acknowledged` → `investigating` or `resolved`
- `investigating` → `resolved`
- `resolved` → `reopened`
- `reopened` → `acknowledged`, `investigating`, or `resolved`

Suppressed findings have no transition out in this first implementation. New evidence does not automatically reopen a resolved finding; an authorized analyst must explicitly reopen it. Invalid transitions are rejected by PostgreSQL, not merely by route validation.

## Authorization and audit

The operator API requires a valid operator session and the `detection:triage` permission. The database function independently validates the active session, tenant membership, role, and step-up timestamp (maximum age five minutes). Only owner, admin, and security_analyst roles can mutate finding state. The transition reason is mandatory and bounded.

Each successful transition updates the finding and appends an audit row in the same transaction. The audit captures tenant, finding, membership, actor, previous/new status, reason, request ID, and timestamp. Runtime roles cannot directly update finding status or mutate audit history. The history read route requires `detection:read`.

## Endpoints

- `POST /v1/operator/findings/:findingId/transition` — operator session, `detection:triage`, recent step-up.
- `GET /v1/operator/findings/:findingId/history` — operator session, `detection:read`.

Finding IDs must be 64-character lowercase SHA-256 hex values. Connector bearer authentication is not accepted for lifecycle mutation.

## Verification status

Migration 018 and the SQL smoke test are authored but have not been executed. The smoke test covers valid and invalid transitions, audit persistence, viewer-role denial, stale step-up denial, history reads, and denial of direct runtime status updates. Typecheck, build, and CI have not been verified. No automatic response or disruptive Autopilot behavior is enabled.
