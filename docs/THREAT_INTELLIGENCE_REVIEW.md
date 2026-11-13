# Threat Intelligence Review and Approval

**Status:** Database reviewer role, constrained status transitions, and append-only audit migration committed; PostgreSQL execution remains unverified until CI can start.

## Trust boundary

- `onishield_app` may submit pending indicators and read permitted tenant records, but cannot activate, reject, revoke, expire, update, or delete indicators.
- `onishield_reviewer` is a separate NOLOGIN role. Only the migration/operations principal is granted membership in the initial lab. It is not granted to the runtime app.
- Reviewer access remains tenant-scoped through the existing `app.tenant_id` RLS context. There is no cross-tenant or global review mode.
- The reviewer role can update only the `status` column. It cannot rewrite indicator values, provenance, source, confidence, TLP, or validity fields.
- A database trigger enforces the state machine and requires a transaction-local reason of 10–1000 characters. Allowed transitions are pending → active/rejected and active → revoked/expired.
- Every transition writes an audit row in the same transaction. The actor is recorded from PostgreSQL `session_user`, not accepted from a caller-supplied actor field.
- The audit table is append-only for app and reviewer roles. Its trigger insert runs through a tightly scoped SECURITY DEFINER function with a fixed search_path; table RLS still checks the transaction tenant.
- Reviewer credentials and membership must be provisioned out-of-band and kept out of source control. Do not expose reviewer database credentials to AI tools or ordinary application endpoints.

## Review transaction

A trusted operations service must connect using an individually attributable reviewer database principal, set the tenant context, set `app.threat_review_reason`, and issue a status-only update. The current lab migration grants the reviewer role to the migrator login for testability; this is not an acceptable production identity model. Production must use per-reviewer database identities or a separately authenticated review service that establishes a non-spoofable actor identity.

## Validation

The new PostgreSQL smoke test checks runtime denial, reviewer approval, audit creation, immutable evidence fields, illegal transition rejection, audit deletion denial, and cross-tenant isolation. These tests are committed but have not run because GitHub Actions currently fails before allocating a runner due to the account billing lock. Do not treat this as a verified security control until the migration and tests execute successfully.

No public review endpoint, AI approval, bulk activation, automatic feed ingestion, global intelligence, or response action is implemented.
