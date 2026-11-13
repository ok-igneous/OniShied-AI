# Threat Intelligence Review and Approval

**Status:** Database reviewer role, constrained status transitions, and append-only audit migration committed; PostgreSQL execution remains unverified until CI can start.

## Trust boundary

- `onishield_app` may submit pending indicators and read permitted tenant records, but cannot activate, reject, revoke, expire, update, or delete indicators.
- `onishield_reviewer` is a separate NOLOGIN role. Only the migration/operations principal is granted membership in the initial lab. It is not granted to the runtime app.
- Reviewer access remains tenant-scoped through the existing `app.tenant_id` RLS context. There is no cross-tenant or global review mode.
- The reviewer role can update only the `status` column. It cannot rewrite indicator values, provenance, source, confidence, TLP, or validity fields.
- A database trigger enforces the state machine and requires a transaction-local reason of 10–1000 characters. Allowed transitions are pending → active/rejected and active → revoked/expired.
- Every transition writes an audit row in the same transaction. The database verifies the opaque operator session, derives the tenant/operator/role from persisted membership, and records `actor_operator_id`; it never accepts a caller-supplied actor ID. `actor_db_role` records the database service principal as secondary context.
- The audit table is append-only for app and reviewer roles. Its trigger insert runs through a tightly scoped SECURITY DEFINER function with a fixed search_path; table RLS still checks the transaction tenant.
- Reviewer credentials and membership must be provisioned out-of-band and kept out of source control. Do not expose reviewer database credentials to AI tools or ordinary application endpoints.

## Review transaction

The local API accepts a bearer session and review request. The service hashes the token; the `SECURITY DEFINER` review function independently verifies that session, resolves the tenant and operator, checks the persisted role, sets transaction-local trusted context, performs the status-only update, and records the operator UUID in the same transaction. A caller cannot choose the actor or tenant. The legacy `onishield_reviewer` database role remains for migration-era smoke tests, but the authenticated review path does not depend on a shared reviewer login. This endpoint remains loopback-only until remote authentication and transport controls are reviewed.

## Validation

The PostgreSQL smoke tests check runtime denial, reviewer approval, audit creation, immutable evidence fields, illegal transition rejection, audit deletion denial, cross-tenant isolation, persistent login throttling, and operator-ID audit attribution. These tests are committed but have not run because GitHub Actions currently fails before allocating a runner due to the account billing lock. Do not treat this as a verified security control until the migration and tests execute successfully.

No public review endpoint, AI approval, bulk activation, automatic feed ingestion, global intelligence, or response action is implemented.
