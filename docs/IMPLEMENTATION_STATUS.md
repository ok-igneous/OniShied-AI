# Implementation Status

**Last updated:** 2026-11-13  
**Environment:** Repository changes are being made through GitHub; the founder currently has no working development PC.

## Implemented in the repository

- TypeScript/Fastify backend scaffold with Zod validation and PostgreSQL access.
- Canonical security event schema, authenticated lab ingestion, payload digest, and duplicate-event handling.
- Tenant-scoped PostgreSQL transactions and RLS policies for security events.
- Separate owner, migrator, and runtime database roles with least-privilege runtime grants.
- Synthetic event fixture and localhost-only replay script.
- Source-file line-count enforcement with a hard 500-line maximum in CI.
- Deterministic threat-indicator normalization and exact matching for explicitly mapped event fields.
- Tenant-scoped threat-intelligence tables, match persistence, and database uniqueness for idempotent match records.
- Reviewer-only threat-indicator status transitions, a required review reason, and trigger-generated status audit records.
- PostgreSQL smoke tests for event RLS, threat-intelligence RLS, reviewer authorization/audit controls, and operator identity permissions.
- Operator identity and tenant-membership schema; scrypt password verification, opaque session tokens, dedicated auth database role/pool, narrow SECURITY DEFINER credential/session functions, tenant-bound session validation/revocation, and deny-by-default role/action authorization bound to a validated session.
- Operator-auth service unit tests for successful login, wrong password, inactive account, missing tenant membership, token digest handling, logout, session-bound authorization, persistent throttle enforcement, password step-up success/failure, and authenticated review attribution.
- PostgreSQL-backed login throttling by HMAC-keyed email and source IP (five attempts per 15 minutes, then a 15-minute lock), plus a database smoke test.
- Loopback-only operator login, session introspection, logout, rotation, session inventory/revocation, and threat-indicator review API routes. Rotation is atomic; session inventory is limited to the authenticated operator and tenant; privileged review/revocation operations serialize against session revocation. Review functions revalidate the session and write the authenticated operator UUID into the status audit record.
- Database smoke coverage for credential-function access, session creation/resolution/revocation, tenant isolation, and denial of direct password/session-digest table access.
- CI workflow configured to provision PostgreSQL, apply migrations, execute database smoke tests, run unit tests, type-check, and build.

## Important implementation boundaries

- Threat-intelligence matching is an internal callable service; it is not wired into event ingestion or an autonomous response path.
- Human operator routes exist only on the server's current `127.0.0.1` listener and require the dedicated `onishield_auth` database connection. Do not expose them remotely. The normal `onishield_app` role cannot read password hashes or session digests, or modify memberships. Persistent account/IP throttling and operator-attributed review audit are implemented but unverified. Invitation, email verification, recovery, device labels, step-up authentication, remote browser/mobile token transport, TLS/origin controls, and throttle-retention cleanup remain unimplemented.
- The legacy reviewer database role is retained only for denial tests and has no direct review privileges. The authenticated review API validates the operator session in PostgreSQL and records the persisted operator UUID in each new review audit row. Production still needs a reviewed identity lifecycle and privileged step-up controls.
- TLP disclosure-policy evaluator and unit tests are implemented as an isolated policy primitive. It is not connected to authenticated read/report/export endpoints; caller identity and community/organization/named-recipient membership must come from trusted server-side authorization, not request fields.
- Automatic threat-feed ingestion, global intelligence, cross-tenant sharing, public review APIs, AI approvals, and automated blocking are not implemented.
- No AI agent or response execution is authorized by the current foundation.

## Verification status

**Not verified yet.** GitHub Actions has repeatedly failed before allocating a runner because the GitHub account is locked due to a billing issue. The most recent known failure had no runner and no executed steps. Therefore, no passing claim is made for migrations, PostgreSQL RLS tests, unit tests, type-checking, or build.

A successful CI run must be observed before treating the database controls or application code as validated. The owner must resolve the GitHub account billing restriction under GitHub **Settings → Billing & plans**; making the repository public does not bypass this account-level restriction.

## Next release gates

1. Obtain a successful CI run and resolve every migration, test, type-check, and build failure, including the new session lifecycle smoke coverage and migration 008 authorization-race hardening.
2. Run the disposable Linux lab end-to-end and verify event ingestion, duplicate handling, tenant isolation, and indicator matching against PostgreSQL.
3. Complete account invitation/recovery, device labeling, remote browser/mobile token transport, TLS/origin policy, secure client storage, throttle retention, and step-up authentication before exposing operator routes beyond loopback.
4. Provision production reviewer accounts and independently review authenticated review/audit controls.
5. Integrate TLP enforcement into authenticated read/report/export paths with persisted recipient scope and verify append-only audit retention/backup controls.
6. Only then integrate deterministic detections and read-only AI investigation.
7. Keep response execution disabled until policy authorization, human approval, rollback, and audit controls have independent tests.

Do not describe OniShield AI as production-ready, fully protective, or autonomously responding to threats.
