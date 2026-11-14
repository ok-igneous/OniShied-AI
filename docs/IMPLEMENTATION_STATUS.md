# Implementation Status

**Last updated:** 2026-11-14  
**Environment:** Repository changes are being made through GitHub; the founder currently has no working development PC.

## Additional implementation on stacked pull-request branches (not merged)

The following work exists on an open PR stack based on `main`; it is not yet part of the default branch and is not verified in a running environment:

- PR #21: stable finding episode identity, explicit episode boundaries, structured evidence references, idempotent evidence merging, and concurrency serialization.
- PR #22: tenant-scoped durable detection replay queue and separate leased worker with bounded retries/dead-letter handling.
- PR #23: operator-controlled finding lifecycle transitions with database-enforced roles, recent step-up authentication, and append-only status audit.
- PR #24: tenant-scoped investigation cases, finding associations, evidence/activity retrieval, and case-level access controls.
- PR #25: evidence-grounded AI investigation worker, strict structured output validation, canonical evidence citation checks, TLP:CLEAR-only external threat metadata, immutable report history, and human-approval-only recommendations.
- PR #26: early operator investigation console at `/operator`, using an existing operator session token; includes case creation, case review, finding association, notes, lifecycle transitions, and AI report review.
- PR #27: operator-authenticated tenant-scoped finding discovery and selection, so analysts can search indexed title prefixes or exact finding IDs when creating cases.
- PR #28 branch: deterministic server-side enforcement of AI report limitations when evidence is truncated or threat-intelligence matches are withheld/omitted, with regression tests.
- PR #29 branch: strict Zod schemas and tests for six Windows/Linux metadata event kinds, pseudonymous identity references, bounded batches, and duplicate sequence rejection. Schema-only; no agent or telemetry ingestion.
- PR #30: endpoint enrollment control plane with tenant-bound, single-use 15-minute enrollment tokens, 256-bit device credentials stored as SHA-256 verifiers, and owner/admin revocation.
- PR #31 branch: repairs malformed SQL in migration 022; adds credential-authenticated endpoint telemetry ingestion, tenant/agent/platform binding, atomic persistence, per-boot sequence and event-ID uniqueness, exact-retry idempotency, replay-conflict rejection, and revoked-device rejection. Events are stored in a dedicated table and are not yet normalized into the existing detection pipeline.

PRs #21–27 are open and must be merged in dependency order. Migrations 016–023 and the associated SQL smoke tests have not been applied/executed. Typecheck, build, unit tests, browser testing, and successful CI have not been observed. The console does not provide its own password/MFA login and is not a production SOC interface. AI output is advisory and cannot execute response actions.


## Implemented in the repository

- Endpoint telemetry protocol schema plus credential-authenticated ingestion route and dedicated tenant-bound persistence implementation exist on stacked, unmerged branches; still no endpoint binary, installer, or detection-pipeline adapter.

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
- TOTP MFA and one-use recovery codes for enrolled operator accounts: 160-bit secret generation, AES-256-GCM encrypted secret storage, password-verified enrollment, 10-minute pending enrollment, login challenge before session issuance, atomic one-use challenge consumption, replay-resistant TOTP counter updates, MFA-required step-up for owner/admin/reviewer roles, MFA-protected disablement, and restricted audit events. Ten 128-bit recovery codes are issued once, stored as peppered HMAC digests, and atomically consumed for login or password-verified step-up. Unit tests cover TOTP primitives, encrypted storage, MFA login, recovery, and privileged step-up.
- Operator-auth service unit tests for successful login, wrong password, inactive account, missing tenant membership, token digest handling, logout, session-bound authorization, persistent throttle enforcement, password step-up success/failure, and authenticated review attribution.
- PostgreSQL-backed login throttling by HMAC-keyed email and source IP (five attempts per 15 minutes, then a 15-minute lock), plus a database smoke test.
- Loopback-only operator login, session introspection, logout, rotation, session inventory/revocation, and threat-indicator review API routes. Rotation is atomic; session inventory is limited to the authenticated operator and tenant; privileged review/revocation operations serialize against session revocation. Review functions revalidate the session and write the authenticated operator UUID into the status audit record.
- Database smoke coverage for credential-function access, session creation/resolution/revocation, tenant isolation, and denial of direct password/session-digest table access.
- Resend transactional-email transport plus operator invitation, email-verification, and password-reset backend workflows. Action tokens are random, HMAC-digested before database storage, short-lived, one-use, and audited. Invitation acceptance creates a verified operator and tenant membership transactionally; password reset revokes active sessions. Login now requires verified email. Unit tests cover token handling and generic reset behavior; PostgreSQL smoke coverage is included in CI. Frontend fragment-token pages and live Resend configuration remain outstanding.

## Important implementation boundaries

- Threat-intelligence matching is an internal callable service; it is not wired into event ingestion or an autonomous response path.
- Human operator routes exist only on the server's current `127.0.0.1` listener and require the dedicated `onishield_auth` database connection. Do not expose them remotely. The normal `onishield_app` role cannot read password hashes or session digests, or modify memberships. Persistent account/IP throttling and operator-attributed review audit are implemented but unverified. Device labels, remote browser/mobile token transport, TLS/origin controls, and throttle-retention cleanup remain unimplemented. Invitation, email verification, and password reset backend workflows are implemented but unverified; frontend token pages and live Resend delivery remain outstanding. Enrolled accounts require TOTP at login; owner/admin/reviewer roles cannot complete privileged step-up without enrolled MFA. MFA enrollment, login challenge, replay prevention, disablement, and audit are implemented in code but remain unverified.
- The legacy reviewer database role is retained only for denial tests and has no direct review privileges. The authenticated review API validates the operator session in PostgreSQL and records the persisted operator UUID in each new review audit row. Production still needs a reviewed identity lifecycle and privileged step-up controls.
- TLP disclosure-policy evaluator and unit tests are implemented as an isolated policy primitive. It is not connected to authenticated read/report/export endpoints; caller identity and community/organization/named-recipient membership must come from trusted server-side authorization, not request fields.
- Automatic threat-feed ingestion, global intelligence, cross-tenant sharing, public review APIs, AI approvals, and automated blocking are not implemented.
- No AI agent or response execution is authorized by the current foundation.
- Configurable Autopilot has a normative design contract only: tenant opt-in, default OFF, bounded modes, per-action policy, risk ceilings, human approval for disruptive actions, Tier 3 prohibition, emergency pause, fail-closed checks, and execution audit. No Autopilot policy schema, UI, or executor is implemented.
- Backup and Disaster Recovery has a normative design contract only: encrypted layered backups, isolated/immutable copies, integrity manifests, tenant-safe restore, clean-room recovery, credential re-enrollment, and restore drills. No backup scheduler, vault integration, restore tooling, or verified recovery capability is implemented.

## Verification status

**Not verified yet.** GitHub Actions has repeatedly failed before allocating a runner because the GitHub account is locked due to a billing issue. The most recent known failure had no runner and no executed steps. Therefore, no passing claim is made for migrations, PostgreSQL RLS tests, unit tests, type-checking, or build.

A successful CI run must be observed before treating the database controls or application code as validated. The owner must resolve the GitHub account billing restriction under GitHub **Settings → Billing & plans**; making the repository public does not bypass this account-level restriction.

## Next release gates

1. Obtain a successful CI run and resolve every migration, test, type-check, and build failure, including the new session lifecycle smoke coverage and migration 012 email-account lifecycle controls.
2. Run the disposable Linux lab end-to-end and verify event ingestion, duplicate handling, tenant isolation, and indicator matching against PostgreSQL.
3. Deploy and verify the web-client token pages, Resend sender/domain, invitation/email verification/password-reset flows, device labeling, remote browser/mobile token transport, TLS/origin policy, secure client storage, key rotation/backup, and throttle retention before exposing operator routes beyond loopback.
4. Provision production reviewer accounts and independently review authenticated review/audit controls.
5. Integrate TLP enforcement into authenticated read/report/export paths with persisted recipient scope and verify append-only audit retention/backup controls.
6. Implement and test backup/PITR, isolated restore, tenant-safe recovery, key recovery, and measured RPO/RTO before production data is accepted.
7. Implement Autopilot policy simulation first; keep execution disabled until deterministic detection, read-only investigation, approval, rollback, emergency pause, and audit controls have independent tests.
8. Only after those gates, implement a reversible lab action and then explicitly opt-in low-risk automation. Tier 2 always requires approval; Tier 3 remains excluded.

Do not describe OniShield AI as production-ready, fully protective, or autonomously responding to threats.
