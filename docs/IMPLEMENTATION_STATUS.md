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
- PostgreSQL smoke tests for event RLS, threat-intelligence RLS, and reviewer authorization/audit controls.
- CI workflow configured to provision PostgreSQL, apply migrations, execute database smoke tests, run unit tests, type-check, and build.

## Important implementation boundaries

- Threat-intelligence matching is an internal callable service; it is not wired into event ingestion or an autonomous response path.
- The reviewer role is a lab control, not a production identity system. The current lab bootstrap grants it to the migrator login for testability. Production must use individually attributable reviewer identities or a separately authenticated review service.
- The audit records the PostgreSQL session identity. A shared database login is not sufficient attribution for production.
- TLP disclosure-policy evaluator and unit tests are implemented as an isolated policy primitive. It is not connected to authenticated read/report/export endpoints; caller identity and community/organization/named-recipient membership must come from trusted server-side authorization, not request fields.
- Automatic threat-feed ingestion, global intelligence, cross-tenant sharing, public review APIs, AI approvals, and automated blocking are not implemented.
- No AI agent or response execution is authorized by the current foundation.

## Verification status

**Not verified yet.** GitHub Actions has repeatedly failed before allocating a runner because the GitHub account is locked due to a billing issue. The most recent known failure had no runner and no executed steps. Therefore, no passing claim is made for migrations, PostgreSQL RLS tests, unit tests, type-checking, or build.

A successful CI run must be observed before treating the database controls or application code as validated. The owner must resolve the GitHub account billing restriction under GitHub **Settings → Billing & plans**; making the repository public does not bypass this account-level restriction.

## Next release gates

1. Obtain a successful CI run and resolve every migration, test, type-check, and build failure.
2. Run the disposable Linux lab end-to-end and verify event ingestion, duplicate handling, tenant isolation, and indicator matching against PostgreSQL.
3. Replace the shared lab reviewer membership with an individually attributable review identity model.
4. Integrate TLP enforcement into authenticated read/report/export paths with persisted recipient scope and verify append-only audit retention/backup controls.
5. Only then integrate deterministic detections and read-only AI investigation.
6. Keep response execution disabled until policy authorization, human approval, rollback, and audit controls have independent tests.

Do not describe OniShield AI as production-ready, fully protective, or autonomously responding to threats.
