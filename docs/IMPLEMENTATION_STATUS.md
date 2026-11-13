# Implementation Status

Last updated: 2026-11-13

## Implemented in repository

- Product vision, architecture, security, team, roadmap, and ADR documentation.
- Initial deterministic detection scenario catalogue (design only; no rule engine implemented).
- Threat intelligence contract, tenant-scoped PostgreSQL schema migration 003, and CI RLS smoke-test definition (not executed yet); service, normalization, matching, reviewer workflow, and behavior tests remain unimplemented.
- AI investigation engine contract (design only; no model provider, orchestration, or investigation API implemented).
- Controlled competition demonstration runbook with explicit capability-claim boundaries.
- Mandatory modular-code standard: hard maximum 500 lines per source file.
- Database security standard covering least privilege, tenant isolation, TLS, backups, and production launch gates.
- TypeScript/Fastify application scaffold and Zod event contract v0.1.0.
- PostgreSQL event persistence, tenant RLS, and threat intelligence schema migrations.
- Transaction-local tenant context for ingestion transactions.
- Separate database owner, migration, and runtime role bootstrap scripts.
- Runtime database grants restricted to least-privilege SELECT/INSERT operations.
- SHA-256 payload digest storage and event-ID reuse conflict handling.
- Production configuration requires verified database TLS.
- Synthetic event fixture and localhost-only replay script.
- PostgreSQL tenant-isolation smoke test wired into CI.
- Source-file size check wired into CI.
- Dependabot update configuration and CODEOWNERS file.
- Partial public-repository exposure review documented in [PUBLIC_REPOSITORY_REVIEW.md](PUBLIC_REPOSITORY_REVIEW.md).
- Repository governance and local lab instructions.

## Not yet verified

- The manually triggered CI run failed before any workflow steps executed because GitHub reported the account is locked due to a billing issue. Passing CI has not been established.
- The repository is currently public by owner decision. Branch protection has not been verified in the current public-repository state; do not assume it is active.
- The application has not yet been installed, compiled, or run against PostgreSQL in a local Linux environment during this work session.
- SQL migrations 001–003 and both tenant RLS smoke tests have not yet been executed in a live PostgreSQL instance.
- Threat intelligence normalization, matching, TLP enforcement, reviewer authorization, and audit behavior do not exist yet.
- A committed npm lockfile is still missing. The current execution environment could not reach the npm registry to generate one.
- Dependabot, secret scanning, and CodeQL status have not yet been verified in GitHub settings.

## Production blockers

- Production connector identity, credential rotation, rate limiting, and request abuse controls.
- Complete authentication and authorization model for users, organizations, and operators.
- Verified cross-tenant isolation for every future table, query, job, cache, export, and object store.
- Threat intelligence review/audit workflow, TLP enforcement, and separately authorized global intelligence design.
- TLS and encryption-at-rest configuration, backup restoration, retention/deletion, and incident procedures.
- Independent security review and production deployment hardening.

## Explicitly out of scope for this milestone

- Real endpoint telemetry collection.
- AI investigation and model integration.
- Detection rule engine.
- Autonomous or manual response execution.
- Customer onboarding and production security certification.

## Required next validation

1. Resolve the GitHub Actions startup failure and obtain a successful CI run.
2. Commit a dependency lockfile and move CI to reproducible `npm ci` installs.
3. Obtain a successful CI run including PostgreSQL RLS smoke test and migration 003.
4. Run the same migration and replay procedure on the local Linux lab.
5. Verify event acceptance, identical replay, event-ID collision rejection, invalid schema rejection, unauthorized requests, and cross-tenant denial.
6. Add and verify threat intelligence normalization, matching, expiry, TLP, replay deduplication, and cross-tenant tests before enabling the service.
7. Review branch protection availability and apply the strongest controls supported by the repository plan.
8. Do not start AI investigation or response execution until the ingestion and database checks pass.
