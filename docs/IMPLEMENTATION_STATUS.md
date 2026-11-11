# Implementation Status

Last updated: 2026-11-11

## Implemented in repository

- Initial product, architecture, team, security, and roadmap documentation.
- Proposed backend stack recorded in ADR-002.
- TypeScript/Fastify application scaffold.
- Zod validation contract for canonical event version 0.1.0.
- PostgreSQL migration for event persistence and idempotency.
- Single-connector bearer authentication for the isolated synthetic lab.
- Server-side tenant and connector identity checks.
- Duplicate event handling through a database unique constraint.
- Health endpoint and local lab instructions.
- Schema unit tests and GitHub Actions validation workflow.

## Not yet verified

The repository changes have been committed through GitHub, but the application has not yet been installed, compiled, or run in a local Linux/PostgreSQL environment during this work session. The CI workflow must pass before the ingestion service is considered validated.

## Explicitly out of scope

- Production connector identity and secret rotation.
- Real endpoint telemetry collection.
- AI investigation and model integration.
- Detection rule engine.
- Response execution.
- Production deployment, customer onboarding, and security certification.

## Immediate validation checklist

1. Install Node.js 22+ and PostgreSQL 15+.
2. Create a disposable local database and apply the SQL migration.
3. Configure a local `.env` using `.env.example`.
4. Run `npm install`.
5. Run `npm test`, `npm run typecheck`, and `npm run build`.
6. Run the service and execute the smoke tests in `docs/LOCAL_LAB.md`.
7. Fix all failing checks before adding AI or response capabilities.
