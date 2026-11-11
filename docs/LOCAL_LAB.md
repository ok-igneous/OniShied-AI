# Local Linux Lab

This is a development-only setup for the first ingestion demonstrator. Use synthetic events only.

## Requirements

- Linux
- Node.js 22 or later
- PostgreSQL 15 or later
- npm

## Configure

1. Create unique local passwords for the migration and runtime roles. Do not reuse personal or production credentials.
2. Run `database/bootstrap-roles.sql` as a local PostgreSQL administrator, supplying `migrator_password` and `app_password` through psql variables. This is a one-time setup script; do not run it against production.
3. Connect as `onishield_migrator`, assume `onishield_owner`, and apply migrations `001_create_security_events.sql` and `002_tenant_rls_and_payload_digest.sql` in order. Record applied migration versions; do not repeatedly apply migrations blindly.
4. Run `database/grant-runtime-privileges.sql` as `onishield_owner`.
5. Set `DATABASE_URL` to the `onishield_app` runtime role, not the migration or administrator role.
6. Copy `.env.example` to `.env`.
4. Set the following local values:
   - `DATABASE_URL`
   - `LAB_CONNECTOR_ID=lab-connector-01`
   - `LAB_CONNECTOR_TOKEN` to a random secret of at least 32 characters
   - `LAB_TENANT_ID=lab-tenant`
7. Install dependencies with `npm install` until the project lockfile is committed; after that use `npm ci`.
8. Run `npm run check:lines`, `npm test`, `npm run typecheck`, and `npm run build`.
9. Run `npm run dev`.

The server binds to `127.0.0.1` only. Do not expose it to a network. The runtime database role has only SELECT and INSERT privileges and is subject to tenant Row-Level Security. Tenant context is set transaction-locally for each ingestion transaction.

## Smoke test

Health check:

```sh
curl http://127.0.0.1:3000/health
```

Submit the synthetic example from `docs/EVENT_SCHEMA.md` to `POST /v1/events` with:

```
Authorization: Bearer YOUR_LOCAL_LAB_TOKEN
Content-Type: application/json
```

Expected first response: HTTP 202 with `status: accepted`.

Submit the exact same event again: HTTP 200 with `status: duplicate`. Reuse the same event ID with a changed payload: HTTP 409 with `event_id_reused_with_different_payload`.

Try a different tenant ID: HTTP 403. Try an invalid event: HTTP 400. Try a missing or incorrect token: HTTP 401.

## Important limitations

- This is a single-connector lab authentication pattern, not production identity management.
- The database role and migration privileges must be hardened before production.
- No endpoint agent, AI investigation, detection rules, or response execution is included yet.
- The sample service binds to loopback and is not intended for internet access.


## Database role setup example

Use a shell to supply unique secrets without placing them in the repository:

```sh
read -rsp "Migration DB password: " MIGRATOR_DB_PASSWORD; echo
read -rsp "Runtime DB password: " APP_DB_PASSWORD; echo
psql -v ON_ERROR_STOP=1 \
  -v migrator_password="$MIGRATOR_DB_PASSWORD" \
  -v app_password="$APP_DB_PASSWORD" \
  -f database/bootstrap-roles.sql
unset MIGRATOR_DB_PASSWORD APP_DB_PASSWORD
```

Apply migrations using the migration identity and owner role. For example, use a controlled psql session as `onishield_migrator`, execute `SET ROLE onishield_owner`, then apply each migration in order. Run the runtime grants script as `onishield_owner`. Keep migration and runtime connection strings separate. Never grant the application role ownership, superuser, role creation, database creation, or RLS bypass privileges.

The initial schema is lab-only. Before production, validate RLS with two tenants and the actual non-owner runtime role, verify TLS certificate validation, and complete the database security launch gate.


## Tenant-isolation smoke test

After migrations and runtime grants, run the SQL test using a database administrator permitted to assume the runtime role:

```sh
psql -v ON_ERROR_STOP=1 -d onishield_lab -f database/tests/tenant_rls_smoke.sql
```

The script temporarily assumes `onishield_app`, inserts a synthetic tenant-A row, changes its transaction-local tenant context to tenant B, asserts that tenant B cannot read the row or insert a tenant-A row, and rolls back all test data. A successful SQL exit is required; do not run this against production.

## Synthetic event replay

With the local server running, export the local lab token and replay the checked-in synthetic fixture:

```sh
export LAB_CONNECTOR_TOKEN='your-local-random-token'
bash scripts/replay-event.sh
bash scripts/replay-event.sh
unset LAB_CONNECTOR_TOKEN
```

The first request should return HTTP 202; the second identical request should return HTTP 200 as a duplicate. The script refuses non-localhost targets. To test event-ID collision handling, submit a modified copy of the fixture while keeping the same `event_id`; the API should return HTTP 409.
