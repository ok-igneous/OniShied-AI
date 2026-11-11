# Local Linux Lab

This is a development-only setup for the first ingestion demonstrator. Use synthetic events only.

## Requirements

- Linux
- Node.js 22 or later
- PostgreSQL 15 or later
- npm

## Configure

1. Create a disposable local PostgreSQL database.
2. Apply `database/migrations/001_create_security_events.sql` to that database.
3. Copy `.env.example` to `.env`.
4. Set the following local values:
   - `DATABASE_URL`
   - `LAB_CONNECTOR_ID=lab-connector-01`
   - `LAB_CONNECTOR_TOKEN` to a random secret of at least 32 characters
   - `LAB_TENANT_ID=lab-tenant`
5. Install dependencies with `npm install`.
6. Run `npm run dev`.

The server binds to `127.0.0.1` only. Do not expose it to a network.

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

Submit the exact same event again: HTTP 200 with `status: duplicate`.

Try a different tenant ID: HTTP 403. Try an invalid event: HTTP 400. Try a missing or incorrect token: HTTP 401.

## Important limitations

- This is a single-connector lab authentication pattern, not production identity management.
- The database role and migration privileges must be hardened before production.
- No endpoint agent, AI investigation, detection rules, or response execution is included yet.
- The sample service binds to loopback and is not intended for internet access.
