# Endpoint Device Enrollment — Initial Control Plane

**Status:** server-side enrollment and credential issuance foundation; not yet a deployable endpoint agent.

## Operator-issued enrollment

An owner or admin creates a platform-specific enrollment token through:

- `POST /v1/operator/endpoints/enrollment-tokens`
- Requires an operator bearer session, `operator:admin`, and database-enforced step-up authentication within five minutes.
- The token is generated with 256 bits of randomness, stored only as a SHA-256 verifier, expires after 15 minutes, and is returned once with `Cache-Control: no-store`.
- The request binds the token to the operator's authenticated tenant and the selected Windows/Linux platform.

## Device claim

An agent claims the token through:

- `POST /v1/endpoints/enroll`
- Requires the one-time token, hostname, agent version and matching platform.
- The database locks the enrollment row, checks expiry, unused state and active originating membership, then consumes it and creates a tenant-bound device record atomically.
- The server generates a separate 256-bit device credential, stores only its SHA-256 verifier, and returns the credential once with no-store headers.
- A second claim cannot reuse the same enrollment token.

The tenant identifier is never accepted from the endpoint request. The server derives it from the stored enrollment grant.

## Revocation

- `POST /v1/operator/endpoints/:agentId/revoke`
- Owner/admin only, with a recent step-up enforced again inside the database function.
- Revocation marks the device credential inactive. A future ingestion authenticator must reject revoked device rows before accepting any telemetry.

## Database boundaries

Migration `022_endpoint_device_enrollment.sql` creates tenant-scoped endpoint inventory and one-time enrollment records. Both tables have forced RLS; direct runtime table access is revoked. Narrow SECURITY DEFINER functions expose token creation, token claim and revocation to the isolated authentication database role.

## Security limitations and next requirements

- This change does **not** add a telemetry ingestion route or middleware that validates device credentials. The issued credential is not yet usable to send events.
- The device credential is a bearer secret. A real agent must store it in the OS credential store or root/admin-readable protected storage, never in logs or command-line arguments.
- Enrollment tokens are one-time and expire after 15 minutes, but there is no UI to display or copy them yet.
- Revocation reason is validated but not yet persisted to an append-only endpoint audit log; add that before production.
- No endpoint inventory/list API, quarantine workflow, credential rotation, device re-enrollment, rate-limit telemetry, or agent heartbeat ingestion exists.
- Enrollment claim endpoint still needs IP/request rate limiting and production abuse monitoring.
- Tests and migrations are authored but have not been executed. Typecheck, build, runtime integration and CI are not verified.

Never treat enrollment success as proof of endpoint protection. The agent, secure local spool, signed updates, event ingestion and detection integration are separate deliverables.
