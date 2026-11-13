# Operator Identity and Authentication

**Status:** Tenant-bound sessions, password verification, session validation/revocation, persistent login throttling, loopback-only login/session routes, deny-by-default authorization, and authenticated threat-indicator review attribution are implemented in the repository. PostgreSQL execution and CI tests remain unverified because GitHub Actions has been unable to start a runner.

## Identity model

- An operator account is separate from a tenant membership; one operator may belong to multiple tenants.
- Roles: owner, admin, security_analyst, reviewer, viewer.
- Only active operators and active tenant memberships can create or resolve sessions.
- Session tokens are 256-bit opaque random values. PostgreSQL stores only their SHA-256 digest.
- Sessions expire within eight hours and can be revoked.
- Passwords use Node.js scrypt with a random per-password salt and fixed work parameters.
- The ordinary application DB role cannot read operator rows/password hashes or modify memberships. Authentication uses a separate `onishield_auth` database login and connection pool; it has function execution only, not direct table access.
- Membership and session tables enforce tenant row-level security.

## Implemented service boundary

- Credential and membership lookup use narrowly granted SECURITY DEFINER functions available only to the dedicated `onishield_auth` role. The application exports a separate auth pool when `AUTH_DATABASE_URL` is configured; it never falls back to the general runtime connection. Do not reuse the normal application database connection.
- Session creation verifies active operator and membership state and caps lifetime at eight hours.
- Session resolution rejects revoked/expired sessions and inactive accounts/memberships.
- Session revocation accepts only a validated opaque token and stores/uses its digest.
- Unknown-account login attempts perform dummy scrypt work to reduce account-enumeration timing differences.
- Login attempts are rate-limited in PostgreSQL by HMAC-keyed account and source-IP buckets: five attempts per 15-minute account window and 30 attempts per 15-minute source-IP window, each followed by a 15-minute lock. The account bucket resets after a successful login; the IP bucket ages out naturally. `AUTH_RATE_LIMIT_SECRET` is mandatory whenever `AUTH_DATABASE_URL` is set, preventing offline email/IP guessing from a database-only leak.
- `POST /v1/operator/login`, `GET /v1/operator/me`, and `POST /v1/operator/logout` are exposed only by the current loopback-bound Fastify process. Login responses are marked `Cache-Control: no-store` and use bearer tokens, not cookies.
- `POST /v1/threat-intelligence/:indicatorId/review` requires a validated session and review permission. PostgreSQL revalidates the session and tenant, derives the operator ID from the stored session, performs the state transition, and writes that operator UUID into the append-only audit record.
- Unit tests cover normalized login, wrong passwords, inactive accounts, absent tenant membership, session token hashing, logout, and session-bound authorization.
- Permission checks use a server-defined role/action map and deny unknown roles/actions. The auth service resolves the opaque session first, then authorizes the requested action from the persisted membership role; callers cannot supply a trusted role.

Database functions use a fixed search path, are not executable by PUBLIC, and are granted only to onishield_auth. The general onishield_app role has no execute grants on these functions. They require dedicated PostgreSQL security review before production.

## API boundary and remaining safeguards

- The current server binds to `127.0.0.1`; these endpoints are for the controlled local lab only. Do not expose them through a reverse proxy, public interface, or mobile network.
- The bearer token must be kept in process memory by a local client and never written to logs, URLs, browser local storage, or analytics. The API does not issue cookies, so cookie-based CSRF is not used.
- Before remote/browser/mobile deployment, implement TLS termination, origin/CORS policy, secure platform token storage, session rotation, step-up authentication for privileged actions, and operational monitoring.
- Account invitation, email verification, password recovery, and session/device management remain unimplemented.
- Rate-limit buckets are hashed before persistence; raw email addresses and IP addresses are not stored in the throttle table. Add scheduled cleanup/retention for old buckets before a long-running deployment.
- The existing lab connector endpoint remains separate and does not authenticate human operators.

## Authorization rules

- Derive tenant, operator, membership, and role only from a validated server-side session.
- Never trust caller-supplied actor IDs, tenant IDs, roles, community IDs, or organization IDs.
- Deny by default. UI visibility is not authorization.
- Threat-intelligence review requires reviewer permission and the separately audited database transition.
- Privileged operations require step-up authentication before production.
- Never log passwords, raw session tokens, or credential hashes.

## Release gates

1. Verify migration 006, login throttle behavior, review audit attribution, and all prior PostgreSQL/RLS smoke tests in a successful CI run.
2. Add invitation, email verification, recovery, session rotation, and device/session management.
3. Design and security-review remote browser/mobile token transport, TLS, origin policy, secure storage, and step-up authentication.
4. Replace shared lab reviewer DB identity with individually attributable reviewer accounts in the production operations model.
5. Add throttle-bucket retention cleanup, monitoring, and abuse-response procedures.
6. Pass PostgreSQL integration, RLS, migration, unit, typecheck, build, and independent security review.
