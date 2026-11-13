# Operator Identity and Authentication

**Status:** Initial identity schema and Node cryptographic primitives are committed. Login, invitation, recovery, session lifecycle endpoints, authorization middleware, and production identity provisioning are not implemented. PostgreSQL execution and unit tests remain unverified while GitHub Actions cannot allocate a runner.

## Identity model

- An operator account is separate from a tenant membership. One operator may have memberships in multiple tenants.
- Membership roles are owner, admin, security_analyst, reviewer, and viewer.
- Membership status must be active before access is granted.
- Sessions are tenant-bound, expire, and support revocation.
- The database stores only a SHA-256 digest of a high-entropy opaque session token, never the bearer token.
- Password hashes use Node.js scrypt with a random per-password salt and fixed, explicit work parameters. Passwords are never stored in plaintext.
- Password hashes and operator lifecycle records are not readable by the ordinary application database role.
- Membership and session tables have tenant RLS policies.

## Important security boundary

This is a schema and cryptographic foundation, not a working login system. Do not expose a login endpoint or accept operator identity from request headers/body based on these files alone. A complete implementation still needs a carefully scoped authentication database function/service for password verification, tenant membership selection, session creation, session lookup, expiry/revocation, rate limiting, lockout/abuse controls, CSRF strategy for browser clients, and audit events.

The current lab server authenticates only its configured connector bearer token. It does not authenticate human operators. No human operator is authorized to review threat indicators through an HTTP endpoint.

## Authorization requirements

- Derive operator, tenant, membership, and role from a validated server-side session.
- Never accept tenant ID, actor ID, role, community ID, or organization ID as authoritative caller-supplied values.
- Deny by default when the session is expired/revoked or membership is inactive.
- Enforce permissions server-side for every action; hiding UI controls is not authorization.
- Review approval/rejection/revocation requires the reviewer permission and a separate audited database path.
- Privileged actions require re-authentication or step-up authentication before production release.
- Log authentication success/failure, session creation/revocation, membership changes, and privileged actions without logging passwords or bearer tokens.

## Release gates

1. Implement authentication persistence without granting broad read access to password hashes.
2. Add rate limiting, credential stuffing defenses, account recovery, and session revocation.
3. Implement tenant-scoped authorization middleware and a permission matrix.
4. Replace shared reviewer DB login with individually attributable reviewer identities.
5. Connect authenticated identities to immutable review audit records.
6. Pass unit, integration, RLS, migration, typecheck, and build tests before enabling endpoints.
