# Operator Identity and Authentication

**Status:** Tenant-bound session persistence, credential lookup, password verification, session validation/revocation, and a deny-by-default permission map are implemented. Human login HTTP routes remain disabled. PostgreSQL execution and CI tests remain unverified because GitHub Actions has been unable to start a runner.

## Identity model

- An operator account is separate from a tenant membership; one operator may belong to multiple tenants.
- Roles: owner, admin, security_analyst, reviewer, viewer.
- Only active operators and active tenant memberships can create or resolve sessions.
- Session tokens are 256-bit opaque random values. PostgreSQL stores only their SHA-256 digest.
- Sessions expire within eight hours and can be revoked.
- Passwords use Node.js scrypt with a random per-password salt and fixed work parameters.
- The ordinary application DB role cannot read operator rows/password hashes or modify memberships.
- Membership and session tables enforce tenant row-level security.

## Implemented service boundary

- Credential and membership lookup use narrowly granted SECURITY DEFINER functions.
- Session creation verifies active operator and membership state and caps lifetime at eight hours.
- Session resolution rejects revoked/expired sessions and inactive accounts/memberships.
- Session revocation accepts only a validated opaque token and stores/uses its digest.
- Unknown-account login attempts perform dummy scrypt work to reduce account-enumeration timing differences.
- Permission checks use a server-defined role/action map and deny unknown roles/actions.

Database functions use a fixed search path, are not executable by PUBLIC, and are granted only to onishield_app. They require dedicated PostgreSQL security review before production.

## Deliberately not exposed

There is no public login/logout HTTP endpoint. Persistent rate limits, credential-stuffing defenses, account recovery, secure browser/mobile token transport, CSRF policy, and authentication audit integration must be completed first. The existing lab connector endpoint remains separate and does not authenticate human operators.

## Authorization rules

- Derive tenant, operator, membership, and role only from a validated server-side session.
- Never trust caller-supplied actor IDs, tenant IDs, roles, community IDs, or organization IDs.
- Deny by default. UI visibility is not authorization.
- Threat-intelligence review requires reviewer permission and the separately audited database transition.
- Privileged operations require step-up authentication before production.
- Never log passwords, raw session tokens, or credential hashes.

## Release gates

1. Add persistent login rate limits and credential-stuffing defenses.
2. Add invitation, email verification, recovery, and session rotation.
3. Decide secure browser/mobile token transport and CSRF protections.
4. Replace shared lab reviewer DB identity with individually attributable reviewers.
5. Connect operator IDs to immutable review audit records.
6. Pass PostgreSQL integration, RLS, migration, unit, typecheck, build, and security review.
