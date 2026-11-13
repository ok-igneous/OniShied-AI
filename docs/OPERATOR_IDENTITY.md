# Operator Identity and Authentication

**Status:** Resend transport and backend invitation, email-verification, and password-reset workflows are implemented in the repository. Frontend token pages, deployment configuration, PostgreSQL execution, and CI verification remain outstanding.

## Transactional email provider

- Resend is the selected transactional-email provider for invitations, email verification, and password recovery. `src/email-delivery.ts` calls the Resend HTTPS API directly with Node.js `fetch`; no SDK dependency is required.
- Configure `RESEND_API_KEY`, `EMAIL_FROM`, and `APP_PUBLIC_URL` together. The sender must be verified in Resend before real delivery. `APP_PUBLIC_URL` must point to the HTTPS web client that handles action links. None of these values belongs in Git.
- The adapter enforces recipient/subject validation, payload bounds, a 10-second request timeout, Resend idempotency keys, and sanitized provider errors. It never logs or returns the API key or provider response body.
- The backend routes use hashed one-use tokens, database-enforced expiry/consumption, account-enumeration resistance, rate limits, and audit records. The web pages that capture link fragments and call the confirmation endpoints are not included yet.

## Account lifecycle through Resend

- Configure `RESEND_API_KEY`, `EMAIL_FROM`, and `APP_PUBLIC_URL` together. `EMAIL_FROM` must be a sender/domain verified in Resend. `APP_PUBLIC_URL` is the HTTPS origin of the web client that hosts `/operator/accept-invitation`, `/operator/verify-email`, and `/operator/reset-password`.
- Invitation creation requires an authenticated owner or admin. Owners may invite admin, analyst, reviewer, or viewer roles; admins may invite analyst, reviewer, or viewer roles. Invitations expire after 48 hours. Acceptance creates the operator and active tenant membership in one database transaction and marks the invited address verified.
- Existing unverified active accounts can request email verification. Verification tokens expire after 30 minutes and are consumed once. Login rejects accounts whose email is not verified; the verification-request endpoint returns the same response whether an account exists or not.
- Password-reset requests are available only for active, verified accounts. Responses are generic to prevent account enumeration. Reset tokens expire after 30 minutes, are consumed atomically, and revoke every active session for that operator.
- Raw action tokens are 256-bit random values delivered only in email links as URL fragments (`#token=...`), not query parameters. The web client must read the fragment and POST the token to the matching API confirmation endpoint; fragments are not sent in HTTP requests or referrer headers. PostgreSQL stores only HMAC-SHA256 digests using `MFA_RECOVERY_PEPPER`.
- The database records invitation creation/acceptance, email verification, and password-reset request/completion events in `operator_account_audit`. Email action rows and audit rows are inaccessible directly to application/auth roles; only narrowly granted SECURITY DEFINER functions can operate on them.
- Email verification and password-reset requests are rate-limited by HMAC-keyed email and source-IP buckets. Resend provider failures on these generic endpoints are deliberately not reflected to callers, preserving account-enumeration resistance. Invitation delivery failures return an error to the authenticated inviter; retrying creates a new invitation and invalidates prior unused invitations for that recipient and tenant.
- The API backend is implemented, but the web pages that capture fragment tokens and call the confirmation endpoints are not part of this repository yet. Do not send production invitations until those pages are deployed and tested.

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
- `POST /v1/operator/invitations` (owner/admin only), `POST /v1/operator/invitations/accept`, `POST /v1/operator/email/verification/request`, `POST /v1/operator/email/verification/confirm`, `POST /v1/operator/password-reset/request`, and `POST /v1/operator/password-reset/confirm` provide the account lifecycle API. `POST /v1/operator/login`, `GET /v1/operator/me`, `POST /v1/operator/logout`, `POST /v1/operator/rotate`, `GET /v1/operator/sessions`, and `DELETE /v1/operator/sessions/:sessionId` are exposed only by the current loopback-bound Fastify process. Login and rotation responses are marked `Cache-Control: no-store` and use bearer tokens, not cookies.
- Session rotation is atomic in PostgreSQL: the current token is row-locked, revoked, and replaced in the same transaction. Privileged review and other-session revocation also row-lock the authorizing session so a completed revocation cannot race through an already-started privileged action. The API lists at most 50 session metadata records for the authenticated operator in the active tenant; it never returns token digests. An operator may revoke another session belonging to the same operator and tenant, but cannot revoke the session used to authorize that request.
- `POST /v1/operator/step-up` re-verifies the current password and, when MFA is enrolled, requires a valid TOTP code. A separate five-attempt/15-minute HMAC-keyed throttle applies. PostgreSQL atomically consumes a strictly increasing TOTP time-step counter and marks only that session stepped up for five minutes.
- TOTP enrollment uses `POST /v1/operator/mfa/enroll` after password reauthentication, followed by `POST /v1/operator/mfa/confirm`. Pending enrollment expires after 10 minutes. The secret is returned once with an `otpauth://` URI and is encrypted with AES-256-GCM before database storage. `MFA_ENCRYPTION_KEY` is a dedicated 32-byte key, separate from the rate-limit secret.
- Enrolled accounts must complete TOTP after password login through `POST /v1/operator/login/verify`; the password phase returns only a five-minute, one-use challenge, not a session. PostgreSQL consumes the challenge and TOTP counter atomically. Ten 128-bit one-use recovery codes are generated at enrollment; only peppered HMAC digests are stored, and raw codes are returned once with `Cache-Control: no-store`. A recovery code can replace TOTP for one login or one password-verified step-up, is atomically consumed, and is audited. If an authenticator is lost, use one code to log in and a different unused code for password-verified step-up before disabling and re-enrolling MFA. Password-only step-up is rejected for owner, admin, and reviewer roles until MFA is enrolled.
- `DELETE /v1/operator/mfa` disables MFA only after current-password and TOTP reauthentication. Enrollment, activation, disablement, successful MFA login, and MFA step-up are recorded in a restricted database audit table.
- `POST /v1/threat-intelligence/:indicatorId/review` requires a validated session, review permission, and step-up completed within the preceding five minutes. PostgreSQL independently revalidates the session and step-up timestamp, derives the operator ID from the stored session, performs the state transition, and writes that operator UUID into the append-only audit record.
- Unit tests cover normalized login, wrong passwords, inactive accounts, absent tenant membership, session token hashing, logout, and session-bound authorization.
- Permission checks use a server-defined role/action map and deny unknown roles/actions. The auth service resolves the opaque session first, then authorizes the requested action from the persisted membership role; callers cannot supply a trusted role.

Database functions use a fixed search path, are not executable by PUBLIC, and are granted only to onishield_auth. The general onishield_app role has no execute grants on these functions. They require dedicated PostgreSQL security review before production.

## Local API contract

The routes are available only when `AUTH_DATABASE_URL` (the dedicated `onishield_auth` login), a separate random `AUTH_RATE_LIMIT_SECRET` of at least 32 characters, `MFA_ENCRYPTION_KEY` (exactly 32 random bytes encoded as 64 hex characters), and a separate random `MFA_RECOVERY_PEPPER` of at least 32 characters are configured.

- `POST /v1/operator/login` accepts JSON `{ "email": "...", "password": "...", "tenantId": "..." }`. Non-enrolled accounts receive a session; enrolled accounts receive an MFA challenge and no session token.
- `POST /v1/operator/login/verify` accepts `{ "challengeToken": "...", "code": "123456" }` for TOTP or a 32-character recovery code and returns a session only after one factor is atomically consumed.
- `POST /v1/operator/mfa/enroll` accepts a bearer token and `{ "password": "..." }`; it returns a one-time secret and authenticator URI. Add the secret to an authenticator app, then confirm it.
- `POST /v1/operator/mfa/confirm` accepts `{ "code": "123456" }`, activates the pending secret, and returns ten recovery codes once. Store them offline; they cannot be retrieved later.
- `DELETE /v1/operator/mfa` accepts `{ "password": "...", "code": "123456" }`; a TOTP or unused recovery code is required with the password to disable MFA.
- `GET /v1/operator/me` accepts `Authorization: Bearer <token>` and returns the current principal.
- `POST /v1/operator/logout` accepts the same bearer header and revokes the session.
- `POST /v1/operator/step-up` accepts `Authorization: Bearer <token>` and `{ "password": "...", "code": "123456" }` when MFA is enrolled; successful reauthentication authorizes sensitive review for five minutes.
- `POST /v1/threat-intelligence/:indicatorId/review` accepts `{ "status": "active|rejected|revoked|expired", "reason": "..." }` and requires the bearer token. Tenant and actor identity are derived from the session, never from the request body.

Example login request:

```http
POST /v1/operator/login
Content-Type: application/json

{"email":"reviewer@example.test","password":"<password>","tenantId":"tenant-a"}
```

The example is a contract illustration only; no seeded production operator or password exists.

## API boundary and remaining safeguards

- The current server binds to `127.0.0.1`; these endpoints are for the controlled local lab only. Do not expose them through a reverse proxy, public interface, or mobile network.
- The bearer token must be kept in process memory by a local client and never written to logs, URLs, browser local storage, or analytics. The API does not issue cookies, so cookie-based CSRF is not used.
- Before remote/browser/mobile deployment, implement TLS termination, strict origin/CORS policy, secure platform token storage, deployment-specific abuse controls, and operational monitoring. The present API is intentionally loopback-only.
- Session device labels and step-up for actions other than threat-indicator review remain unimplemented. TOTP and one-use recovery codes are implemented for enrolled accounts. Recovery codes are shown only once at enrollment, are stored as peppered HMAC digests, and are consumed atomically on login or password-verified step-up. Session inventory, rotation, revocation, and password reauthentication for threat-indicator review are implemented; device fingerprinting is deliberately not inferred from untrusted user-agent strings.
- Rate-limit buckets are HMAC-keyed before persistence; raw email addresses and IP addresses are not stored in the throttle table. `database/maintenance/cleanup_operator_login_limits.sql` deletes expired MFA login challenges older than one day and throttle buckets untouched for 30 days; schedule it daily with the deployment's trusted database maintenance runner.
- Back up `MFA_ENCRYPTION_KEY` and `MFA_RECOVERY_PEPPER` in a dedicated secret manager. Losing the encryption key makes existing TOTP secrets unusable; losing the recovery pepper invalidates all outstanding recovery codes. Key rotation with re-encryption/re-hashing is a production release gate. Recovery codes are 128-bit random values and are stored only as peppered HMAC digests.
- The existing lab connector endpoint remains separate and does not authenticate human operators.

## Authorization rules

- Derive tenant, operator, membership, and role only from a validated server-side session.
- Never trust caller-supplied actor IDs, tenant IDs, roles, community IDs, or organization IDs.
- Deny by default. UI visibility is not authorization.
- Threat-intelligence review requires reviewer permission and the separately audited database transition.
- Privileged operations require step-up authentication before production.
- Never log passwords, raw session tokens, or credential hashes.

## Release gates

1. Verify migrations 006–012, MFA enrollment/login/step-up/disable flows, TOTP replay prevention, recovery-code one-use consumption, challenge expiry and one-use behavior, MFA audit records, five-minute review step-up expiry, session lifecycle, and all PostgreSQL/RLS smoke tests in a successful CI run.
2. Deploy and test the web pages for invitation acceptance, email verification, and password reset. Configure a verified Resend sender and HTTPS `APP_PUBLIC_URL`; add delivery monitoring and a support-safe account recovery process. Define encryption-key rotation and backup/restore procedures before production.
3. Design and security-review remote browser/mobile token transport, TLS, origin policy, secure storage, and step-up authentication.
4. Replace shared lab reviewer DB identity with individually attributable reviewer accounts in the production operations model.
5. Schedule the 30-day throttle-bucket cleanup, add monitoring, and document abuse-response procedures.
6. Verify Resend delivery, link handling, action-token expiry/one-use behavior, generic account-enumeration responses, rate limits, and audit records. Never return raw action tokens in public API responses.
7. Pass PostgreSQL integration, RLS, migration, unit, typecheck, build, and independent security review.
