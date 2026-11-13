import { createHmac } from "node:crypto";
import { decryptMfaSecret, encryptMfaSecret } from "./operator-mfa-crypto.js";
import { encodeBase32, generateTotpSecret, verifyTotp } from "./operator-mfa-totp.js";
import { isIP } from "node:net";
import type { Pool } from "pg";
import { assertOperatorPermission, type OperatorAction } from "./operator-authz.js";
import { createOperatorSessionToken, hashOperatorSessionToken, performDummyPasswordVerification, verifyOperatorPassword } from "./operator-auth-crypto.js";

export interface OperatorPrincipal { tenantId: string; operatorId: string; membershipId: string; email: string; displayName: string; role: string; }
export interface OperatorLoginResult { token: string; expiresAt: string; principal: OperatorPrincipal; }
export interface OperatorMfaChallengeResult { mfaRequired: true; challengeToken: string; expiresAt: string; }
export interface OperatorSessionInfo {
  sessionId: string; createdAt: string; expiresAt: string;
  lastSeenAt: string; revokedAt: string | null; current: boolean;
}
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export class OperatorLoginRateLimitError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super("Too many login attempts");
    this.name = "OperatorLoginRateLimitError";
  }
}

function throttleKey(secret: string, scope: "email" | "ip", value: string): string {
  return createHmac("sha256", secret).update(`onishield:operator-login:${scope}:${value}`).digest("hex");
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (normalized.length > 254 || !EMAIL_PATTERN.test(normalized)) throw new Error("Invalid login credentials");
  return normalized;
}

export class OperatorAuthService {
  constructor(
    private readonly database: Pick<Pool, "query">,
    private readonly rateLimitSecret: string,
    private readonly mfaEncryptionKey: string
  ) {
    if (rateLimitSecret.length < 32) throw new Error("AUTH_RATE_LIMIT_SECRET must contain at least 32 characters");
    if (!/^[a-fA-F0-9]{64}$/.test(mfaEncryptionKey)) {
      throw new Error("MFA_ENCRYPTION_KEY must contain exactly 32 bytes encoded as hex");
    }
  }

  private async consumeLoginLimit(key: string, maxAttempts: number): Promise<number> {
    const result = await this.database.query<{allowed:boolean;retry_after_seconds:number}>(
      "SELECT * FROM onishield.consume_operator_login_limit($1,$2,900,900)", [key, maxAttempts]);
    const row = result.rows[0];
    if (!row?.allowed) return Math.max(1, Number(row?.retry_after_seconds ?? 900));
    return 0;
  }

  async login(email: string, password: string, tenantId: string, clientIp: string): Promise<OperatorLoginResult | OperatorMfaChallengeResult> {
    if (password.length < 1 || password.length > 256 || tenantId.trim().length < 1 || tenantId.length > 128) throw new Error("Invalid login credentials");
    const normalizedEmail = normalizeEmail(email);
    const normalizedTenantId = tenantId.trim();
    if (!clientIp || clientIp.length > 128 || isIP(clientIp) === 0) throw new Error("Invalid login credentials");
    const emailKey = throttleKey(this.rateLimitSecret, "email", normalizedEmail);
    const ipKey = throttleKey(this.rateLimitSecret, "ip", clientIp);
    const limits = await Promise.all([
      this.consumeLoginLimit(emailKey, 5),
      this.consumeLoginLimit(ipKey, 30)
    ]);
    const retryAfter = Math.max(...limits);
    if (retryAfter > 0) throw new OperatorLoginRateLimitError(retryAfter);
    const credentials = await this.database.query<{operator_id:string;password_hash:string;operator_status:string}>(
      "SELECT * FROM onishield.lookup_operator_credentials($1)", [normalizedEmail]);
    const account = credentials.rows[0];
    if (!account) { await performDummyPasswordVerification(password); throw new Error("Invalid login credentials"); }
    const passwordValid = await verifyOperatorPassword(password, account.password_hash);
    if (!passwordValid || account.operator_status !== "active") throw new Error("Invalid login credentials");
    const membership = await this.database.query<{membership_id:string;role:string}>(
      "SELECT * FROM onishield.lookup_operator_membership($1,$2)", [account.operator_id, normalizedTenantId]);
    const activeMembership = membership.rows[0];
    if (!activeMembership) throw new Error("Invalid login credentials");
    const mfaState = await this.database.query<{enabled:boolean}>(
      "SELECT enabled FROM onishield.get_operator_mfa($1)", [account.operator_id]
    );
    if (mfaState.rows[0]?.enabled) {
      const challengeToken = createOperatorSessionToken();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
      await this.database.query(
        "SELECT onishield.create_operator_login_challenge($1,$2,$3,$4,$5)",
        [hashOperatorSessionToken(challengeToken), normalizedTenantId, account.operator_id,
          activeMembership.membership_id, expiresAt]
      );
      return { mfaRequired: true, challengeToken, expiresAt: expiresAt.toISOString() };
    }
    const token = createOperatorSessionToken();
    const tokenHash = hashOperatorSessionToken(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    await this.database.query("SELECT * FROM onishield.create_operator_session($1,$2,$3,$4,$5)",
      [tokenHash, normalizedTenantId, account.operator_id, activeMembership.membership_id, expiresAt]);
    const principal = await this.resolve(token);
    if (!principal) {
      await this.logout(token);
      throw new Error("Session creation failed");
    }
    await this.database.query("SELECT onishield.reset_operator_login_limit($1)", [emailKey]);
    return { token, expiresAt: expiresAt.toISOString(), principal };
  }

  async completeMfaLogin(challengeToken: string, code: string): Promise<OperatorLoginResult> {
    const challengeHash = hashOperatorSessionToken(challengeToken);
    const bucket = throttleKey(this.rateLimitSecret, "email", `mfa-login:${challengeHash}`);
    const retryAfter = await this.consumeLoginLimit(bucket, 5);
    if (retryAfter > 0) throw new OperatorLoginRateLimitError(retryAfter);
    const challenge = await this.database.query<{operator_id:string}>(
      "SELECT * FROM onishield.get_operator_login_challenge($1)", [challengeHash]
    );
    const operatorId = challenge.rows[0]?.operator_id;
    if (!operatorId) throw new Error("Invalid MFA challenge");
    const credential = await this.database.query<{
      enabled:boolean;ciphertext:Buffer;nonce:Buffer;auth_tag:Buffer
    }>("SELECT * FROM onishield.get_operator_mfa($1)", [operatorId]);
    const row = credential.rows[0];
    if (!row?.enabled || !row.ciphertext || !row.nonce || !row.auth_tag) {
      throw new Error("Invalid MFA challenge");
    }
    const secret = decryptMfaSecret({
      ciphertext:row.ciphertext, nonce:row.nonce, authTag:row.auth_tag
    }, this.mfaEncryptionKey);
    const counter = verifyTotp(secret, code, Date.now());
    if (counter === null) throw new Error("Invalid MFA code");
    const token = createOperatorSessionToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    const consumed = await this.database.query(
      "SELECT * FROM onishield.consume_operator_login_challenge($1,$2,$3,$4)",
      [challengeHash, counter, hashOperatorSessionToken(token), expiresAt]
    );
    if (consumed.rowCount !== 1) throw new Error("Invalid MFA challenge");
    const principal = await this.resolve(token);
    if (!principal) {
      await this.logout(token);
      throw new Error("MFA session creation failed");
    }
    await this.database.query("SELECT onishield.reset_operator_login_limit($1)", [bucket]);
    await this.database.query("SELECT onishield.reset_operator_login_limit($1)", [throttleKey(this.rateLimitSecret,"email",principal.email)]);
    return { token, expiresAt:expiresAt.toISOString(), principal };
  }

  async beginMfaEnrollment(token: string, password: string): Promise<{secret:string;otpauthUrl:string}> {
    const principal = await this.resolve(token);
    if (!principal) throw new Error("unauthorized");
    if (password.length < 1 || password.length > 256) throw new Error("Invalid step-up credentials");
    const bucket = throttleKey(this.rateLimitSecret,"email",`mfa-enroll-stepup:${principal.operatorId}`);
    const retryAfter = await this.consumeLoginLimit(bucket,5);
    if (retryAfter > 0) throw new OperatorLoginRateLimitError(retryAfter);
    const credentials = await this.database.query<{password_hash:string;operator_status:string}>(
      "SELECT * FROM onishield.lookup_operator_credentials($1)",[principal.email]
    );
    const account = credentials.rows[0];
    if (account?.operator_status !== "active" ||
        !await verifyOperatorPassword(password,account.password_hash)) {
      throw new Error("Invalid step-up credentials");
    }
    const enrollmentStepUp = await this.database.query<{marked:boolean}>(
      "SELECT onishield.mark_operator_session_mfa_enrollment_step_up($1) AS marked",
      [hashOperatorSessionToken(token)]
    );
    if (enrollmentStepUp.rows[0]?.marked !== true) throw new Error("unauthorized");
    const secret = generateTotpSecret();
    const encrypted = encryptMfaSecret(secret, this.mfaEncryptionKey);
    const stored = await this.database.query<{stored:boolean}>(
      "SELECT onishield.store_pending_operator_mfa($1,$2,$3,$4) AS stored",
      [hashOperatorSessionToken(token), encrypted.ciphertext, encrypted.nonce, encrypted.authTag]
    );
    if (stored.rows[0]?.stored !== true) throw new Error("MFA enrollment could not be started");
    await this.database.query("SELECT onishield.reset_operator_login_limit($1)",[bucket]);
    const label = encodeURIComponent(`OniShield AI:${principal.email}`);
    const issuer = encodeURIComponent("OniShield AI");
    return { secret, otpauthUrl:`otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` };
  }

  async confirmMfaEnrollment(token: string, code: string): Promise<void> {
    const principal = await this.resolve(token);
    if (!principal) throw new Error("unauthorized");
    const bucket = throttleKey(this.rateLimitSecret, "email", `mfa-enroll:${principal.operatorId}`);
    const retryAfter = await this.consumeLoginLimit(bucket, 5);
    if (retryAfter > 0) throw new OperatorLoginRateLimitError(retryAfter);
    const pending = await this.database.query<{ciphertext:Buffer;nonce:Buffer;auth_tag:Buffer}>(
      "SELECT * FROM onishield.get_pending_operator_mfa($1)", [hashOperatorSessionToken(token)]
    );
    const row = pending.rows[0];
    if (!row) throw new Error("MFA enrollment is not pending");
    const secret = decryptMfaSecret({
      ciphertext:row.ciphertext,nonce:row.nonce,authTag:row.auth_tag
    },this.mfaEncryptionKey);
    const counter = verifyTotp(secret,code,Date.now());
    if (counter === null) throw new Error("Invalid MFA code");
    const activated = await this.database.query<{activated:boolean}>(
      "SELECT onishield.activate_operator_mfa($1,$2) AS activated",
      [hashOperatorSessionToken(token),counter]
    );
    if (activated.rows[0]?.activated !== true) throw new Error("MFA enrollment could not be activated");
    await this.database.query("SELECT onishield.reset_operator_login_limit($1)",[bucket]);
  }

  async disableMfa(token: string, password: string, code: string): Promise<void> {
    await this.stepUp(token,password,code);
    const result = await this.database.query<{disabled:boolean}>(
      "SELECT onishield.disable_operator_mfa($1) AS disabled",[hashOperatorSessionToken(token)]
    );
    if (result.rows[0]?.disabled !== true) throw new Error("MFA disable failed");
  }

  async resolve(token: string): Promise<OperatorPrincipal | null> {
    let tokenHash: string;
    try { tokenHash = hashOperatorSessionToken(token); } catch { return null; }
    const result = await this.database.query<{tenant_id:string;operator_id:string;membership_id:string;operator_email:string;display_name:string;role:string}>(
      "SELECT * FROM onishield.resolve_operator_session($1)", [tokenHash]);
    const row = result.rows[0];
    if (!row) return null;
    return { tenantId:row.tenant_id, operatorId:row.operator_id, membershipId:row.membership_id, email:row.operator_email, displayName:row.display_name, role:row.role };
  }

  /** Resolve identity from the opaque session, then enforce the server-side role map. */
  async authorize(token: string, action: OperatorAction): Promise<OperatorPrincipal> {
    const principal = await this.resolve(token);
    if (!principal) throw new Error("unauthorized");
    assertOperatorPermission(principal.role, action);
    return principal;
  }

  async rotate(token: string): Promise<OperatorLoginResult> {
    const currentHash = hashOperatorSessionToken(token);
    const replacementToken = createOperatorSessionToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    const rotated = await this.database.query(
      "SELECT * FROM onishield.rotate_operator_session($1,$2,$3)",
      [currentHash, hashOperatorSessionToken(replacementToken), expiresAt]
    );
    if (rotated.rowCount !== 1) throw new Error("Session rotation failed");
    const principal = await this.resolve(replacementToken);
    if (!principal) throw new Error("Rotated session could not be validated");
    return { token: replacementToken, expiresAt: expiresAt.toISOString(), principal };
  }

  async listSessions(token: string): Promise<OperatorSessionInfo[]> {
    const tokenHash = hashOperatorSessionToken(token);
    const result = await this.database.query<{
      session_id: string; created_at: Date | string; expires_at: Date | string;
      last_seen_at: Date | string; revoked_at: Date | string | null; is_current: boolean;
    }>("SELECT * FROM onishield.list_operator_sessions($1)", [tokenHash]);
    return result.rows.map((row) => ({
      sessionId: row.session_id,
      createdAt: new Date(row.created_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(),
      lastSeenAt: new Date(row.last_seen_at).toISOString(),
      revokedAt: row.revoked_at ? new Date(row.revoked_at).toISOString() : null,
      current: row.is_current
    }));
  }

  async revokeOtherSession(token: string, sessionId: string): Promise<boolean> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionId)) {
      throw new Error("Invalid session ID");
    }
    const tokenHash = hashOperatorSessionToken(token);
    const result = await this.database.query<{ revoked: boolean }>(
      "SELECT onishield.revoke_operator_session_by_id($1,$2) AS revoked",
      [tokenHash, sessionId]
    );
    return result.rows[0]?.revoked === true;
  }

  async stepUp(token: string, password: string, code?: string): Promise<{validForSeconds: number}> {
    const principal = await this.resolve(token);
    if (!principal) throw new Error("unauthorized");
    if (password.length < 1 || password.length > 256) throw new Error("Invalid step-up credentials");
    const bucket = throttleKey(this.rateLimitSecret, "email", `step-up:${principal.operatorId}`);
    const retryAfter = await this.consumeLoginLimit(bucket, 5);
    if (retryAfter > 0) throw new OperatorLoginRateLimitError(retryAfter);
    const credentials = await this.database.query<{password_hash:string;operator_status:string}>(
      "SELECT * FROM onishield.lookup_operator_credentials($1)", [principal.email]
    );
    const account = credentials.rows[0];
    const valid = account?.operator_status === "active" && account.password_hash
      ? await verifyOperatorPassword(password, account.password_hash)
      : false;
    if (!valid) throw new Error("Invalid step-up credentials");
    const mfaState = await this.database.query<{
      enabled:boolean;ciphertext:Buffer;nonce:Buffer;auth_tag:Buffer
    }>("SELECT * FROM onishield.get_operator_mfa($1)",[principal.operatorId]);
    let counter: number | null = null;
    if (mfaState.rows[0]?.enabled) {
      const row = mfaState.rows[0];
      if (!code || !row.ciphertext || !row.nonce || !row.auth_tag) {
        throw new Error("MFA code required");
      }
      const secret = decryptMfaSecret({
        ciphertext:row.ciphertext,nonce:row.nonce,authTag:row.auth_tag
      },this.mfaEncryptionKey);
      counter = verifyTotp(secret,code,Date.now());
      if (counter === null) throw new Error("Invalid step-up credentials");
    } else if (code !== undefined) {
      throw new Error("Invalid step-up credentials");
    }
    const marked = await this.database.query<{marked:boolean}>(
      "SELECT onishield.mark_operator_session_step_up($1,$2) AS marked",
      [hashOperatorSessionToken(token),counter]
    );
    if (marked.rows[0]?.marked !== true) throw new Error("unauthorized");
    await this.database.query("SELECT onishield.reset_operator_login_limit($1)", [bucket]);
    return {validForSeconds: 300};
  }

  async reviewThreatIndicator(
    token: string,
    indicatorId: number,
    newStatus: "active" | "rejected" | "revoked" | "expired",
    reason: string
  ): Promise<{indicatorId:number;oldStatus:string;newStatus:string;actorOperatorId:string;changedAt:string}> {
    const principal = await this.authorize(token, "threat-intelligence:review");
    if (!Number.isSafeInteger(indicatorId) || indicatorId < 1 ||
        reason.trim().length < 10 || reason.length > 1000) {
      throw new Error("Invalid review request");
    }
    const tokenHash = hashOperatorSessionToken(token);
    const result = await this.database.query<{
      indicator_id:string;old_status:string;new_status:string;
      actor_operator_id:string;changed_at:Date|string
    }>(
      "SELECT * FROM onishield.review_threat_indicator($1,$2,$3,$4)",
      [tokenHash, indicatorId, newStatus, reason]
    );
    const row = result.rows[0];
    if (!row || row.actor_operator_id !== principal.operatorId) {
      throw new Error("Threat indicator review failed");
    }
    return {
      indicatorId: Number(row.indicator_id),
      oldStatus: row.old_status,
      newStatus: row.new_status,
      actorOperatorId: row.actor_operator_id,
      changedAt: (row.changed_at instanceof Date ? row.changed_at : new Date(row.changed_at)).toISOString()
    };
  }

  async logout(token: string): Promise<void> {
    let tokenHash: string;
    try { tokenHash = hashOperatorSessionToken(token); } catch { return; }
    await this.database.query("SELECT onishield.revoke_operator_session($1)", [tokenHash]);
  }
}

