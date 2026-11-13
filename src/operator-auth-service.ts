import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { Pool } from "pg";
import { assertOperatorPermission, type OperatorAction } from "./operator-authz.js";
import { createOperatorSessionToken, hashOperatorSessionToken, performDummyPasswordVerification, verifyOperatorPassword } from "./operator-auth-crypto.js";

export interface OperatorPrincipal { tenantId: string; operatorId: string; membershipId: string; email: string; displayName: string; role: string; }
export interface OperatorLoginResult { token: string; expiresAt: string; principal: OperatorPrincipal; }
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export class OperatorLoginRateLimitError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super("Too many login attempts");
    this.name = "OperatorLoginRateLimitError";
  }
}

function throttleKey(scope: "email" | "ip", value: string): string {
  return createHash("sha256").update(`onishield:operator-login:${scope}:${value}`).digest("hex");
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (normalized.length > 254 || !EMAIL_PATTERN.test(normalized)) throw new Error("Invalid login credentials");
  return normalized;
}

export class OperatorAuthService {
  constructor(private readonly database: Pick<Pool, "query">) {}

  private async consumeLoginLimit(key: string, maxAttempts: number): Promise<number> {
    const result = await this.database.query<{allowed:boolean;retry_after_seconds:number}>(
      "SELECT * FROM onishield.consume_operator_login_limit($1,$2,900,900)", [key, maxAttempts]);
    const row = result.rows[0];
    if (!row?.allowed) return Math.max(1, Number(row?.retry_after_seconds ?? 900));
    return 0;
  }

  async login(email: string, password: string, tenantId: string, clientIp: string): Promise<OperatorLoginResult> {
    if (password.length < 1 || password.length > 256 || tenantId.trim().length < 1 || tenantId.length > 128) throw new Error("Invalid login credentials");
    const normalizedEmail = normalizeEmail(email);
    const normalizedTenantId = tenantId.trim();
    if (!clientIp || clientIp.length > 128 || isIP(clientIp) === 0) throw new Error("Invalid login credentials");
    const emailKey = throttleKey("email", normalizedEmail);
    const ipKey = throttleKey("ip", clientIp);
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

