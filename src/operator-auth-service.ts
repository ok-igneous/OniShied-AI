import type { Pool } from "pg";
import { createOperatorSessionToken, hashOperatorSessionToken, performDummyPasswordVerification, verifyOperatorPassword } from "./operator-auth-crypto.js";

export interface OperatorPrincipal { tenantId: string; operatorId: string; membershipId: string; email: string; displayName: string; role: string; }
export interface OperatorLoginResult { token: string; expiresAt: string; principal: OperatorPrincipal; }
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (normalized.length > 254 || !EMAIL_PATTERN.test(normalized)) throw new Error("Invalid login credentials");
  return normalized;
}

export class OperatorAuthService {
  constructor(private readonly database: Pick<Pool, "query">) {}

  async login(email: string, password: string, tenantId: string): Promise<OperatorLoginResult> {
    if (password.length < 1 || password.length > 256 || tenantId.trim().length < 1 || tenantId.length > 128) throw new Error("Invalid login credentials");
    const normalizedEmail = normalizeEmail(email);
    const credentials = await this.database.query<{operator_id:string;password_hash:string;operator_status:string}>(
      "SELECT * FROM onishield.lookup_operator_credentials($1)", [normalizedEmail]);
    const account = credentials.rows[0];
    if (!account) { await performDummyPasswordVerification(password); throw new Error("Invalid login credentials"); }
    const passwordValid = await verifyOperatorPassword(password, account.password_hash);
    if (!passwordValid || account.operator_status !== "active") throw new Error("Invalid login credentials");
    const membership = await this.database.query<{membership_id:string;role:string}>(
      "SELECT * FROM onishield.lookup_operator_membership($1,$2)", [account.operator_id, tenantId]);
    const activeMembership = membership.rows[0];
    if (!activeMembership) throw new Error("Invalid login credentials");
    const token = createOperatorSessionToken();
    const tokenHash = hashOperatorSessionToken(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    await this.database.query("SELECT * FROM onishield.create_operator_session($1,$2,$3,$4,$5)",
      [tokenHash, tenantId, account.operator_id, activeMembership.membership_id, expiresAt]);
    const principal = await this.resolve(token);
    if (!principal) {
      await this.logout(token);
      throw new Error("Session creation failed");
    }
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

  async logout(token: string): Promise<void> {
    let tokenHash: string;
    try { tokenHash = hashOperatorSessionToken(token); } catch { return; }
    await this.database.query("SELECT onishield.revoke_operator_session($1)", [tokenHash]);
  }
}
