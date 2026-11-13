import { createHmac, randomBytes } from "node:crypto";
import type { Pool } from "pg";
import { hashOperatorPassword, hashOperatorSessionToken } from "./operator-auth-crypto.js";
import type { EmailDelivery } from "./email-delivery.js";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
type InviteRole = "admin" | "security_analyst" | "reviewer" | "viewer";

function normalizeEmail(value: string): string {
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !EMAIL_PATTERN.test(email)) throw new Error("Invalid email address");
  return email;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character] ?? character);
}

export class OperatorAccountLifecycle {
  constructor(
    private readonly database: Pick<Pool, "query">,
    private readonly email: EmailDelivery,
    private readonly rateLimitSecret: string,
    private readonly tokenPepper: string,
    private readonly publicUrl: string
  ) {
    if (rateLimitSecret.length < 32 || tokenPepper.length < 32) {
      throw new Error("Account lifecycle secrets must contain at least 32 characters");
    }
    const base = new URL(publicUrl);
    if (base.protocol !== "https:" && base.hostname !== "localhost" && base.hostname !== "127.0.0.1") {
      throw new Error("APP_PUBLIC_URL must use HTTPS outside localhost");
    }
  }

  private newToken(): { raw: string; digest: string } {
    const raw = randomBytes(32).toString("base64url");
    const digest = createHmac("sha256", this.tokenPepper)
      .update(`onishield:operator-email-action:v1:${raw}`).digest("hex");
    return { raw, digest };
  }

  private bucket(scope: "email" | "ip", value: string): string {
    return createHmac("sha256", this.rateLimitSecret)
      .update(`onishield:operator-email-action:${scope}:${value}`).digest("hex");
  }

  private async rateLimit(email: string, ip: string, maxAttempts = 5): Promise<void> {
    const keys = [this.bucket("email", email), this.bucket("ip", ip)];
    const results = await Promise.all(keys.map((key) =>
      this.database.query<{ allowed: boolean; retry_after_seconds: number }>(
        "SELECT * FROM onishield.consume_operator_login_limit($1,$2,900,900)", [key, maxAttempts]
      )
    ));
    const blocked = results.map((result) => result.rows[0])
      .find((row) => !row?.allowed);
    if (blocked) throw new Error("Account action rate limited");
  }

  private async sendAction(
    to: string, actionId: string, kind: "invitation" | "verification" | "password-reset",
    token: string, displayName?: string
  ): Promise<void> {
    const paths = {
      invitation: "/operator/accept-invitation",
      verification: "/operator/verify-email",
      "password-reset": "/operator/reset-password"
    };
    const link = new URL(paths[kind], this.publicUrl);
    link.hash = new URLSearchParams({ token }).toString();
    const greeting = displayName ? `Hello ${escapeHtml(displayName)},` : "Hello,";
    const descriptions = {
      invitation: "You have been invited to join an OniShield AI security team.",
      verification: "Confirm that this email address belongs to your OniShield AI account.",
      "password-reset": "A password reset was requested for your OniShield AI account."
    };
    const subjects = {
      invitation: "Your OniShield AI invitation",
      verification: "Verify your OniShield AI email",
      "password-reset": "Reset your OniShield AI password"
    };
    const actionText = {
      invitation: "Accept invitation",
      verification: "Verify email",
      "password-reset": "Reset password"
    };
    const expiry = kind === "invitation" ? "48 hours" : "30 minutes";
    await this.email.send({
      to, subject: subjects[kind],
      html: `<p>${greeting}</p><p>${descriptions[kind]}</p><p><a href="${escapeHtml(link.toString())}">${actionText[kind]}</a></p><p>This link expires in ${expiry}. If you did not expect this message, ignore it.</p>`,
      text: `${greeting}\n\n${descriptions[kind]}\n\n${actionText[kind]}: ${link.toString()}\n\nThis link expires in ${expiry}. If you did not expect this message, ignore it.`,
      idempotencyKey: `operator-${kind}/${actionId}`
    });
  }

  async createInvitation(
    sessionToken: string, input: { email: string; displayName: string; role: InviteRole }, ip: string
  ): Promise<void> {
    const email = normalizeEmail(input.email);
    const displayName = input.displayName.trim();
    if (displayName.length < 1 || displayName.length > 120) throw new Error("Invalid display name");
    await this.rateLimit(email, ip, 20);
    const token = this.newToken();
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
    const result = await this.database.query<{ action_id: string; recipient_email: string }>(
      "SELECT * FROM onishield.create_operator_invitation($1,$2,$3,$4,$5,$6)",
      [hashOperatorSessionToken(sessionToken), email, displayName, input.role, token.digest, expiresAt]
    );
    const row = result.rows[0];
    if (!row) throw new Error("Invitation could not be created");
    await this.sendAction(row.recipient_email, row.action_id, "invitation", token.raw, displayName);
  }

  async requestEmailVerification(emailInput: string, ip: string): Promise<void> {
    const email = normalizeEmail(emailInput);
    await this.rateLimit(email, ip);
    const token = this.newToken();
    const result = await this.database.query<{ action_id: string; recipient_email: string }>(
      "SELECT * FROM onishield.request_operator_email_verification($1,$2,$3)",
      [email, token.digest, new Date(Date.now() + 30 * 60 * 1000)]
    );
    const row = result.rows[0];
    if (row) {
      try { await this.sendAction(row.recipient_email, row.action_id, "verification", token.raw); }
      catch { /* Keep account-existence and provider status indistinguishable to callers. */ }
    }
  }

  async requestPasswordReset(emailInput: string, ip: string): Promise<void> {
    const email = normalizeEmail(emailInput);
    await this.rateLimit(email, ip);
    const token = this.newToken();
    const result = await this.database.query<{ action_id: string; recipient_email: string }>(
      "SELECT * FROM onishield.request_operator_password_reset($1,$2,$3)",
      [email, token.digest, new Date(Date.now() + 30 * 60 * 1000)]
    );
    const row = result.rows[0];
    if (row) {
      try { await this.sendAction(row.recipient_email, row.action_id, "password-reset", token.raw); }
      catch { /* Keep account-existence and provider status indistinguishable to callers. */ }
    }
  }

  async acceptInvitation(rawToken: string, password: string, ip: string): Promise<{ email: string; displayName: string; tenantId: string; role: string }> {
    if (password.length < 12 || password.length > 256) throw new Error("Password must contain between 12 and 256 characters");
    const token = this.tokenDigest(rawToken);
    await this.rateLimit(`action:${token}`, ip);
    const passwordHash = await hashOperatorPassword(password);
    const result = await this.database.query<{
      email: string; display_name: string; tenant_id: string; role: string;
    }>("SELECT * FROM onishield.accept_operator_invitation($1,$2)", [token, passwordHash]);
    const row = result.rows[0];
    if (!row) throw new Error("Invalid or expired invitation");
    return { email: row.email, displayName: row.display_name, tenantId: row.tenant_id, role: row.role };
  }

  async verifyEmail(rawToken: string, ip: string): Promise<boolean> {
    const token = this.tokenDigest(rawToken);
    await this.rateLimit(`action:${token}`, ip);
    const result = await this.database.query<{ verified: boolean }>(
      "SELECT onishield.consume_operator_email_verification($1) AS verified",
      [token]
    );
    return result.rows[0]?.verified === true;
  }

  async resetPassword(rawToken: string, password: string, ip: string): Promise<boolean> {
    if (password.length < 12 || password.length > 256) throw new Error("Password must contain between 12 and 256 characters");
    const token = this.tokenDigest(rawToken);
    await this.rateLimit(`action:${token}`, ip);
    const passwordHash = await hashOperatorPassword(password);
    const result = await this.database.query<{ reset: boolean }>(
      "SELECT onishield.consume_operator_password_reset($1,$2) AS reset",
      [token, passwordHash]
    );
    return result.rows[0]?.reset === true;
  }

  private tokenDigest(rawToken: string): string {
    if (!/^[A-Za-z0-9_-]{43}$/.test(rawToken)) throw new Error("Invalid or expired account action");
    return createHmac("sha256", this.tokenPepper)
      .update(`onishield:operator-email-action:v1:${rawToken}`).digest("hex");
  }
}
