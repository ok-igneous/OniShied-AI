import assert from "node:assert/strict";
import test from "node:test";
import type { Pool } from "pg";
import { OperatorAccountLifecycle } from "./operator-account-lifecycle.js";
import type { EmailDelivery, TransactionalEmail } from "./email-delivery.js";

const secret = "test-only-secret-with-more-than-32-characters";
const pepper = "test-only-token-pepper-with-more-than-32-characters";

function harness(handler: (sql: string, params: unknown[]) => { rows: unknown[] }) {
  const calls: Array<{ sql: string; params: unknown[] }> = [];
  const database = {
    query: async (sql: string, params: unknown[] = []) => {
      calls.push({ sql, params });
      if (sql.includes("consume_operator_login_limit")) return { rows: [{ allowed: true, retry_after_seconds: 0 }] };
      const result = handler(sql, params) as { rows: unknown[]; rowCount?: number };
      return { ...result, rowCount: result.rowCount ?? result.rows.length };
    }
  } as unknown as Pick<Pool, "query">;
  const sent: TransactionalEmail[] = [];
  const delivery: EmailDelivery = {
    send: async (message) => {
      sent.push(message);
      return { id: "resend-message-id" };
    }
  };
  return {
    service: new OperatorAccountLifecycle(database, delivery, secret, pepper, "https://console.example.test"),
    calls, sent
  };
}

test("invitation stores only a token digest and sends a fragment link through Resend", async () => {
  const { service, calls, sent } = harness(() => ({
    rows: [{ action_id: "00000000-0000-4000-8000-000000000001", recipient_email: "new@example.test" }]
  }));
  await service.createInvitation("A".repeat(43), {
    email: " NEW@EXAMPLE.TEST ", displayName: "New Operator", role: "security_analyst"
  }, "192.0.2.10");
  const call = calls.find((entry) => entry.sql.includes("create_operator_invitation"));
  assert.ok(call);
  assert.equal(call.params[1], "new@example.test");
  assert.match(String(call.params[4]), /^[a-f0-9]{64}$/);
  assert.notEqual(call.params[4], sent[0]?.text.match(/token=([A-Za-z0-9_-]{43})/)?.[1]);
  assert.equal(sent.length, 1);
  assert.equal(sent[0]?.to, "new@example.test");
  assert.match(sent[0]?.text ?? "", /#token=[A-Za-z0-9_-]{43}/);
  assert.equal(sent[0]?.idempotencyKey, "operator-invitation/00000000-0000-4000-8000-000000000001");
});

test("password-reset request returns no account data and sends only when database finds an account", async () => {
  const { service, calls, sent } = harness((sql) => sql.includes("request_operator_password_reset")
    ? { rows: [{ action_id: "reset-1", recipient_email: "operator@example.test" }] }
    : { rows: [{ allowed: true, retry_after_seconds: 0 }] });
  await service.requestPasswordReset("operator@example.test", "192.0.2.10");
  assert.equal(sent.length, 1);
  assert.equal(sent[0]?.subject, "Reset your OniShield AI password");
  assert.match(String(calls.find((entry) => entry.sql.includes("request_operator_password_reset"))?.params[1]), /^[a-f0-9]{64}$/);
});

test("unknown email password-reset requests send no email", async () => {
  const { service, sent } = harness(() => ({ rows: [{ allowed: true, retry_after_seconds: 0 }] }));
  await service.requestPasswordReset("unknown@example.test", "192.0.2.10");
  assert.equal(sent.length, 0);
});

test("email verification and password reset consume peppered token digests", async () => {
  const { service, calls } = harness((sql) => {
    if (sql.includes("consume_operator_email_verification")) return { rows: [{ verified: true }] };
    if (sql.includes("consume_operator_password_reset")) return { rows: [{ reset: true }] };
    return { rows: [] };
  });
  const raw = "A".repeat(43);
  assert.equal(await service.verifyEmail(raw, "192.0.2.10"), true);
  assert.equal(await service.resetPassword(raw, "a secure password with 12+ chars", "192.0.2.10"), true);
  const verify = calls.find((entry) => entry.sql.includes("consume_operator_email_verification"));
  const reset = calls.find((entry) => entry.sql.includes("consume_operator_password_reset"));
  assert.match(String(verify?.params[0]), /^[a-f0-9]{64}$/);
  assert.match(String(reset?.params[0]), /^[a-f0-9]{64}$/);
  assert.notEqual(verify?.params[0], raw);
  assert.equal(reset?.params[1] && String(reset.params[1]).startsWith("scrypt$16384$8$1$"), true);
});

test("invalid action tokens and weak passwords fail before database mutation", async () => {
  const { service, calls } = harness(() => ({ rows: [] }));
  await assert.rejects(() => service.verifyEmail("bad-token", "192.0.2.10"), /Invalid or expired/);
  await assert.rejects(() => service.acceptInvitation("A".repeat(43), "short", "192.0.2.10"), /Password must contain/);
  assert.equal(calls.length, 0);
});

test("password-reset provider failures do not disclose whether an account exists", async () => {
  const database = {
    query: async (sql: string) => {
      if (sql.includes("consume_operator_login_limit")) {
        return { rows: [{ allowed: true, retry_after_seconds: 0 }] };
      }
      if (sql.includes("request_operator_password_reset")) {
        return { rows: [{ action_id: "reset-failure", recipient_email: "operator@example.test" }] };
      }
      return { rows: [] };
    }
  } as unknown as Pick<Pool, "query">;
  const failingDelivery: EmailDelivery = {
    send: async () => { throw new Error("provider unavailable"); }
  };
  const service = new OperatorAccountLifecycle(database, failingDelivery, secret, pepper, "https://console.example.test");
  await assert.doesNotReject(() => service.requestPasswordReset("operator@example.test", "192.0.2.10"));
});
