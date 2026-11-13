import assert from "node:assert/strict";
import test from "node:test";
import type { Pool } from "pg";
import { OperatorAuthService } from "./operator-auth-service.js";
import { hashOperatorPassword, hashOperatorSessionToken } from "./operator-auth-crypto.js";

const accountId = "00000000-0000-4000-8000-000000000001";
const principalRow = {
  tenant_id: "tenant-a",
  operator_id: accountId,
  membership_id: "7",
  operator_email: "operator@example.test",
  display_name: "Test Operator",
  role: "security_analyst"
};

function fakeDatabase(handler: (sql: string, params: unknown[]) => { rows: unknown[] }) {
  const calls: Array<{ sql: string; params: unknown[] }> = [];
  const database = {
    query: async (sql: string, params: unknown[] = []) => {
      calls.push({ sql, params });
      if (sql.includes("consume_operator_login_limit")) return { rows: [{ allowed: true, retry_after_seconds: 0 }] };
      return handler(sql, params);
    }
  } as unknown as Pick<Pool, "query">;
  return { database, calls };
}

test("login normalizes email, stores only a token digest, and returns a trusted principal", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const { database, calls } = fakeDatabase((sql) => {
    if (sql.includes("lookup_operator_credentials")) {
      return { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "active" }] };
    }
    if (sql.includes("lookup_operator_membership")) {
      return { rows: [{ membership_id: "7", role: "security_analyst" }] };
    }
    if (sql.includes("create_operator_session")) return { rows: [{ session_id: "session-id" }] };
    if (sql.includes("resolve_operator_session")) return { rows: [principalRow] };
    if (sql.includes("reset_operator_login_limit")) return { rows: [] };
    throw new Error("Unexpected query");
  });

  const result = await new OperatorAuthService(database).login(
    "  OPERATOR@EXAMPLE.TEST ", "correct horse battery staple", "tenant-a", "192.0.2.10"
  );

  assert.match(result.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.principal.operatorId, accountId);
  assert.equal(result.principal.tenantId, "tenant-a");
  assert.equal(result.principal.role, "security_analyst");
  const credentialCall = calls.find((call) => call.sql.includes("lookup_operator_credentials"));
  assert.deepEqual(credentialCall?.params, ["operator@example.test"]);
  const sessionCall = calls.find((call) => call.sql.includes("create_operator_session"));
  assert.ok(sessionCall);
  assert.equal(sessionCall.params[0], hashOperatorSessionToken(result.token));
  assert.notEqual(sessionCall.params[0], result.token);
  assert.equal(calls.some((call) => call.params.includes(result.token)), false);
});

test("wrong passwords fail generically and never create a session", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const { database, calls } = fakeDatabase((sql) => sql.includes("lookup_operator_credentials")
    ? { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "active" }] }
    : { rows: [] });

  await assert.rejects(
    () => new OperatorAuthService(database).login("operator@example.test", "incorrect password", "tenant-a", "192.0.2.10"),
    /Invalid login credentials/
  );
  assert.equal(calls.some((call) => call.sql.includes("create_operator_session")), false);
});

test("inactive accounts and missing tenant memberships cannot create sessions", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const inactive = fakeDatabase((sql) => sql.includes("lookup_operator_credentials")
    ? { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "suspended" }] }
    : { rows: [] });
  await assert.rejects(
    () => new OperatorAuthService(inactive.database).login("operator@example.test", "correct horse battery staple", "tenant-a", "192.0.2.10"),
    /Invalid login credentials/
  );
  assert.equal(inactive.calls.some((call) => call.sql.includes("lookup_operator_membership")), false);

  const noMembership = fakeDatabase((sql) => sql.includes("lookup_operator_credentials")
    ? { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "active" }] }
    : { rows: [] });
  await assert.rejects(
    () => new OperatorAuthService(noMembership.database).login("operator@example.test", "correct horse battery staple", "tenant-b", "192.0.2.10"),
    /Invalid login credentials/
  );
  assert.equal(noMembership.calls.some((call) => call.sql.includes("create_operator_session")), false);
});

test("session resolution rejects malformed tokens without querying the database", async () => {
  const { database, calls } = fakeDatabase(() => ({ rows: [] }));
  const principal = await new OperatorAuthService(database).resolve("invalid");
  assert.equal(principal, null);
  assert.equal(calls.length, 0);
});

test("logout sends only the SHA-256 digest to PostgreSQL", async () => {
  const { database, calls } = fakeDatabase(() => ({ rows: [] }));
  const token = "A".repeat(43);
  await new OperatorAuthService(database).logout(token);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.params[0], hashOperatorSessionToken(token));
  assert.notEqual(calls[0]?.params[0], token);
});

test("authorization derives role from the resolved session and denies forbidden actions", async () => {
  const { database } = fakeDatabase((sql) => sql.includes("resolve_operator_session")
    ? { rows: [principalRow] }
    : { rows: [] });
  const service = new OperatorAuthService(database);
  const principal = await service.authorize("A".repeat(43), "investigation:read");
  assert.equal(principal.operatorId, accountId);
  await assert.rejects(
    () => service.authorize("A".repeat(43), "response:approve"),
    /forbidden/
  );
});

test("persistent throttle blocks login before credential lookup", async () => {
  const calls: Array<{sql:string;params:unknown[]}> = [];
  const database = {
    query: async (sql:string, params:unknown[] = []) => {
      calls.push({sql,params});
      if (sql.includes("consume_operator_login_limit")) {
        const isIpBucket = calls.filter((call) => call.sql.includes("consume_operator_login_limit")).length === 2;
        return { rows: [{ allowed: !isIpBucket, retry_after_seconds: isIpBucket ? 300 : 0 }] };
      }
      return { rows: [] };
    }
  } as unknown as Pick<Pool,"query">;
  await assert.rejects(
    () => new OperatorAuthService(database).login("operator@example.test","wrong password","tenant-a","192.0.2.10"),
    /Too many login attempts/
  );
  assert.equal(calls.filter((call) => call.sql.includes("lookup_operator_credentials")).length, 0);
});

test("review service binds audit actor to the authenticated session", async () => {
  const token = "A".repeat(43);
  const { database, calls } = fakeDatabase((sql) => {
    if (sql.includes("resolve_operator_session")) return { rows: [{...principalRow, role:"reviewer"}] };
    if (sql.includes("review_threat_indicator")) return { rows: [{
      indicator_id:"12", old_status:"pending", new_status:"active",
      actor_operator_id:accountId, changed_at:"2026-11-13T12:00:00.000Z"
    }] };
    return { rows: [] };
  });
  const result = await new OperatorAuthService(database).reviewThreatIndicator(token,12,"active","Verified source provenance.");
  assert.equal(result.actorOperatorId,accountId);
  const reviewCall = calls.find((call) => call.sql.includes("review_threat_indicator"));
  assert.equal(reviewCall?.params[0],hashOperatorSessionToken(token));
  assert.equal(reviewCall?.params[1],12);
});
