import assert from "node:assert/strict";
import test from "node:test";
import type { Pool } from "pg";
import { OperatorAuthService } from "./operator-auth-service.js";
import { hashOperatorPassword, hashOperatorSessionToken } from "./operator-auth-crypto.js";
import { encryptMfaSecret } from "./operator-mfa-crypto.js";
import { generateTotpAt, generateTotpSecret } from "./operator-mfa-totp.js";

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
      const result = handler(sql, params) as {rows:unknown[];rowCount?:number};
      return {...result,rowCount:result.rowCount ?? result.rows.length};
    }
  } as unknown as Pick<Pool, "query">;
  return { database, calls };
}

test("login normalizes email, stores only a token digest, and returns a trusted principal", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const { database, calls } = fakeDatabase((sql) => {
    if (sql.includes("lookup_operator_credentials")) {
      return { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "active", email_verified: true }] };
    }
    if (sql.includes("get_operator_mfa")) return { rows: [{enabled:false}] };
    if (sql.includes("lookup_operator_membership")) {
      return { rows: [{ membership_id: "7", role: "security_analyst" }] };
    }
    if (sql.includes("create_operator_session")) return { rows: [{ session_id: "session-id" }] };
    if (sql.includes("resolve_operator_session")) return { rows: [principalRow] };
    if (sql.includes("reset_operator_login_limit")) return { rows: [] };
    throw new Error("Unexpected query");
  });

  const result = await new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).login(
    "  OPERATOR@EXAMPLE.TEST ", "correct horse battery staple", "tenant-a", "192.0.2.10"
  );

  if ("mfaRequired" in result) throw new Error("Unexpected MFA challenge");
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
  const limitCalls = calls.filter((call) => call.sql.includes("consume_operator_login_limit"));
  assert.equal(limitCalls.length, 2);
  assert.deepEqual(limitCalls.map((call) => call.params[1]), [5, 30]);
  assert.equal(calls.filter((call) => call.sql.includes("reset_operator_login_limit")).length, 1);
});

test("wrong passwords fail generically and never create a session", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const { database, calls } = fakeDatabase((sql) => sql.includes("lookup_operator_credentials")
    ? { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "active", email_verified: true }] }
    : { rows: [] });

  await assert.rejects(
    () => new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).login("operator@example.test", "incorrect password", "tenant-a", "192.0.2.10"),
    /Invalid login credentials/
  );
  assert.equal(calls.some((call) => call.sql.includes("create_operator_session")), false);
});

test("unverified email addresses cannot create operator sessions", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const { database, calls } = fakeDatabase((sql) => sql.includes("lookup_operator_credentials")
    ? { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "active", email_verified: false }] }
    : { rows: [] });
  await assert.rejects(
    () => new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32), "cd".repeat(32))
      .login("operator@example.test", "correct horse battery staple", "tenant-a", "192.0.2.10"),
    /Invalid login credentials/
  );
  assert.equal(calls.some((call) => call.sql.includes("lookup_operator_membership")), false);
  assert.equal(calls.some((call) => call.sql.includes("create_operator_session")), false);
});

test("inactive accounts and missing tenant memberships cannot create sessions", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const inactive = fakeDatabase((sql) => sql.includes("lookup_operator_credentials")
    ? { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "suspended" }] }
    : { rows: [] });
  await assert.rejects(
    () => new OperatorAuthService(inactive.database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).login("operator@example.test", "correct horse battery staple", "tenant-a", "192.0.2.10"),
    /Invalid login credentials/
  );
  assert.equal(inactive.calls.some((call) => call.sql.includes("lookup_operator_membership")), false);

  const noMembership = fakeDatabase((sql) => sql.includes("lookup_operator_credentials")
    ? { rows: [{ operator_id: accountId, password_hash: passwordHash, operator_status: "active", email_verified: true }] }
    : { rows: [] });
  await assert.rejects(
    () => new OperatorAuthService(noMembership.database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).login("operator@example.test", "correct horse battery staple", "tenant-b", "192.0.2.10"),
    /Invalid login credentials/
  );
  assert.equal(noMembership.calls.some((call) => call.sql.includes("create_operator_session")), false);
});

test("session resolution rejects malformed tokens without querying the database", async () => {
  const { database, calls } = fakeDatabase(() => ({ rows: [] }));
  const principal = await new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).resolve("invalid");
  assert.equal(principal, null);
  assert.equal(calls.length, 0);
});

test("logout sends only the SHA-256 digest to PostgreSQL", async () => {
  const { database, calls } = fakeDatabase(() => ({ rows: [] }));
  const token = "A".repeat(43);
  await new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).logout(token);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.params[0], hashOperatorSessionToken(token));
  assert.notEqual(calls[0]?.params[0], token);
});

test("authorization derives role from the resolved session and denies forbidden actions", async () => {
  const { database } = fakeDatabase((sql) => sql.includes("resolve_operator_session")
    ? { rows: [principalRow] }
    : { rows: [] });
  const service = new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32));
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
    () => new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).login("operator@example.test","wrong password","tenant-a","192.0.2.10"),
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
  const result = await new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).reviewThreatIndicator(token,12,"active","Verified source provenance.");
  assert.equal(result.actorOperatorId,accountId);
  const reviewCall = calls.find((call) => call.sql.includes("review_threat_indicator"));
  assert.equal(reviewCall?.params[0],hashOperatorSessionToken(token));
  assert.equal(reviewCall?.params[1],12);
});

test("session rotation invalidates the old token and returns a new token", async () => {
  const token = "A".repeat(43);
  const { database, calls } = fakeDatabase((sql) => {
    if (sql.includes("rotate_operator_session")) return { rows: [{ session_id: "new-session" }], rowCount: 1 };
    if (sql.includes("resolve_operator_session")) return { rows: [principalRow] };
    return { rows: [] };
  });
  const result = await new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32)).rotate(token);
  assert.notEqual(result.token, token);
  assert.match(result.token, /^[A-Za-z0-9_-]{43}$/);
  const rotation = calls.find((call) => call.sql.includes("rotate_operator_session"));
  assert.equal(rotation?.params[0], hashOperatorSessionToken(token));
  assert.equal(rotation?.params[1], hashOperatorSessionToken(result.token));
});

test("session inventory returns metadata only and other-session revocation is tenant-bound in SQL", async () => {
  const token = "A".repeat(43);
  const { database, calls } = fakeDatabase((sql) => {
    if (sql.includes("list_operator_sessions")) return { rows: [{
      session_id: "session-1", created_at: "2026-11-13T10:00:00Z",
      expires_at: "2026-11-13T18:00:00Z", last_seen_at: "2026-11-13T11:00:00Z",
      revoked_at: null, is_current: true
    }] };
    if (sql.includes("revoke_operator_session_by_id")) return { rows: [{ revoked: true }] };
    return { rows: [] };
  });
  const service = new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32));
  const sessions = await service.listSessions(token);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0]?.current, true);
  assert.equal("token" in (sessions[0] ?? {}), false);
  assert.equal(await service.revokeOtherSession(token, "00000000-0000-4000-8000-000000000002"), true);
  const listCall = calls.find((call) => call.sql.includes("list_operator_sessions"));
  const revokeCall = calls.find((call) => call.sql.includes("revoke_operator_session_by_id"));
  assert.equal(listCall?.params[0], hashOperatorSessionToken(token));
  assert.equal(revokeCall?.params[0], hashOperatorSessionToken(token));
  assert.equal(revokeCall?.params[1], "00000000-0000-4000-8000-000000000002");
});

test("session revocation rejects malformed identifiers before database access", async () => {
  const { database, calls } = fakeDatabase(() => ({ rows: [] }));
  await assert.rejects(
    () => new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32))
      .revokeOtherSession("A".repeat(43), "not-a-uuid"),
    /Invalid session ID/
  );
  assert.equal(calls.length, 0);
});

test("step-up requires the current account password and marks only the current session", async () => {
  const token = "A".repeat(43);
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const { database, calls } = fakeDatabase((sql) => {
    if (sql.includes("resolve_operator_session")) return { rows: [principalRow] };
    if (sql.includes("lookup_operator_credentials")) {
      return { rows: [{password_hash:passwordHash,operator_status:"active"}] };
    }
    if (sql.includes("mark_operator_session_step_up")) return { rows: [{marked:true}] };
    return { rows: [] };
  });
  const service = new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32));
  const result = await service.stepUp(token, "correct horse battery staple");
  assert.equal(result.validForSeconds, 300);
  const mark = calls.find((call) => call.sql.includes("mark_operator_session_step_up"));
  assert.equal(mark?.params[0], hashOperatorSessionToken(token));
});

test("step-up rejects a wrong password without marking the session", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const { database, calls } = fakeDatabase((sql) => {
    if (sql.includes("resolve_operator_session")) return { rows: [principalRow] };
    if (sql.includes("lookup_operator_credentials")) {
      return { rows: [{password_hash:passwordHash,operator_status:"active"}] };
    }
    return { rows: [] };
  });
  await assert.rejects(
    () => new OperatorAuthService(database, "test-only-rate-limit-secret-with-32-plus-characters", "ab".repeat(32),"cd".repeat(32))
      .stepUp("A".repeat(43), "incorrect password"),
    /Invalid step-up credentials/
  );
  assert.equal(calls.some((call) => call.sql.includes("mark_operator_session_step_up")), false);
});

test("MFA login issues a challenge instead of a session, then consumes a valid TOTP once", async () => {
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const secret = generateTotpSecret();
  const encrypted = encryptMfaSecret(secret,"ab".repeat(32),"cd".repeat(32));
  const {database,calls} = fakeDatabase((sql) => {
    if (sql.includes("lookup_operator_credentials")) return {rows:[{operator_id:accountId,password_hash:passwordHash,operator_status:"active"}]};
    if (sql.includes("lookup_operator_membership")) return {rows:[{membership_id:"7",role:"security_analyst"}]};
    if (sql.includes("get_operator_mfa")) return {rows:[{enabled:true,ciphertext:encrypted.ciphertext,nonce:encrypted.nonce,auth_tag:encrypted.authTag}]};
    if (sql.includes("create_operator_login_challenge")) return {rows:[{create_operator_login_challenge:true}]};
    if (sql.includes("get_operator_login_challenge")) return {rows:[{operator_id:accountId}]};
    if (sql.includes("consume_operator_login_challenge")) return {rows:[{session_id:"session-1"}],rowCount:1};
    if (sql.includes("resolve_operator_session")) return {rows:[principalRow]};
    return {rows:[]};
  });
  const service = new OperatorAuthService(database,"test-only-rate-limit-secret-with-32-plus-characters","ab".repeat(32),"cd".repeat(32));
  const login = await service.login("operator@example.test","correct horse battery staple","tenant-a","192.0.2.10");
  assert.ok("mfaRequired" in login);
  if (!("mfaRequired" in login)) throw new Error("Expected MFA challenge");
  assert.equal(calls.some((call)=>call.sql.includes("create_operator_session")),false);
  const code = generateTotpAt(secret,Date.now());
  const session = await service.completeMfaLogin(login.challengeToken,code);
  assert.equal(session.principal.operatorId,accountId);
  assert.ok(calls.some((call)=>call.sql.includes("consume_operator_login_challenge")));
});

test("enrolled reviewer step-up requires a fresh TOTP counter", async () => {
  const token = "A".repeat(43);
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const secret = generateTotpSecret();
  const encrypted = encryptMfaSecret(secret,"ab".repeat(32),"cd".repeat(32));
  const {database,calls} = fakeDatabase((sql) => {
    if (sql.includes("resolve_operator_session")) return {rows:[{...principalRow,role:"reviewer"}]};
    if (sql.includes("lookup_operator_credentials")) return {rows:[{password_hash:passwordHash,operator_status:"active"}]};
    if (sql.includes("get_operator_mfa")) return {rows:[{enabled:true,ciphertext:encrypted.ciphertext,nonce:encrypted.nonce,auth_tag:encrypted.authTag}]};
    if (sql.includes("mark_operator_session_step_up")) return {rows:[{marked:true}]};
    return {rows:[]};
  });
  const service = new OperatorAuthService(database,"test-only-rate-limit-secret-with-32-plus-characters","ab".repeat(32),"cd".repeat(32));
  await assert.rejects(()=>service.stepUp(token,"correct horse battery staple"),/MFA code required/);
  assert.equal(calls.some(call=>call.sql.includes("mark_operator_session_step_up")),false);
  const code = generateTotpAt(secret,Date.now());
  const result = await service.stepUp(token,"correct horse battery staple",code);
  assert.equal(result.validForSeconds,300);
  const mark = calls.filter(call=>call.sql.includes("mark_operator_session_step_up")).at(-1);
  assert.equal(mark?.params[0],hashOperatorSessionToken(token));
  assert.equal(typeof mark?.params[1],"number");
});

test("MFA enrollment reauthenticates password and stores only encrypted secret material", async () => {
  const token = "A".repeat(43);
  const passwordHash = await hashOperatorPassword("correct horse battery staple");
  const pendingSecret = generateTotpSecret();
  const encrypted = encryptMfaSecret(pendingSecret,"ab".repeat(32),"cd".repeat(32));
  const {database,calls} = fakeDatabase((sql) => {
    if (sql.includes("resolve_operator_session")) return {rows:[{...principalRow,role:"reviewer"}]};
    if (sql.includes("lookup_operator_credentials")) return {rows:[{password_hash:passwordHash,operator_status:"active"}]};
    if (sql.includes("mark_operator_session_mfa_enrollment_step_up")) return {rows:[{marked:true}]};
    if (sql.includes("store_pending_operator_mfa")) return {rows:[{stored:true}]};
    if (sql.includes("get_pending_operator_mfa")) return {rows:[{ciphertext:encrypted.ciphertext,nonce:encrypted.nonce,auth_tag:encrypted.authTag}]};
    if (sql.includes("activate_operator_mfa")) return {rows:[{activated:true}]};
    return {rows:[]};
  });
  const service = new OperatorAuthService(database,"test-only-rate-limit-secret-with-32-plus-characters","ab".repeat(32),"cd".repeat(32));
  const enrollment = await service.beginMfaEnrollment(token,"correct horse battery staple");
  assert.match(enrollment.secret,/^[A-Z2-7]{32}$/);
  assert.ok(enrollment.otpauthUrl.startsWith("otpauth://totp/"));
  const store = calls.find(call=>call.sql.includes("store_pending_operator_mfa"));
  assert.ok(store);
  assert.notDeepEqual(store.params[1],Buffer.from(enrollment.secret,"utf8"));
  const confirmed = await service.confirmMfaEnrollment(token,generateTotpAt(pendingSecret,Date.now()));
  assert.equal(confirmed.recoveryCodes.length,10);
  assert.ok(confirmed.recoveryCodes.every(code=>/^[A-F0-9]{32}$/.test(code)));
  const activation = calls.find(call=>call.sql.includes("activate_operator_mfa"));
  assert.ok(activation);
  assert.equal((activation.params[2] as string[]).length,10);
  assert.ok((activation.params[2] as string[]).every(hash=>/^[a-f0-9]{64}$/.test(hash)));
  assert.ok(!(activation.params[2] as string[]).includes(confirmed.recoveryCodes[0]!));
});

test("MFA recovery login sends only a peppered digest and creates a session once", async () => {
  const challengeToken="B".repeat(43);
  const recoveryCode="C".repeat(32);
  const encrypted=encryptMfaSecret(generateTotpSecret(),"ab".repeat(32));
  const {database,calls}=fakeDatabase((sql)=> {
    if(sql.includes("get_operator_login_challenge")) return {rows:[{operator_id:accountId}]};
    if(sql.includes("get_operator_mfa")) return {rows:[{enabled:true,ciphertext:encrypted.ciphertext,nonce:encrypted.nonce,auth_tag:encrypted.authTag}]};
    if(sql.includes("consume_operator_login_challenge_with_recovery")) return {rows:[{session_id:"recovered"}]};
    if(sql.includes("resolve_operator_session")) return {rows:[principalRow]};
    return {rows:[]};
  });
  const service=new OperatorAuthService(database,"test-only-rate-limit-secret-with-32-plus-characters","ab".repeat(32),"cd".repeat(32));
  const result=await service.completeMfaLogin(challengeToken,recoveryCode);
  assert.equal(result.principal.operatorId,accountId);
  const consume=calls.find(call=>call.sql.includes("consume_operator_login_challenge_with_recovery"));
  assert.ok(consume);
  assert.notEqual(consume.params[1],recoveryCode);
  assert.match(String(consume.params[1]),/^[a-f0-9]{64}$/);
});

test("recovery code can provide one-time MFA step-up after password verification", async () => {
  const token="D".repeat(43);
  const recoveryCode="E".repeat(32);
  const passwordHash=await hashOperatorPassword("correct horse battery staple");
  const encrypted=encryptMfaSecret(generateTotpSecret(),"ab".repeat(32));
  const {database,calls}=fakeDatabase((sql)=> {
    if(sql.includes("resolve_operator_session")) return {rows:[{...principalRow,role:"reviewer"}]};
    if(sql.includes("lookup_operator_credentials")) return {rows:[{password_hash:passwordHash,operator_status:"active"}]};
    if(sql.includes("get_operator_mfa")) return {rows:[{enabled:true,ciphertext:encrypted.ciphertext,nonce:encrypted.nonce,auth_tag:encrypted.authTag}]};
    if(sql.includes("mark_operator_session_step_up_with_recovery")) return {rows:[{marked:true}]};
    return {rows:[]};
  });
  const service=new OperatorAuthService(database,"test-only-rate-limit-secret-with-32-plus-characters","ab".repeat(32),"cd".repeat(32));
  const result=await service.stepUp(token,"correct horse battery staple",recoveryCode);
  assert.equal(result.validForSeconds,300);
  const mark=calls.find(call=>call.sql.includes("mark_operator_session_step_up_with_recovery"));
  assert.ok(mark);
  assert.notEqual(mark.params[1],recoveryCode);
});
