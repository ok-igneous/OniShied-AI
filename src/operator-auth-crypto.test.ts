import assert from "node:assert/strict";
import test from "node:test";
import {
  createOperatorSessionToken,
  hashOperatorPassword,
  hashOperatorSessionToken,
  verifyOperatorPassword
} from "./operator-auth-crypto.js";

test("password hashes are salted and verify only the correct password", async () => {
  const first = await hashOperatorPassword("correct horse battery staple");
  const second = await hashOperatorPassword("correct horse battery staple");
  assert.notEqual(first, second);
  assert.equal(await verifyOperatorPassword("correct horse battery staple", first), true);
  assert.equal(await verifyOperatorPassword("wrong password", first), false);
});

test("password policy rejects short and oversized passwords", async () => {
  await assert.rejects(() => hashOperatorPassword("short"));
  await assert.rejects(() => hashOperatorPassword("x".repeat(257)));
});

test("session tokens are high entropy and only their digest is stored", () => {
  const token = createOperatorSessionToken();
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  const digest = hashOperatorSessionToken(token);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.notEqual(digest, token);
  assert.throws(() => hashOperatorSessionToken("not-a-session-token"));
});
