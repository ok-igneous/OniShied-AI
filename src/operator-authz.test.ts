import assert from "node:assert/strict";
import test from "node:test";
import { assertOperatorPermission, canOperatorPerform } from "./operator-authz.js";

test("owner and admin receive the intended tenant administration permissions", () => {
  assert.equal(canOperatorPerform("owner", "tenant:admin"), true);
  assert.equal(canOperatorPerform("admin", "operator:admin"), true);
  assert.equal(canOperatorPerform("security_analyst", "operator:admin"), false);
});

test("review permission is restricted to owner, admin, and reviewer", () => {
  for (const role of ["owner", "admin", "reviewer"]) {
    assert.equal(canOperatorPerform(role, "threat-intelligence:review"), true);
  }
  for (const role of ["security_analyst", "viewer"]) {
    assert.equal(canOperatorPerform(role, "threat-intelligence:review"), false);
  }
});

test("security analysts can investigate but viewers remain read-only", () => {
  assert.equal(canOperatorPerform("security_analyst", "investigation:read"), true);
  assert.equal(canOperatorPerform("security_analyst", "detection:triage"), true);
  assert.equal(canOperatorPerform("viewer", "detection:triage"), false);
  assert.equal(canOperatorPerform("viewer", "event:read"), true);
});

test("unknown roles and actions fail closed", () => {
  assert.equal(canOperatorPerform("superuser", "event:read"), false);
  assert.equal(canOperatorPerform("owner", "arbitrary:execute"), false);
  assert.throws(() => assertOperatorPermission("viewer", "response:approve"), /forbidden/);
});
