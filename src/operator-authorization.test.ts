import assert from "node:assert/strict";
import test from "node:test";
import { canPerformOperatorAction } from "./operator-authorization.js";

test("reviewer can review intelligence but cannot administer operators", () => {
  assert.equal(canPerformOperatorAction({role:"reviewer"},"threat-intelligence:review"),true);
  assert.equal(canPerformOperatorAction({role:"reviewer"},"operators:manage"),false);
  assert.equal(canPerformOperatorAction({role:"reviewer"},"response:approve"),false);
});
test("security analyst can investigate but cannot approve response", () => {
  assert.equal(canPerformOperatorAction({role:"security_analyst"},"investigation:read"),true);
  assert.equal(canPerformOperatorAction({role:"security_analyst"},"response:approve"),false);
  assert.equal(canPerformOperatorAction({role:"security_analyst"},"threat-intelligence:review"),false);
});
test("viewer is read-only and unknown roles fail closed", () => {
  assert.equal(canPerformOperatorAction({role:"viewer"},"events:read"),true);
  assert.equal(canPerformOperatorAction({role:"viewer"},"threat-intelligence:submit"),false);
  assert.equal(canPerformOperatorAction({role:"unknown"},"tenant:read"),false);
});
test("owner and admin have distinct privilege sets", () => {
  assert.equal(canPerformOperatorAction({role:"owner"},"response:approve"),true);
  assert.equal(canPerformOperatorAction({role:"admin"},"response:approve"),false);
  assert.equal(canPerformOperatorAction({role:"admin"},"operators:manage"),true);
});
