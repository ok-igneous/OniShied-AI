import test from "node:test";
import assert from "node:assert/strict";
import { investigationRetryDelayMs } from "./investigation-analysis-policy.js";

test("investigation retry delay grows exponentially and is capped", () => {
  assert.equal(investigationRetryDelayMs(1), 2_000);
  assert.equal(investigationRetryDelayMs(2), 4_000);
  assert.equal(investigationRetryDelayMs(20), 30 * 60_000);
});

test("investigation retry delay rejects invalid attempts", () => {
  assert.throws(() => investigationRetryDelayMs(0));
  assert.throws(() => investigationRetryDelayMs(1.5));
});
