import assert from "node:assert/strict";
import test from "node:test";
import { replayRetryDelayMs } from "./detection-replay-policy.js";

test("replay retry delay grows exponentially and is capped", () => {
  assert.equal(replayRetryDelayMs(1), 1_000);
  assert.equal(replayRetryDelayMs(2), 2_000);
  assert.equal(replayRetryDelayMs(3), 4_000);
  assert.equal(replayRetryDelayMs(20), 3_600_000);
});

test("replay retry delay rejects invalid attempts", () => {
  assert.throws(() => replayRetryDelayMs(0), /positive integer/);
  assert.throws(() => replayRetryDelayMs(1.5), /positive integer/);
});
