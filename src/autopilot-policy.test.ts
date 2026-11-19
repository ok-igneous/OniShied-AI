import assert from "node:assert/strict";
import test from "node:test";
import {
  defaultAutopilotPolicy, evaluateAutopilotPolicy, type AutopilotPolicy
} from "./autopilot-policy.js";

function enabledPolicy(overrides: Partial<AutopilotPolicy> = {}): AutopilotPolicy {
  return {
    ...defaultAutopilotPolicy("tenant-a"),
    version: 4, enabled: true, mode: "guarded", maxRiskTier: 2,
    allowedActions: ["evidence.collect", "alert.label.add", "network.block"],
    targetScope: ["host-1"], ...overrides
  };
}
const trusted = { targetVerified: true, evidenceFresh: true, now: new Date("2026-11-19T00:00:00Z") };

test("default policy is disabled and fails closed", () => {
  const policy = defaultAutopilotPolicy("tenant-a");
  const result = evaluateAutopilotPolicy(policy, "evidence.collect", "host-1", trusted);
  assert.equal(policy.enabled, false);
  assert.equal(result.decision, "deny");
  assert.equal(result.reason, "autopilot_disabled");
  assert.equal(result.execution, "never_dispatch");
});

test("read-only Tier 0 may be simulated but never dispatched", () => {
  const result = evaluateAutopilotPolicy(enabledPolicy(), "evidence.collect", "host-1", trusted);
  assert.equal(result.decision, "allow");
  assert.equal(result.execution, "never_dispatch");
});

test("Observe mode never changes the no-dispatch boundary", () => {
  const result = evaluateAutopilotPolicy(
    enabledPolicy({ mode: "observe" }), "evidence.collect", "host-1", trusted
  );
  assert.equal(result.decision, "allow");
  assert.equal(result.reason, "observe_only_no_dispatch");
  assert.equal(result.execution, "never_dispatch");
});

test("Tier 1 always requires independent approval in this release", () => {
  const result = evaluateAutopilotPolicy(enabledPolicy(), "alert.label.add", "host-1", trusted);
  assert.equal(result.decision, "approval_required");
});

test("Tier 2 always requires human approval", () => {
  const result = evaluateAutopilotPolicy(enabledPolicy(), "network.block", "host-1", trusted);
  assert.equal(result.decision, "approval_required");
  assert.equal(result.reason, "tier_2_requires_human_approval");
});

test("Tier 3 is prohibited regardless of tenant configuration", () => {
  const result = evaluateAutopilotPolicy(
    enabledPolicy({ maxRiskTier: 2, allowedActions: ["device.wipe"] }),
    "device.wipe", "host-1", trusted
  );
  assert.equal(result.decision, "deny");
  assert.equal(result.reason, "tier_3_prohibited");
});

test("unknown actions fail closed", () => {
  const result = evaluateAutopilotPolicy(enabledPolicy(), "shell.execute", "host-1", trusted);
  assert.equal(result.decision, "deny");
  assert.equal(result.reason, "action_not_in_server_catalogue");
});

test("an action omitted from the tenant allowlist is denied", () => {
  const result = evaluateAutopilotPolicy(
    enabledPolicy({ allowedActions: ["evidence.collect"] }),
    "alert.label.add", "host-1", trusted
  );
  assert.equal(result.decision, "deny");
  assert.equal(result.reason, "action_not_allowlisted");
});

test("cross-scope and unverified targets fail closed", () => {
  assert.equal(
    evaluateAutopilotPolicy(enabledPolicy(), "evidence.collect", "host-2", trusted).reason,
    "target_out_of_scope"
  );
  assert.equal(
    evaluateAutopilotPolicy(enabledPolicy(), "evidence.collect", "host-1",
      { ...trusted, targetVerified: false }).reason,
    "target_identity_unverified"
  );
});

test("missing or stale evidence fails closed", () => {
  const result = evaluateAutopilotPolicy(
    enabledPolicy(), "evidence.collect", "host-1", { ...trusted, evidenceFresh: false }
  );
  assert.equal(result.reason, "evidence_missing_or_stale");
});

test("emergency pause, expiry, and stale risk ceiling deny", () => {
  assert.equal(
    evaluateAutopilotPolicy(enabledPolicy({ emergencyPaused: true }), "evidence.collect", "host-1", trusted).reason,
    "emergency_pause_active"
  );
  assert.equal(
    evaluateAutopilotPolicy(enabledPolicy({ expiresAt: "2026-11-18T00:00:00Z" }),
      "evidence.collect", "host-1", trusted).reason,
    "policy_expired"
  );
  assert.equal(
    evaluateAutopilotPolicy(enabledPolicy({ maxRiskTier: 0 }), "alert.label.add", "host-1", trusted).reason,
    "risk_exceeds_policy_ceiling"
  );
});
