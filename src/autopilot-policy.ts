export type AutopilotMode = "off" | "observe" | "low_risk" | "guarded";
export type RiskTier = 0 | 1 | 2 | 3;
export type PolicyDecision = "allow" | "deny" | "approval_required";

export interface AutopilotPolicy {
  tenantId: string;
  version: number;
  enabled: boolean;
  mode: AutopilotMode;
  maxRiskTier: 0 | 1 | 2;
  allowedActions: string[];
  targetScope: string[];
  rateLimitPerHour: number;
  concurrencyLimit: number;
  expiresAt: string | null;
  emergencyPaused: boolean;
}

export interface ActionDefinition {
  id: string;
  riskTier: RiskTier;
  reversible: boolean;
  description: string;
}

export interface SimulationContext {
  targetVerified: boolean;
  evidenceFresh: boolean;
  now?: Date;
}

export interface PolicySimulation {
  decision: PolicyDecision;
  reason: string;
  actionId: string;
  riskTier: RiskTier;
  policyVersion: number;
  execution: "never_dispatch";
}

export const ACTION_CATALOGUE: Readonly<Record<string, ActionDefinition>> = {
  "evidence.collect": {
    id: "evidence.collect", riskTier: 0, reversible: true,
    description: "Collect a bounded, read-only evidence snapshot."
  },
  "alert.label.add": {
    id: "alert.label.add", riskTier: 1, reversible: true,
    description: "Add a temporary alert label; no endpoint state changes."
  },
  "network.block": {
    id: "network.block", riskTier: 2, reversible: true,
    description: "Apply a scoped network block that can disrupt service."
  },
  "device.wipe": {
    id: "device.wipe", riskTier: 3, reversible: false,
    description: "Destructive device wipe; prohibited in the initial product."
  }
};

export function defaultAutopilotPolicy(tenantId: string): AutopilotPolicy {
  return {
    tenantId, version: 0, enabled: false, mode: "off", maxRiskTier: 0,
    allowedActions: [], targetScope: [], rateLimitPerHour: 10,
    concurrencyLimit: 1, expiresAt: null, emergencyPaused: false
  };
}

export function evaluateAutopilotPolicy(
  policy: AutopilotPolicy,
  actionId: string,
  targetId: string,
  context: SimulationContext
): PolicySimulation {
  const action = ACTION_CATALOGUE[actionId];
  const result = (decision: PolicyDecision, reason: string): PolicySimulation => ({
    decision, reason, actionId, riskTier: action?.riskTier ?? 3,
    policyVersion: policy.version, execution: "never_dispatch"
  });

  if (!action) return result("deny", "action_not_in_server_catalogue");
  if (action.riskTier === 3) return result("deny", "tier_3_prohibited");
  if (policy.emergencyPaused) return result("deny", "emergency_pause_active");
  if (!policy.enabled || policy.mode === "off") return result("deny", "autopilot_disabled");
  if (policy.expiresAt && Date.parse(policy.expiresAt) <= (context.now ?? new Date()).getTime()) {
    return result("deny", "policy_expired");
  }
  if (action.riskTier > policy.maxRiskTier) return result("deny", "risk_exceeds_policy_ceiling");
  if (!policy.allowedActions.includes(actionId)) return result("deny", "action_not_allowlisted");
  if (!targetId || !policy.targetScope.includes(targetId)) return result("deny", "target_out_of_scope");
  if (!context.targetVerified) return result("deny", "target_identity_unverified");
  if (!context.evidenceFresh) return result("deny", "evidence_missing_or_stale");
  if (action.riskTier === 2) return result("approval_required", "tier_2_requires_human_approval");
  if (action.riskTier === 1) {
    return result("approval_required", "tier_1_requires_independent_approval_in_this_release");
  }
  return result("allow", policy.mode === "observe" ? "observe_only_no_dispatch" : "policy_allows_read_only_action");
}
