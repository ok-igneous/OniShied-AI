import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { z } from "zod";
import type { OperatorAuthService } from "./operator-auth-service.js";
import { hashOperatorSessionToken } from "./operator-auth-crypto.js";
import {
  defaultAutopilotPolicy, evaluateAutopilotPolicy, type AutopilotPolicy, type AutopilotMode
} from "./autopilot-policy.js";

const policyInput = z.object({
  expectedVersion: z.number().int().min(0),
  enabled: z.boolean(),
  mode: z.enum(["off", "observe", "low_risk", "guarded"]),
  maxRiskTier: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  allowedActions: z.array(z.enum(["evidence.collect", "alert.label.add", "network.block"])).max(20),
  targetScope: z.array(z.string().trim().min(1).max(200)).max(500),
  rateLimitPerHour: z.number().int().min(1).max(1000),
  concurrencyLimit: z.number().int().min(1).max(20),
  expiresAt: z.string().datetime().nullable(),
  emergencyPaused: z.boolean(),
  changeReason: z.string().trim().min(10).max(1000)
}).strict().refine((value) => value.enabled === (value.mode !== "off"), {
  message: "enabled must be true exactly when mode is not off"
}).refine((value) => new Set(value.allowedActions).size === value.allowedActions.length, {
  message: "allowedActions must not contain duplicates"
}).refine((value) => new Set(value.targetScope).size === value.targetScope.length, {
  message: "targetScope must not contain duplicates"
});

function bearer(header: string | undefined): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

function mapPolicy(row: Record<string, unknown>): AutopilotPolicy {
  return {
    tenantId: String(row.tenant_id),
    version: Number(row.policy_version),
    enabled: row.enabled === true,
    mode: row.mode as AutopilotMode,
    maxRiskTier: Number(row.max_risk_tier) as 0 | 1 | 2,
    allowedActions: row.allowed_actions as string[],
    targetScope: row.target_scope as string[],
    rateLimitPerHour: Number(row.rate_limit_per_hour),
    concurrencyLimit: Number(row.concurrency_limit),
    expiresAt: row.expires_at ? new Date(String(row.expires_at)).toISOString() : null,
    emergencyPaused: row.emergency_paused === true
  };
}

export function registerAutopilotRoutes(
  app: FastifyInstance, auth: OperatorAuthService | null, database: Pick<Pool, "query"> | null
): void {
  app.get("/v1/operator/autopilot/policy", async (request, reply) => {
    const token = bearer(request.headers.authorization);
    if (!auth || !database) return reply.code(503).send({ error: "autopilot_unavailable" });
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    try {
      const principal = await auth.authorize(token, "detection:read");
      const result = await database.query("SELECT * FROM onishield.get_autopilot_policy($1)",
        [hashOperatorSessionToken(token)]);
      const policy = result.rows[0] ? mapPolicy(result.rows[0]) : defaultAutopilotPolicy(principal.tenantId);
      reply.header("cache-control", "no-store");
      return { policy };
    } catch (error) {
      if (error instanceof Error && error.message === "unauthorized") return reply.code(401).send({ error: "unauthorized" });
      if (error instanceof Error && error.message === "forbidden") return reply.code(403).send({ error: "forbidden" });
      request.log.error({ err: error }, "Autopilot policy read failed");
      return reply.code(503).send({ error: "autopilot_unavailable" });
    }
  });

  app.put("/v1/operator/autopilot/policy", async (request, reply) => {
    const token = bearer(request.headers.authorization);
    if (!auth || !database) return reply.code(503).send({ error: "autopilot_unavailable" });
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    const parsed = policyInput.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_autopilot_policy" });
    try {
      await auth.authorize(token, "tenant:admin");
      const p = parsed.data;
      const saved = await database.query(
        "SELECT * FROM onishield.save_autopilot_policy($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        [hashOperatorSessionToken(token),p.expectedVersion,p.enabled,p.mode,p.maxRiskTier,
          p.allowedActions,p.targetScope,p.rateLimitPerHour,p.concurrencyLimit,p.expiresAt,
          p.emergencyPaused,p.changeReason]
      );
      reply.header("cache-control", "no-store");
      return { policyVersion: Number(saved.rows[0]?.policy_version), updatedAt: saved.rows[0]?.updated_at };
    } catch (error) {
      if (error instanceof Error && error.message === "unauthorized") return reply.code(401).send({ error: "unauthorized" });
      if (error instanceof Error && error.message === "forbidden") return reply.code(403).send({ error: "forbidden" });
      if (error instanceof Error && /Step-up authentication required/.test(error.message)) return reply.code(428).send({ error: "step_up_required" });
      if (error instanceof Error && /Stale Autopilot policy version/.test(error.message)) return reply.code(409).send({ error: "policy_version_conflict" });
      if (error instanceof Error && /Invalid Autopilot policy/.test(error.message)) return reply.code(400).send({ error: "invalid_autopilot_policy" });
      request.log.error({ err: error }, "Autopilot policy update failed");
      return reply.code(503).send({ error: "autopilot_unavailable" });
    }
  });

  app.post("/v1/operator/autopilot/simulate", async (request, reply) => {
    const token = bearer(request.headers.authorization);
    if (!auth || !database) return reply.code(503).send({ error: "autopilot_unavailable" });
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    const parsed = z.object({
      actionId: z.string().min(1).max(80),
      targetId: z.string().trim().min(1).max(200)
    }).strict().safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_simulation_request" });
    try {
      const principal = await auth.authorize(token, "detection:read");
      const result = await database.query("SELECT * FROM onishield.get_autopilot_policy($1)",
        [hashOperatorSessionToken(token)]);
      const policy = result.rows[0]
        ? mapPolicy(result.rows[0])
        : defaultAutopilotPolicy(principal.tenantId);
      // Target enrollment and evidence-freshness services are not yet wired.
      // Never accept client-supplied booleans as proof of either property.
      const simulation = evaluateAutopilotPolicy(policy, parsed.data.actionId,
        parsed.data.targetId, { targetVerified: false, evidenceFresh: false });
      const audit = await database.query<{ decision_id: string }>(
        "SELECT onishield.record_autopilot_simulation($1,$2,$3,$4,$5,$6,$7,$8) AS decision_id",
        [hashOperatorSessionToken(token),simulation.policyVersion,simulation.actionId,
          parsed.data.targetId,simulation.decision,simulation.reason,simulation.riskTier,
          simulation.execution]
      );
      reply.header("cache-control", "no-store");
      return { simulation, auditId: audit.rows[0]?.decision_id };
    } catch (error) {
      if (error instanceof Error && error.message === "unauthorized") return reply.code(401).send({ error: "unauthorized" });
      if (error instanceof Error && error.message === "forbidden") return reply.code(403).send({ error: "forbidden" });
      if (error instanceof Error && /Stale Autopilot policy version/.test(error.message)) return reply.code(409).send({ error: "policy_version_conflict" });
      request.log.error({ err: error }, "Autopilot simulation failed");
      return reply.code(503).send({ error: "autopilot_unavailable" });
    }
  });
}
