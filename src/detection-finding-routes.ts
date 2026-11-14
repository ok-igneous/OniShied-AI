import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "./config.js";
import type { OperatorAuthService } from "./operator-auth-service.js";
import { listDetectionFindings } from "./detection-finding-store.js";
import type { Pool } from "pg";
import { registerInvestigationRoutes } from "./investigation-routes.js";

function operatorBearer(header: string | undefined): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

function connectorAuthorized(header: string | undefined): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice(7), "utf8");
  const expected = Buffer.from(config.connectorToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export function registerDetectionFindingRoutes(
  app: FastifyInstance,
  operatorAuth: OperatorAuthService | null,
  authDatabase: Pick<Pool, "query"> | null
): void {
  registerInvestigationRoutes(app, operatorAuth, authDatabase);
  app.get<{ Params: { findingId: string } }>(
    "/v1/operator/findings/:findingId/history",
    async (request, reply) => {
      if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
      const token = operatorBearer(request.headers.authorization);
      if (!token) return reply.code(401).send({ error: "unauthorized" });
      if (!/^[a-f0-9]{64}$/.test(request.params.findingId)) {
        return reply.code(400).send({ error: "invalid_finding_id" });
      }
      try {
        const history = await operatorAuth.listDetectionFindingStatusAudit(token, request.params.findingId);
        reply.header("cache-control", "no-store");
        return { history };
      } catch (error) {
        if (error instanceof Error && (error.message === "unauthorized" || /Unauthorized finding history request/.test(error.message))) {
          return reply.code(401).send({ error: "unauthorized" });
        }
        if (error instanceof Error && error.message === "forbidden") {
          return reply.code(403).send({ error: "forbidden" });
        }
        if (error instanceof Error && /Detection finding not found/.test(error.message)) {
          return reply.code(404).send({ error: "finding_not_found" });
        }
        request.log.error({ err: error }, "Detection finding history unavailable");
        return reply.code(503).send({ error: "finding_history_unavailable" });
      }
    }
  );

  app.post<{ Params: { findingId: string } }>(
    "/v1/operator/findings/:findingId/transition",
    async (request, reply) => {
      if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
      const token = operatorBearer(request.headers.authorization);
      if (!token) return reply.code(401).send({ error: "unauthorized" });
      const parsed = z.object({
        status: z.enum(["acknowledged", "investigating", "resolved", "reopened", "suppressed"]),
        reason: z.string().trim().min(10).max(1000)
      }).strict().safeParse(request.body);
      if (!/^[a-f0-9]{64}$/.test(request.params.findingId) || !parsed.success) {
        return reply.code(400).send({ error: "invalid_finding_transition_request" });
      }
      try {
        const transition = await operatorAuth.transitionDetectionFinding(
          token, request.params.findingId, parsed.data.status, parsed.data.reason, request.id
        );
        reply.header("cache-control", "no-store");
        return { transition };
      } catch (error) {
        if (error instanceof Error && (error.message === "unauthorized" || /Unauthorized finding transition/.test(error.message))) {
          return reply.code(401).send({ error: "unauthorized" });
        }
        if (error instanceof Error && (error.message === "forbidden" || /Forbidden finding transition/.test(error.message))) {
          return reply.code(403).send({ error: "forbidden" });
        }
        if (error instanceof Error && /Step-up authentication required/.test(error.message)) {
          return reply.code(428).send({ error: "step_up_required" });
        }
        if (error instanceof Error && /Detection finding not found/.test(error.message)) {
          return reply.code(404).send({ error: "finding_not_found" });
        }
        if (error instanceof Error && /Invalid finding status transition/.test(error.message)) {
          return reply.code(409).send({ error: "invalid_finding_status_transition" });
        }
        if (error instanceof Error && /Invalid finding transition request/.test(error.message)) {
          return reply.code(400).send({ error: "invalid_finding_transition_request" });
        }
        request.log.error({ err: error }, "Detection finding transition failed");
        return reply.code(503).send({ error: "finding_transition_unavailable" });
      }
    }
  );

  app.get("/v1/findings", async (request, reply) => {
    if (!connectorAuthorized(request.headers.authorization)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const parsed = z.object({
      limit: z.coerce.number().int().min(1).max(500).default(100)
    }).strict().safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_findings_query" });
    try {
      const findings = await listDetectionFindings(config.tenantId, parsed.data.limit);
      reply.header("cache-control", "no-store");
      return { findings };
    } catch (error) {
      request.log.error({ err: error }, "Failed to list detection findings");
      return reply.code(503).send({ error: "findings_unavailable" });
    }
  });
}
