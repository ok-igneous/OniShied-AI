import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { z } from "zod";
import { timingSafeEqual } from "node:crypto";
import { listDetectionFindings } from "./detection-finding-store.js";

function authorizedBearer(header: string | undefined, expectedToken: string): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice(7), "utf8");
  const expected = Buffer.from(expectedToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export function registerSystemRoutes(
  app: FastifyInstance, database: Pick<Pool, "query">,
  tenantId: string, connectorToken: string
): void {
  app.get("/v1/findings", async (request, reply) => {
    if (!authorizedBearer(request.headers.authorization, connectorToken)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const parsed = z.object({
      limit: z.coerce.number().int().min(1).max(500).default(100)
    }).strict().safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_findings_query" });
    try {
      const findings = await listDetectionFindings(tenantId, parsed.data.limit);
      reply.header("cache-control", "no-store");
      return { findings };
    } catch (error) {
      request.log.error({ err: error }, "Failed to list detection findings");
      return reply.code(503).send({ error: "findings_unavailable" });
    }
  });

  app.get("/health", async (_request, reply) => {
    try {
      await database.query("SELECT 1");
      return { status: "ok", database: "connected" };
    } catch {
      return reply.code(503).send({ status: "degraded", database: "unavailable" });
    }
  });
}
