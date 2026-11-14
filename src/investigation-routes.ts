import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { z } from "zod";
import type { OperatorAuthService } from "./operator-auth-service.js";
import { hashOperatorSessionToken } from "./operator-auth-crypto.js";

const caseIdSchema = z.string().uuid();
const findingIdSchema = z.string().regex(/^[a-f0-9]{64}$/);

export function registerInvestigationRoutes(
  app: FastifyInstance,
  operatorAuth: OperatorAuthService | null,
  database: Pick<Pool, "query"> | null
): void {
  app.get("/v1/operator/investigations", async (request, reply) => {
    if (!operatorAuth || !database) return reply.code(503).send({ error: "investigation_unavailable" });
    const token = bearer(request.headers.authorization);
    const query = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }).strict().safeParse(request.query);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    if (!query.success) return reply.code(400).send({ error: "invalid_investigation_query" });
    try {
      await operatorAuth.authorize(token, "investigation:read");
      const result = await database.query<{ cases: unknown }>(
        "SELECT onishield.list_investigation_cases($1,$2) AS cases",
        [hashOperatorSessionToken(token), query.data.limit]
      );
      reply.header("cache-control", "no-store");
      return { cases: result.rows[0]?.cases ?? [] };
    } catch (error) {
      return handleError(request, reply, error, "investigation_list_unavailable");
    }
  });

  app.post("/v1/operator/investigations", async (request, reply) => {
    if (!operatorAuth || !database) return reply.code(503).send({ error: "investigation_unavailable" });
    const token = bearer(request.headers.authorization);
    const body = z.object({
      title: z.string().trim().min(3).max(160),
      findingIds: z.array(findingIdSchema).min(1).max(50),
      reason: z.string().trim().min(10).max(1000)
    }).strict().safeParse(request.body);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    if (!body.success) return reply.code(400).send({ error: "invalid_investigation_request" });
    try {
      await operatorAuth.authorize(token, "detection:triage");
      const result = await database.query<{ case_id: string }>(
        "SELECT onishield.create_investigation_case($1,$2,$3,$4,$5) AS case_id",
        [hashOperatorSessionToken(token), body.data.title, body.data.findingIds, body.data.reason, request.id]
      );
      reply.header("cache-control", "no-store");
      return reply.code(201).send({ caseId: result.rows[0]?.case_id });
    } catch (error) {
      return handleError(request, reply, error, "investigation_create_failed");
    }
  });

  app.get<{ Params: { caseId: string } }>("/v1/operator/investigations/:caseId", async (request, reply) => {
    if (!operatorAuth || !database) return reply.code(503).send({ error: "investigation_unavailable" });
    const token = bearer(request.headers.authorization);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    if (!caseIdSchema.safeParse(request.params.caseId).success) return reply.code(400).send({ error: "invalid_case_id" });
    try {
      await operatorAuth.authorize(token, "investigation:read");
      const result = await database.query<{ investigation: unknown }>(
        "SELECT onishield.get_investigation_case($1,$2::uuid) AS investigation",
        [hashOperatorSessionToken(token), request.params.caseId]
      );
      reply.header("cache-control", "no-store");
      return { investigation: result.rows[0]?.investigation };
    } catch (error) {
      return handleError(request, reply, error, "investigation_read_failed");
    }
  });

  app.post<{ Params: { caseId: string } }>("/v1/operator/investigations/:caseId/findings", async (request, reply) => {
    if (!operatorAuth || !database) return reply.code(503).send({ error: "investigation_unavailable" });
    const token = bearer(request.headers.authorization);
    const body = z.object({
      findingId: findingIdSchema,
      reason: z.string().trim().min(10).max(1000)
    }).strict().safeParse(request.body);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    if (!caseIdSchema.safeParse(request.params.caseId).success || !body.success) {
      return reply.code(400).send({ error: "invalid_investigation_association" });
    }
    try {
      await operatorAuth.authorize(token, "detection:triage");
      const result = await database.query<{ inserted: boolean }>(
        "SELECT onishield.add_investigation_finding($1,$2::uuid,$3,$4,$5) AS inserted",
        [hashOperatorSessionToken(token), request.params.caseId, body.data.findingId, body.data.reason, request.id]
      );
      reply.header("cache-control", "no-store");
      return { inserted: result.rows[0]?.inserted === true };
    } catch (error) {
      return handleError(request, reply, error, "investigation_association_failed");
    }
  });

  app.post<{ Params: { caseId: string } }>("/v1/operator/investigations/:caseId/notes", async (request, reply) => {
    if (!operatorAuth || !database) return reply.code(503).send({ error: "investigation_unavailable" });
    const token = bearer(request.headers.authorization);
    const body = z.object({ note: z.string().trim().min(10).max(2000) }).strict().safeParse(request.body);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    if (!caseIdSchema.safeParse(request.params.caseId).success || !body.success) {
      return reply.code(400).send({ error: "invalid_investigation_note" });
    }
    try {
      await operatorAuth.authorize(token, "detection:triage");
      await database.query(
        "SELECT onishield.add_investigation_note($1,$2::uuid,$3,$4)",
        [hashOperatorSessionToken(token), request.params.caseId, body.data.note, request.id]
      );
      reply.header("cache-control", "no-store");
      return reply.code(201).send({ saved: true });
    } catch (error) {
      return handleError(request, reply, error, "investigation_note_failed");
    }
  });
}

function bearer(header: string | undefined): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

function handleError(
  request: { log: { error: (context: unknown, message: string) => void } },
  reply: { code: (status: number) => { send: (body: unknown) => unknown } },
  error: unknown,
  fallback: string
): unknown {
  const message = error instanceof Error ? error.message : "";
  if (message === "unauthorized" || /Unauthorized investigation/.test(message)) {
    return reply.code(401).send({ error: "unauthorized" });
  }
  if (message === "forbidden" || /Forbidden investigation/.test(message)) {
    return reply.code(403).send({ error: "forbidden" });
  }
  if (/step-up required/.test(message)) return reply.code(428).send({ error: "step_up_required" });
  if (/not found|not exist/.test(message)) return reply.code(404).send({ error: "investigation_resource_not_found" });
  if (/Invalid investigation|Duplicate finding/.test(message)) {
    return reply.code(400).send({ error: "invalid_investigation_request" });
  }
  request.log.error({ err: error }, "Investigation operation failed");
  return reply.code(503).send({ error: fallback });
}
