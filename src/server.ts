import Fastify from "fastify";
import { z } from "zod";
import { timingSafeEqual } from "node:crypto";
import { config } from "./config.js";
import { authPool, pool, withTenantTransaction } from "./database.js";
import { OperatorAuthService, OperatorLoginRateLimitError } from "./operator-auth-service.js";
import { securityEventSchema } from "./security-event.js";
import { securityEventDigest } from "./security-event-digest.js";

const operatorAuth = authPool && config.authRateLimitSecret
  ? new OperatorAuthService(authPool, config.authRateLimitSecret)
  : null;
const operatorLoginSchema = z.object({
  email: z.string().min(3).max(254),
  password: z.string().min(1).max(256),
  tenantId: z.string().trim().min(1).max(128)
}).strict();
const operatorReviewSchema = z.object({
  status: z.enum(["active", "rejected", "revoked", "expired"]),
  reason: z.string().trim().min(10).max(1000)
}).strict();

const app = Fastify({
  logger: true,
  bodyLimit: 256 * 1024,
  requestTimeout: 10_000
});

function authorizedBearer(header: string | undefined): boolean {
  if (!header?.startsWith("Bearer ")) return false;

  const supplied = Buffer.from(header.slice(7), "utf8");
  const expected = Buffer.from(config.connectorToken, "utf8");

  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

app.post("/v1/operator/login", async (request, reply) => {
  if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
  const parsed = operatorLoginSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: "invalid_login_request" });
  try {
    const result = await operatorAuth.login(
      parsed.data.email, parsed.data.password, parsed.data.tenantId, request.ip
    );
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
    return reply.code(200).send(result);
  } catch (error) {
    if (error instanceof OperatorLoginRateLimitError) {
      reply.header("retry-after", String(error.retryAfterSeconds));
      return reply.code(429).send({ error: "too_many_login_attempts" });
    }
    if (error instanceof Error && error.message === "Invalid login credentials") {
      return reply.code(401).send({ error: "invalid_login_credentials" });
    }
    request.log.error({ err: error }, "Operator login unavailable");
    return reply.code(503).send({ error: "operator_auth_unavailable" });
  }
});

function operatorBearer(header: string | undefined): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

app.get("/v1/operator/me", async (request, reply) => {
  if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
  const token = operatorBearer(request.headers.authorization);
  if (!token) return reply.code(401).send({ error: "unauthorized" });
  try {
    const principal = await operatorAuth.resolve(token);
    if (!principal) return reply.code(401).send({ error: "unauthorized" });
    reply.header("cache-control", "no-store");
    return { principal };
  } catch (error) {
    request.log.error({ err: error }, "Operator session validation unavailable");
    return reply.code(503).send({ error: "operator_auth_unavailable" });
  }
});

app.post("/v1/operator/logout", async (request, reply) => {
  if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
  const token = operatorBearer(request.headers.authorization);
  if (!token) return reply.code(401).send({ error: "unauthorized" });
  try {
    await operatorAuth.logout(token);
    return reply.code(204).send();
  } catch (error) {
    request.log.error({ err: error }, "Operator logout unavailable");
    return reply.code(503).send({ error: "operator_auth_unavailable" });
  }
});

app.post("/v1/operator/rotate", async (request, reply) => {
  if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
  const token = operatorBearer(request.headers.authorization);
  if (!token) return reply.code(401).send({ error: "unauthorized" });
  try {
    const result = await operatorAuth.rotate(token);
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
    return { session: result };
  } catch (error) {
    if (error instanceof Error && /Unauthorized session rotation/.test(error.message)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    request.log.error({ err: error }, "Operator session rotation unavailable");
    return reply.code(503).send({ error: "operator_auth_unavailable" });
  }
});

app.get("/v1/operator/sessions", async (request, reply) => {
  if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
  const token = operatorBearer(request.headers.authorization);
  if (!token) return reply.code(401).send({ error: "unauthorized" });
  try {
    if (!await operatorAuth.resolve(token)) return reply.code(401).send({ error: "unauthorized" });
    const sessions = await operatorAuth.listSessions(token);
    reply.header("cache-control", "no-store");
    return { sessions };
  } catch (error) {
    request.log.error({ err: error }, "Operator session inventory unavailable");
    return reply.code(503).send({ error: "operator_auth_unavailable" });
  }
});

app.delete<{ Params: { sessionId: string } }>(
  "/v1/operator/sessions/:sessionId",
  async (request, reply) => {
    if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
    const token = operatorBearer(request.headers.authorization);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    if (!z.string().uuid().safeParse(request.params.sessionId).success) {
      return reply.code(400).send({ error: "invalid_session_id" });
    }
    try {
      if (!await operatorAuth.resolve(token)) return reply.code(401).send({ error: "unauthorized" });
      const revoked = await operatorAuth.revokeOtherSession(token, request.params.sessionId);
      if (!revoked) return reply.code(404).send({ error: "session_not_found_or_not_revocable" });
      return reply.code(204).send();
    } catch (error) {
      request.log.error({ err: error }, "Operator session revocation unavailable");
      return reply.code(503).send({ error: "operator_auth_unavailable" });
    }
  }
);

app.post<{ Params: { indicatorId: string } }>(
  "/v1/threat-intelligence/:indicatorId/review",
  async (request, reply) => {
    if (!operatorAuth) return reply.code(503).send({ error: "operator_auth_not_configured" });
    const token = operatorBearer(request.headers.authorization);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    const indicatorId = Number(request.params.indicatorId);
    const parsed = operatorReviewSchema.safeParse(request.body);
    if (!Number.isSafeInteger(indicatorId) || indicatorId < 1 || !parsed.success) {
      return reply.code(400).send({ error: "invalid_review_request" });
    }
    try {
      const result = await operatorAuth.reviewThreatIndicator(
        token, indicatorId, parsed.data.status, parsed.data.reason
      );
      reply.header("cache-control", "no-store");
      return { review: result };
    } catch (error) {
      if (error instanceof Error && error.message === "unauthorized") {
        return reply.code(401).send({ error: "unauthorized" });
      }
      if (error instanceof Error && error.message === "forbidden") {
        return reply.code(403).send({ error: "forbidden" });
      }
      if (error instanceof Error && /Invalid review request/.test(error.message)) {
        return reply.code(400).send({ error: "invalid_review_request" });
      }
      request.log.error({ err: error }, "Threat indicator review failed");
      return reply.code(409).send({ error: "threat_indicator_review_failed" });
    }
  }
);

app.get("/health", async (_request, reply) => {
  try {
    await pool.query("SELECT 1");
    return { status: "ok", database: "connected" };
  } catch {
    return reply.code(503).send({ status: "degraded", database: "unavailable" });
  }
});

app.post("/v1/events", async (request, reply) => {
  if (!authorizedBearer(request.headers.authorization)) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const parsed = securityEventSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({
      error: "invalid_event",
      details: parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message
      }))
    });
  }

  const event = parsed.data;

  // The connector identity and tenant are authoritative server-side values.
  // Payload values are checked, never used to choose another tenant.
  if (event.source.connector_id !== config.connectorId) {
    return reply.code(403).send({ error: "connector_identity_mismatch" });
  }

  if (event.tenant_id !== config.tenantId) {
    return reply.code(403).send({ error: "tenant_scope_mismatch" });
  }

  const ingestedAt = new Date().toISOString();
  const normalizedEvent = {
    ...event,
    ingested_at: ingestedAt
  };

  try {
    const payloadDigest = securityEventDigest(event);

    const outcome = await withTenantTransaction(config.tenantId, async (client) => {
      const inserted = await client.query(
        `INSERT INTO onishield.security_events
          (tenant_id, connector_id, event_id, schema_version, event_type,
           observed_at, ingested_at, severity_hint, event_json, payload_sha256)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
         ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING
         RETURNING event_id`,
        [
          config.tenantId,
          config.connectorId,
          event.event_id,
          event.schema_version,
          event.event_type,
          event.observed_at,
          ingestedAt,
          event.severity_hint ?? "unknown",
          JSON.stringify(normalizedEvent),
          payloadDigest
        ]
      );

      if (inserted.rowCount === 1) return "accepted" as const;

      const existing = await client.query<{ payload_sha256: string | null }>(
        `SELECT payload_sha256
           FROM onishield.security_events
          WHERE tenant_id = $1 AND connector_id = $2 AND event_id = $3`,
        [config.tenantId, config.connectorId, event.event_id]
      );

      if (existing.rowCount !== 1) {
        throw new Error("Conflicting event could not be read inside tenant scope");
      }

      return existing.rows[0]?.payload_sha256 === payloadDigest
        ? "duplicate" as const
        : "event_id_conflict" as const;
    });

    if (outcome === "event_id_conflict") {
      return reply.code(409).send({
        error: "event_id_reused_with_different_payload",
        event_id: event.event_id
      });
    }

    if (outcome === "duplicate") {
      return reply.code(200).send({
        status: "duplicate",
        event_id: event.event_id
      });
    }

    return reply.code(202).send({
      status: "accepted",
      event_id: event.event_id,
      ingested_at: ingestedAt
    });
  } catch (error) {
    request.log.error({ err: error }, "Failed to persist security event");
    return reply.code(503).send({ error: "event_persistence_unavailable" });
  }
});

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "Shutting down");
  await app.close();
  await pool.end();
  await authPool?.end();
  process.exit(0);
};

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));

try {
  await pool.query("SELECT 1");
  await app.listen({ host: "127.0.0.1", port: config.port });
} catch (error) {
  app.log.error(error);
  await pool.end();
  await authPool?.end();
  process.exit(1);
}
