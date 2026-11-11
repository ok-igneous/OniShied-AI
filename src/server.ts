import Fastify from "fastify";
import { timingSafeEqual } from "node:crypto";
import { config } from "./config.js";
import { pool, withTenantTransaction } from "./database.js";
import { securityEventSchema } from "./security-event.js";
import { securityEventDigest } from "./security-event-digest.js";

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
  process.exit(1);
}
