import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { z } from "zod";
import { endpointTelemetryBatchSchema } from "./endpoint-telemetry.js";

function credentialHash(header: string | undefined): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return createHash("sha256").update(token,"utf8").digest("hex");
}

export function registerEndpointTelemetryRoutes(
  app: FastifyInstance,
  database: Pick<Pool,"query"> | null
): void {
  app.post("/v1/endpoints/telemetry",async(request,reply)=>{
    const hash=credentialHash(request.headers.authorization);
    if(!hash) return reply.code(401).send({error:"unauthorized_endpoint"});
    if(!database) return reply.code(503).send({error:"endpoint_telemetry_unavailable"});
    const parsed=endpointTelemetryBatchSchema.safeParse(request.body);
    if(!parsed.success) return reply.code(400).send({
      error:"invalid_endpoint_telemetry",
      details:parsed.error.issues.map(issue=>({path:issue.path.join("."),message:issue.message}))
    });
    try {
      const result=await database.query<{
        accepted_count:number;duplicate_count:number;agent_id:string
      }>(
        "SELECT * FROM onishield.ingest_endpoint_telemetry($1,$2::jsonb)",
        [hash,JSON.stringify(parsed.data.events)]
      );
      const outcome=result.rows[0];
      if(!outcome) throw new Error("Endpoint telemetry function returned no result");
      reply.header("cache-control","no-store");
      return reply.code(outcome.accepted_count>0?202:200).send({
        status:outcome.accepted_count>0?"accepted":"duplicate",
        agentId:outcome.agent_id,
        accepted:outcome.accepted_count,
        duplicates:outcome.duplicate_count
      });
    } catch(error) {
      if(error instanceof Error && /Unauthorized endpoint credential/.test(error.message)) {
        return reply.code(401).send({error:"unauthorized_endpoint"});
      }
      if(error instanceof Error && /Endpoint event identity or platform mismatch|Invalid endpoint telemetry batch|Invalid endpoint event identity/.test(error.message)) {
        return reply.code(400).send({error:"invalid_endpoint_telemetry"});
      }
      if(error instanceof Error && /Endpoint sequence replay conflict/.test(error.message)) {
        return reply.code(409).send({error:"endpoint_sequence_conflict"});
      }
      request.log.error({err:error},"Endpoint telemetry ingestion failed");
      return reply.code(503).send({error:"endpoint_telemetry_unavailable"});
    }
  });
}
