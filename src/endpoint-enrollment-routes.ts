import { createHash, randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Pool } from "pg";
import type { OperatorAuthService } from "./operator-auth-service.js";
import { hashOperatorSessionToken } from "./operator-auth-crypto.js";

function bearer(header: string | undefined): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const token=header.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}
function sha256(value: string): string {
  return createHash("sha256").update(value,"utf8").digest("hex");
}

export function registerEndpointEnrollmentRoutes(
  app: FastifyInstance,
  operatorAuth: OperatorAuthService | null,
  authDatabase: Pick<Pool,"query"> | null,
  applicationDatabase: Pick<Pool,"query"> | null
): void {
  app.post("/v1/operator/endpoints/enrollment-tokens",async(request,reply)=>{
    if(!operatorAuth || !authDatabase) return reply.code(503).send({error:"endpoint_enrollment_unavailable"});
    const session=bearer(request.headers.authorization);
    const parsed=z.object({
      displayName:z.string().trim().min(1).max(120),
      platform:z.enum(["windows","linux"])
    }).strict().safeParse(request.body);
    if(!session) return reply.code(401).send({error:"unauthorized"});
    if(!parsed.success) return reply.code(400).send({error:"invalid_enrollment_request"});
    try {
      await operatorAuth.authorize(session,"operator:admin");
      const enrollmentToken=randomBytes(32).toString("base64url");
      const result=await authDatabase.query<{expires_at:Date|string}>(
        "SELECT * FROM onishield.create_endpoint_enrollment_token($1,$2,$3,$4)",
        [hashOperatorSessionToken(session),sha256(enrollmentToken),parsed.data.displayName,parsed.data.platform]
      );
      const expiresAt=result.rows[0]?.expires_at;
      if(!expiresAt) throw new Error("Enrollment token was not created");
      reply.header("cache-control","no-store");
      reply.header("pragma","no-cache");
      return reply.code(201).send({token:enrollmentToken,expiresAt:new Date(expiresAt).toISOString(),platform:parsed.data.platform});
    } catch(error) {
      if(error instanceof Error && error.message==="unauthorized") return reply.code(401).send({error:"unauthorized"});
      if(error instanceof Error && error.message==="forbidden") return reply.code(403).send({error:"forbidden"});
      if(error instanceof Error && /Step-up authentication required/.test(error.message)) return reply.code(428).send({error:"step_up_required"});
      request.log.error({err:error},"Endpoint enrollment token creation failed");
      return reply.code(503).send({error:"endpoint_enrollment_unavailable"});
    }
  });

  app.post("/v1/endpoints/enroll",async(request,reply)=>{
    if(!applicationDatabase) return reply.code(503).send({error:"endpoint_enrollment_unavailable"});
    const parsed=z.object({
      token:z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      hostname:z.string().trim().min(1).max(255),
      agentVersion:z.string().min(1).max(64),
      platform:z.enum(["windows","linux"])
    }).strict().safeParse(request.body);
    if(!parsed.success) return reply.code(400).send({error:"invalid_enrollment_claim"});
    const credential=randomBytes(32).toString("base64url");
    try {
      const result=await applicationDatabase.query<{agent_id:string;display_name:string;platform:string}>(
        "SELECT agent_id,display_name,platform FROM onishield.claim_endpoint_enrollment($1,$2,$3,$4,$5)",
        [sha256(parsed.data.token),sha256(credential),parsed.data.hostname,parsed.data.agentVersion,parsed.data.platform]
      );
      const agent=result.rows[0];
      if(!agent) return reply.code(401).send({error:"invalid_or_expired_enrollment_token"});
      reply.header("cache-control","no-store");
      reply.header("pragma","no-cache");
      return reply.code(201).send({agentId:agent.agent_id,credential,displayName:agent.display_name,platform:agent.platform});
    } catch(error) {
      if(error instanceof Error && /Invalid or expired endpoint enrollment token|Invalid endpoint enrollment claim/.test(error.message)) {
        return reply.code(401).send({error:"invalid_or_expired_enrollment_token"});
      }
      request.log.error({err:error},"Endpoint enrollment claim failed");
      return reply.code(503).send({error:"endpoint_enrollment_unavailable"});
    }
  });

  app.post<{Params:{agentId:string}}>("/v1/operator/endpoints/:agentId/revoke",async(request,reply)=>{
    if(!operatorAuth || !authDatabase) return reply.code(503).send({error:"endpoint_management_unavailable"});
    const session=bearer(request.headers.authorization);
    const parsed=z.object({reason:z.string().trim().min(10).max(500)}).strict().safeParse(request.body);
    if(!session) return reply.code(401).send({error:"unauthorized"});
    if(!z.string().uuid().safeParse(request.params.agentId).success || !parsed.success) {
      return reply.code(400).send({error:"invalid_endpoint_revocation"});
    }
    try {
      await operatorAuth.authorize(session,"operator:admin");
      const result=await authDatabase.query<{revoke_endpoint_agent:boolean}>(
        "SELECT onishield.revoke_endpoint_agent($1,$2,$3)",
        [hashOperatorSessionToken(session),request.params.agentId,parsed.data.reason]
      );
      if(result.rows[0]?.revoke_endpoint_agent!==true) return reply.code(404).send({error:"endpoint_not_found_or_already_revoked"});
      reply.header("cache-control","no-store");
      return reply.code(200).send({revoked:true});
    } catch(error) {
      if(error instanceof Error && error.message==="unauthorized") return reply.code(401).send({error:"unauthorized"});
      if(error instanceof Error && error.message==="forbidden") return reply.code(403).send({error:"forbidden"});
      if(error instanceof Error && /Step-up authentication required/.test(error.message)) return reply.code(428).send({error:"step_up_required"});
      request.log.error({err:error},"Endpoint credential revocation failed");
      return reply.code(503).send({error:"endpoint_management_unavailable"});
    }
  });
}
