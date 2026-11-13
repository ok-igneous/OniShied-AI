import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { OperatorAccountLifecycle } from "./operator-account-lifecycle.js";

const invitationSchema = z.object({
  email: z.string().email().max(254),
  displayName: z.string().trim().min(1).max(120),
  role: z.enum(["admin", "security_analyst", "reviewer", "viewer"])
}).strict();
const emailSchema = z.object({ email: z.string().email().max(254) }).strict();
const tokenSchema = z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict();
const passwordSchema = z.object({
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  password: z.string().min(12).max(256)
}).strict();

function bearer(header: string | undefined): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

export function registerOperatorAccountRoutes(
  app: FastifyInstance,
  lifecycle: OperatorAccountLifecycle | null
): void {
  app.post("/v1/operator/invitations", async (request, reply) => {
    if (!lifecycle) return reply.code(503).send({ error: "email_delivery_not_configured" });
    const token = bearer(request.headers.authorization);
    const parsed = invitationSchema.safeParse(request.body);
    if (!token) return reply.code(401).send({ error: "unauthorized" });
    if (!parsed.success) return reply.code(400).send({ error: "invalid_invitation_request" });
    try {
      await lifecycle.createInvitation(token, parsed.data);
      reply.header("cache-control", "no-store");
      return reply.code(202).send({ status: "invitation_sent" });
    } catch (error) {
      if (error instanceof Error && /Forbidden/.test(error.message)) {
        return reply.code(403).send({ error: "forbidden" });
      }
      if (error instanceof Error && /already belongs|already exists/.test(error.message)) {
        return reply.code(409).send({ error: "invitation_not_available" });
      }
      request.log.error({ err: error }, "Operator invitation delivery failed");
      return reply.code(503).send({ error: "invitation_delivery_unavailable" });
    }
  });

  app.post("/v1/operator/email/verification/request", async (request, reply) => {
    if (!lifecycle) return reply.code(503).send({ error: "email_delivery_not_configured" });
    const parsed = emailSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_email_request" });
    try {
      await lifecycle.requestEmailVerification(parsed.data.email, request.ip);
      reply.header("cache-control", "no-store");
      return reply.code(202).send({ status: "if_account_requires_verification_email_will_be_sent" });
    } catch (error) {
      if (error instanceof Error && /rate limited/.test(error.message)) {
        return reply.code(429).send({ error: "too_many_requests" });
      }
      request.log.error({ err: error }, "Email verification request failed");
      return reply.code(503).send({ error: "email_action_unavailable" });
    }
  });

  app.post("/v1/operator/email/verification/confirm", async (request, reply) => {
    if (!lifecycle) return reply.code(503).send({ error: "email_delivery_not_configured" });
    const parsed = tokenSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_verification_token" });
    try {
      const verified = await lifecycle.verifyEmail(parsed.data.token);
      if (!verified) return reply.code(400).send({ error: "invalid_or_expired_token" });
      reply.header("cache-control", "no-store");
      return reply.code(204).send();
    } catch {
      return reply.code(400).send({ error: "invalid_or_expired_token" });
    }
  });

  app.post("/v1/operator/password-reset/request", async (request, reply) => {
    if (!lifecycle) return reply.code(503).send({ error: "email_delivery_not_configured" });
    const parsed = emailSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_email_request" });
    try {
      await lifecycle.requestPasswordReset(parsed.data.email, request.ip);
      reply.header("cache-control", "no-store");
      return reply.code(202).send({ status: "if_account_exists_email_will_be_sent" });
    } catch (error) {
      if (error instanceof Error && /rate limited/.test(error.message)) {
        return reply.code(429).send({ error: "too_many_requests" });
      }
      request.log.error({ err: error }, "Password reset request failed");
      return reply.code(503).send({ error: "email_action_unavailable" });
    }
  });

  app.post("/v1/operator/password-reset/confirm", async (request, reply) => {
    if (!lifecycle) return reply.code(503).send({ error: "email_delivery_not_configured" });
    const parsed = passwordSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_password_reset_request" });
    try {
      const reset = await lifecycle.resetPassword(parsed.data.token, parsed.data.password);
      if (!reset) return reply.code(400).send({ error: "invalid_or_expired_token" });
      reply.header("cache-control", "no-store");
      return reply.code(204).send();
    } catch (error) {
      if (error instanceof Error && /Password must contain/.test(error.message)) {
        return reply.code(400).send({ error: "invalid_password" });
      }
      return reply.code(400).send({ error: "invalid_or_expired_token" });
    }
  });

  app.post("/v1/operator/invitations/accept", async (request, reply) => {
    if (!lifecycle) return reply.code(503).send({ error: "email_delivery_not_configured" });
    const parsed = passwordSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_invitation_acceptance" });
    try {
      const account = await lifecycle.acceptInvitation(parsed.data.token, parsed.data.password);
      reply.header("cache-control", "no-store");
      return reply.code(201).send({ account });
    } catch (error) {
      if (error instanceof Error && /Password must contain/.test(error.message)) {
        return reply.code(400).send({ error: "invalid_password" });
      }
      return reply.code(400).send({ error: "invalid_or_expired_invitation" });
    }
  });
}
