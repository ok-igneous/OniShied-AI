import { readFileSync } from "node:fs";
import type { FastifyInstance } from "fastify";

const consoleHtml = readFileSync(new URL("../public/operator-investigation-console.html", import.meta.url), "utf8");

export function registerOperatorInvestigationConsole(app: FastifyInstance): void {
  app.get("/operator", async (_request, reply) => {
    reply
      .header("cache-control", "no-store")
      .header("x-content-type-options", "nosniff")
      .header("referrer-policy", "no-referrer")
      .header("content-security-policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
      .type("text/html; charset=utf-8");
    return reply.send(consoleHtml);
  });
}
