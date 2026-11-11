import "dotenv/config";
import { z } from "zod";

const configSchema = z.object({
  APP_ENV: z.enum(["development", "test", "production"]).default("development"),
  APP_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().min(1),
  LAB_CONNECTOR_ID: z.string().min(1).max(128),
  LAB_CONNECTOR_TOKEN: z.string().min(32),
  LAB_TENANT_ID: z.string().min(1).max(128)
});

const parsed = configSchema.safeParse(process.env);

if (!parsed.success) {
  const details = parsed.error.issues
    .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    .join("; ");
  throw new Error(`Invalid environment configuration: ${details}`);
}

export const config = {
  environment: parsed.data.APP_ENV,
  port: parsed.data.APP_PORT,
  databaseUrl: parsed.data.DATABASE_URL,
  connectorId: parsed.data.LAB_CONNECTOR_ID,
  connectorToken: parsed.data.LAB_CONNECTOR_TOKEN,
  tenantId: parsed.data.LAB_TENANT_ID
} as const;
