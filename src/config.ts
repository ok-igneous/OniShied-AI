import "dotenv/config";
import { z } from "zod";

const configSchema = z.object({
  APP_ENV: z.enum(["development", "test", "production"]).default("development"),
  APP_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().min(1),
  AUTH_DATABASE_URL: z.string().min(1).optional(),
  AUTH_RATE_LIMIT_SECRET: z.string().min(32).optional(),
  MFA_ENCRYPTION_KEY: z.string().regex(/^[a-fA-F0-9]{64}$/).optional(),
  MFA_RECOVERY_PEPPER: z.string().min(32).optional(),
  RESEND_API_KEY: z.string().min(20).optional(),
  EMAIL_FROM: z.string().min(3).max(254).optional(),
  APP_PUBLIC_URL: z.string().url().optional(),
  DATABASE_SSL: z.enum(["true", "false"]).default("false"),
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

if (parsed.data.AUTH_DATABASE_URL && !parsed.data.MFA_ENCRYPTION_KEY) {
  throw new Error("MFA_ENCRYPTION_KEY is required when AUTH_DATABASE_URL is configured");
}

if (parsed.data.AUTH_DATABASE_URL && !parsed.data.AUTH_RATE_LIMIT_SECRET) {
  throw new Error("AUTH_RATE_LIMIT_SECRET is required when AUTH_DATABASE_URL is configured");
}

if (parsed.data.AUTH_DATABASE_URL && !parsed.data.MFA_RECOVERY_PEPPER) {
  throw new Error("MFA_RECOVERY_PEPPER is required when AUTH_DATABASE_URL is configured");
}

if (Boolean(parsed.data.RESEND_API_KEY) !== Boolean(parsed.data.EMAIL_FROM) ||
    Boolean(parsed.data.RESEND_API_KEY) !== Boolean(parsed.data.APP_PUBLIC_URL)) {
  throw new Error("RESEND_API_KEY, EMAIL_FROM, and APP_PUBLIC_URL must be configured together");
}

if (parsed.data.APP_ENV === "production" && parsed.data.APP_PUBLIC_URL &&
    !parsed.data.APP_PUBLIC_URL.startsWith("https://")) {
  throw new Error("APP_PUBLIC_URL must use HTTPS in production");
}

if (parsed.data.APP_ENV === "production" && parsed.data.DATABASE_SSL !== "true") {
  throw new Error("DATABASE_SSL=true is required in production");
}

export const config = {
  environment: parsed.data.APP_ENV,
  port: parsed.data.APP_PORT,
  databaseUrl: parsed.data.DATABASE_URL,
  authDatabaseUrl: parsed.data.AUTH_DATABASE_URL,
  authRateLimitSecret: parsed.data.AUTH_RATE_LIMIT_SECRET,
  mfaEncryptionKey: parsed.data.MFA_ENCRYPTION_KEY,
  mfaRecoveryPepper: parsed.data.MFA_RECOVERY_PEPPER,
  resendApiKey: parsed.data.RESEND_API_KEY,
  emailFrom: parsed.data.EMAIL_FROM,
  publicUrl: parsed.data.APP_PUBLIC_URL,
  databaseSsl: parsed.data.DATABASE_SSL === "true",
  connectorId: parsed.data.LAB_CONNECTOR_ID,
  connectorToken: parsed.data.LAB_CONNECTOR_TOKEN,
  tenantId: parsed.data.LAB_TENANT_ID
} as const;
