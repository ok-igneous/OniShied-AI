import { z } from "zod";

const sourceSchema = z.object({
  connector_id: z.string().min(1).max(128),
  kind: z.string().min(1).max(64),
  version: z.string().max(64).optional(),
  host_ref: z.string().max(128).optional()
}).strict();

const provenanceSchema = z.object({
  record_ref: z.string().min(1).max(256),
  collection_method: z.enum([
    "agent",
    "api",
    "syslog",
    "file_import",
    "synthetic_replay"
  ]),
  raw_digest: z.string().regex(/^[a-f0-9]{64}$/).optional()
}).strict();

export const securityEventSchema = z.object({
  schema_version: z.literal("0.1.0"),
  event_id: z.string().min(1).max(128),
  tenant_id: z.string().min(1).max(128),
  source: sourceSchema,
  event_type: z.string()
    .regex(/^[a-z0-9]+(\.[a-z0-9_-]+){1,5}$/)
    .max(128),
  observed_at: z.string().datetime({ offset: true }),
  ingested_at: z.string().datetime({ offset: true }).optional(),
  severity_hint: z.enum(["unknown", "info", "low", "medium", "high", "critical"]).optional(),
  provenance: provenanceSchema,
  data: z.record(z.unknown()).refine(
    (value) => Object.keys(value).length <= 100,
    "data may contain at most 100 top-level properties"
  )
}).strict();

export type SecurityEventInput = z.infer<typeof securityEventSchema>;
