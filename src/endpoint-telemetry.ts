import { z } from "zod";
const digestSchema = z.string().regex(/^[a-f0-9]{64}$/);
const opaqueRefSchema = z.string().regex(/^[a-f0-9]{64}$/);
const base = {
  agent_id: z.string().uuid(), event_id: z.string().uuid(),
  sequence: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  boot_id: z.string().uuid(),
  observed_at: z.string().datetime({ offset: true }),
  collected_at: z.string().datetime({ offset: true }),
  agent_version: z.string().min(1).max(64), platform: z.enum(["windows", "linux"])
};
const heartbeat = z.object({
  ...base, kind: z.literal("heartbeat"),
  data: z.object({
    os_version: z.string().min(1).max(128), hostname: z.string().min(1).max(255),
    capabilities: z.array(z.enum(["process_start","authentication","network_connection","file_integrity","service_change"])).max(5),
    clock_skew_ms: z.number().int().min(-86400000).max(86400000)
  }).strict()
}).strict();
const processStart = z.object({
  ...base, kind: z.literal("process_start"),
  data: z.object({
    process_id: z.number().int().positive().max(4294967295),
    parent_process_id: z.number().int().positive().max(4294967295).optional(),
    image_path_ref: opaqueRefSchema, image_sha256: digestSchema.optional(),
    signer_status: z.enum(["valid","invalid","unsigned","unknown"])
  }).strict()
}).strict();
const authentication = z.object({
  ...base, kind: z.literal("authentication"),
  data: z.object({
    result: z.enum(["success","failure"]),
    mechanism: z.enum(["interactive","remote","service","privilege","unknown"]),
    principal_ref: opaqueRefSchema, source_address: z.string().ip().optional()
  }).strict()
}).strict();
const networkConnection = z.object({
  ...base, kind: z.literal("network_connection"),
  data: z.object({
    protocol: z.enum(["tcp","udp"]), direction: z.enum(["outbound","inbound"]),
    local_port: z.number().int().min(1).max(65535),
    remote_port: z.number().int().min(1).max(65535),
    remote_address: z.string().ip(),
    process_id: z.number().int().positive().max(4294967295).optional()
  }).strict()
}).strict();
const fileIntegrity = z.object({
  ...base, kind: z.literal("file_integrity"),
  data: z.object({
    action: z.enum(["created","modified","deleted"]), path_ref: opaqueRefSchema,
    previous_sha256: digestSchema.optional(), current_sha256: digestSchema.optional(),
    monitored_scope: z.enum(["system","startup","application_config"])
  }).strict().refine(
    value => value.action !== "deleted" || value.current_sha256 === undefined,
    "deleted files cannot have a current content digest"
  )
}).strict();
const serviceChange = z.object({
  ...base, kind: z.literal("service_change"),
  data: z.object({
    action: z.enum(["installed","started","stopped","removed","configuration_changed"]),
    service_ref: opaqueRefSchema, binary_sha256: digestSchema.optional()
  }).strict()
}).strict();

/** Tenant scope must come from the authenticated device credential, never this payload. */
export const endpointTelemetryEventSchema = z.discriminatedUnion("kind", [
  heartbeat, processStart, authentication, networkConnection, fileIntegrity, serviceChange
]);
export const endpointTelemetryBatchSchema = z.object({
  events: z.array(endpointTelemetryEventSchema).min(1).max(100)
}).strict().superRefine((batch, context) => {
  const sequenceIdentities = new Set<string>();
  const eventIds = new Set<string>();
  const batchAgentId = batch.events[0]?.agent_id;
  for (const [index, event] of batch.events.entries()) {
    const sequenceIdentity = JSON.stringify([event.agent_id,event.boot_id,event.sequence]);
    if (sequenceIdentities.has(sequenceIdentity)) context.addIssue({
      code: z.ZodIssueCode.custom, path: ["events",index,"sequence"],
      message: "duplicate agent sequence within batch"
    });
    sequenceIdentities.add(sequenceIdentity);

    if (eventIds.has(event.event_id)) context.addIssue({
      code: z.ZodIssueCode.custom, path: ["events",index,"event_id"],
      message: "duplicate event ID within batch"
    });
    eventIds.add(event.event_id);

    if (event.agent_id !== batchAgentId) context.addIssue({
      code: z.ZodIssueCode.custom, path: ["events",index,"agent_id"],
      message: "all events in a batch must belong to the same agent"
    });

    if (Date.parse(event.collected_at) < Date.parse(event.observed_at) - 300000) context.addIssue({
      code: z.ZodIssueCode.custom, path: ["events",index,"collected_at"],
      message: "collection time cannot precede observation by more than five minutes"
    });
  }
});
export type EndpointTelemetryEvent = z.infer<typeof endpointTelemetryEventSchema>;
export type EndpointTelemetryBatch = z.infer<typeof endpointTelemetryBatchSchema>;
