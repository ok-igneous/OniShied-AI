import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { config } from "./config.js";
import { pool, withTenantTransaction } from "./database.js";
import { evaluateAndPersistAroundEvent } from "./detection-finding-store.js";
import { securityEventSchema } from "./security-event.js";

const POLL_INTERVAL_MS = 2_000;
const LEASE_MS = 120_000;
const MAX_ATTEMPTS = 10;

export function replayRetryDelayMs(attempt: number): number {
  if (!Number.isInteger(attempt) || attempt < 1) {
    throw new Error("Replay attempt must be a positive integer");
  }
  return Math.min(60 * 60_000, 1_000 * 2 ** Math.min(attempt - 1, 12));
}

type ClaimedJob = {
  id: string;
  lease_token: string;
  event_json: unknown;
};

async function claimOne(): Promise<ClaimedJob | null> {
  return withTenantTransaction(config.tenantId, async (client) => {
    const token = randomUUID();
    const result = await client.query<ClaimedJob>(
      `WITH candidate AS (
         SELECT j.id
           FROM onishield.detection_replay_jobs AS j
          WHERE j.tenant_id = $1
            AND (
              (j.status = 'pending' AND j.available_at <= NOW())
              OR (j.status = 'processing' AND j.lease_until < NOW())
            )
          ORDER BY j.available_at ASC, j.id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE onishield.detection_replay_jobs AS j
          SET status = 'processing',
              attempts = j.attempts + 1,
              lease_until = NOW() + ($2 * INTERVAL '1 millisecond'),
              lease_token = $3::uuid,
              updated_at = NOW()
         FROM candidate, onishield.security_events AS e
        WHERE j.id = candidate.id
          AND e.tenant_id = j.tenant_id
          AND e.connector_id = j.connector_id
          AND e.event_id = j.event_id
       RETURNING j.id::text, j.lease_token::text, e.event_json`,
      [config.tenantId, LEASE_MS, token]
    );
    return result.rows[0] ?? null;
  });
}

async function complete(job: ClaimedJob): Promise<void> {
  await withTenantTransaction(config.tenantId, async (client) => {
    await client.query(
      `UPDATE onishield.detection_replay_jobs
          SET status = 'completed', completed_at = NOW(),
              lease_until = NULL, lease_token = NULL,
              last_error = NULL, updated_at = NOW()
        WHERE tenant_id = $1 AND id = $2
          AND status = 'processing' AND lease_token = $3::uuid`,
      [config.tenantId, job.id, job.lease_token]
    );
  });
}

async function fail(job: ClaimedJob, error: unknown): Promise<void> {
  const message = error instanceof Error ? error.message : "unknown_detection_error";
  await withTenantTransaction(config.tenantId, async (client) => {
    await client.query(
      `UPDATE onishield.detection_replay_jobs
          SET status = CASE WHEN attempts >= $4 THEN 'dead_letter' ELSE 'pending' END,
              available_at = CASE
                WHEN attempts >= $4 THEN available_at
                ELSE NOW() + ($5 * INTERVAL '1 millisecond')
              END,
              lease_until = NULL, lease_token = NULL,
              last_error = $6, updated_at = NOW()
        WHERE tenant_id = $1 AND id = $2
          AND status = 'processing' AND lease_token = $3::uuid`,
      [
        config.tenantId,
        job.id,
        job.lease_token,
        MAX_ATTEMPTS,
        replayRetryDelayMs(1),
        message.slice(0, 500)
      ]
    );
  });
}

export async function processOneReplayJob(): Promise<boolean> {
  const job = await claimOne();
  if (!job) return false;

  try {
    const parsed = securityEventSchema.safeParse(job.event_json);
    if (!parsed.success || parsed.data.tenant_id !== config.tenantId) {
      throw new Error("replay_event_invalid_or_outside_tenant_scope");
    }
    await evaluateAndPersistAroundEvent(config.tenantId, parsed.data);
    await complete(job);
  } catch (error) {
    await fail(job, error);
    throw error;
  }
  return true;
}

let stopping = false;
process.once("SIGINT", () => { stopping = true; });
process.once("SIGTERM", () => { stopping = true; });

try {
  await pool.query("SELECT 1");
  console.info("OniShield detection replay worker started", { tenantId: config.tenantId });
  while (!stopping) {
    try {
      const processed = await processOneReplayJob();
      if (!processed) await delay(POLL_INTERVAL_MS);
    } catch (error) {
      console.error("Detection replay job failed; retry policy applied", error);
      await delay(POLL_INTERVAL_MS);
    }
  }
} finally {
  await pool.end();
}
