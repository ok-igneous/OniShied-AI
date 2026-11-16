import { withTenantTransaction } from "./database.js";
import { evaluateAndPersistAroundEvent } from "./detection-finding-store.js";
import { securityEventSchema } from "./security-event.js";

type ClaimedJob = {
  id: string;
  event_json: unknown;
};

/** Insert this job in the same transaction as the accepted event. */
export async function enqueueDetectionEvaluation(
  client: import("pg").PoolClient,
  tenantId: string,
  connectorId: string,
  eventId: string
): Promise<void> {
  await client.query(
    `INSERT INTO onishield.detection_evaluation_jobs
       (tenant_id, connector_id, event_id)
     VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING`,
    [tenantId, connectorId, eventId]
  );
}

/**
 * Claims one job using SKIP LOCKED. Expired leases are reclaimable after a
 * process crash. The event is read under the same tenant transaction.
 */
async function claimDetectionJob(tenantId: string): Promise<ClaimedJob | null> {
  return withTenantTransaction(tenantId, async (client) => {
    const result = await client.query<ClaimedJob>(
      `WITH candidate AS (
         SELECT j.id, j.connector_id, j.event_id
           FROM onishield.detection_evaluation_jobs AS j
          WHERE j.tenant_id = $1
            AND (
              (j.status = 'pending' AND j.available_at <= NOW())
              OR (j.status = 'processing' AND j.locked_at < NOW() - INTERVAL '10 minutes')
            )
          ORDER BY j.available_at ASC, j.id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE onishield.detection_evaluation_jobs AS j
          SET status = 'processing',
              attempts = j.attempts + 1,
              locked_at = NOW(),
              updated_at = NOW()
         FROM candidate AS c
         JOIN onishield.security_events AS e
           ON e.tenant_id = $1
          AND e.connector_id = c.connector_id
          AND e.event_id = c.event_id
        WHERE j.id = c.id
       RETURNING j.id::text, e.event_json`,
      [tenantId]
    );
    return result.rows[0] ?? null;
  });
}

async function markDetectionJobCompleted(tenantId: string, jobId: string): Promise<void> {
  await withTenantTransaction(tenantId, async (client) => {
    await client.query(
      `UPDATE onishield.detection_evaluation_jobs
          SET status = 'completed', locked_at = NULL, completed_at = NOW(),
              last_error_code = NULL, updated_at = NOW()
        WHERE tenant_id = $1 AND id = $2 AND status = 'processing'`,
      [tenantId, jobId]
    );
  });
}

async function markDetectionJobFailed(
  tenantId: string,
  jobId: string,
  errorCode: string
): Promise<void> {
  await withTenantTransaction(tenantId, async (client) => {
    await client.query(
      `UPDATE onishield.detection_evaluation_jobs
          SET status = CASE WHEN attempts >= 8 THEN 'dead_letter' ELSE 'pending' END,
              locked_at = NULL,
              available_at = NOW() + make_interval(
                secs => LEAST(3600, 5 * (2 ^ LEAST(attempts, 10))::integer)
              ),
              last_error_code = $3,
              updated_at = NOW()
        WHERE tenant_id = $1 AND id = $2 AND status = 'processing'`,
      [tenantId, jobId, errorCode]
    );
  });
}

/** Process at most one tenant job. Safe to invoke repeatedly from a worker loop. */
export async function processOneDetectionEvaluation(tenantId: string): Promise<boolean> {
  const job = await claimDetectionJob(tenantId);
  if (!job) return false;

  try {
    const parsed = securityEventSchema.safeParse(job.event_json);
    if (!parsed.success || parsed.data.tenant_id !== tenantId) {
      await markDetectionJobFailed(tenantId, job.id, "invalid_stored_event");
      return true;
    }
    await evaluateAndPersistAroundEvent(tenantId, parsed.data);
    await markDetectionJobCompleted(tenantId, job.id);
  } catch (error) {
    const code = error instanceof Error &&
      error.message === "Detection evaluation window exceeds the 5000-event safety limit"
      ? "evaluation_window_overflow"
      : "evaluation_failed";
    await markDetectionJobFailed(tenantId, job.id, code);
  }
  return true;
}

/** Read the durable state for one event without exposing another tenant's jobs. */
export async function getDetectionEvaluationStatus(
  tenantId: string,
  connectorId: string,
  eventId: string
): Promise<"pending" | "processing" | "completed" | "failed"> {
  return withTenantTransaction(tenantId, async (client) => {
    const result = await client.query<{ status: string }>(
      `SELECT status
         FROM onishield.detection_evaluation_jobs
        WHERE tenant_id = $1 AND connector_id = $2 AND event_id = $3`,
      [tenantId, connectorId, eventId]
    );
    const status = result.rows[0]?.status;
    if (status === "completed") return "completed";
    if (status === "processing") return "processing";
    if (status === "dead_letter") return "failed";
    return "pending";
  });
}
