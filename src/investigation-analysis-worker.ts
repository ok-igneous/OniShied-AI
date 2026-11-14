import { setTimeout as delay } from "node:timers/promises";
import { config } from "./config.js";
import { authPool, pool, withTenantTransaction } from "./database.js";
import { generateInvestigationReport } from "./investigation-analysis.js";
import { investigationRetryDelayMs } from "./investigation-analysis-policy.js";

const POLL_INTERVAL_MS = 2_000;
const LEASE_MS = 180_000;
const MAX_ATTEMPTS = 6;

type ClaimedJob = {
  job_id: string;
  case_id: string;
  lease_token: string;
  attempts: number;
  input: unknown;
};

async function claimOne(): Promise<ClaimedJob | null> {
  return withTenantTransaction(config.tenantId, async (client) => {
    const result = await client.query<ClaimedJob>(
      "SELECT * FROM onishield.claim_investigation_analysis_job($1,$2)",
      [config.tenantId, LEASE_MS]
    );
    return result.rows[0] ?? null;
  });
}

async function complete(job: ClaimedJob): Promise<void> {
  const generated = await generateInvestigationReport(
    job.input,
    config.openAiApiKey!,
    config.openAiModel!
  );
  await withTenantTransaction(config.tenantId, async (client) => {
    await client.query(
      "SELECT onishield.complete_investigation_analysis_job($1,$2::uuid,$3::uuid,$4,$5,$6,$7,$8::jsonb)",
      [
        config.tenantId, job.job_id, job.lease_token, "openai",
        config.openAiModel!, "investigation-report-v1",
        generated.evidenceDigest, JSON.stringify(generated.report)
      ]
    );
  });
}

async function fail(job: ClaimedJob, error: unknown): Promise<void> {
  const message = error instanceof Error ? error.message : "unknown_investigation_analysis_error";
  await withTenantTransaction(config.tenantId, async (client) => {
    await client.query(
      "SELECT onishield.fail_investigation_analysis_job($1,$2::uuid,$3::uuid,$4,$5,$6)",
      [
        config.tenantId, job.job_id, job.lease_token, MAX_ATTEMPTS,
        investigationRetryDelayMs(job.attempts), message.slice(0, 500)
      ]
    );
  });
}

export async function processOneInvestigationAnalysisJob(): Promise<boolean> {
  const job = await claimOne();
  if (!job) return false;
  try {
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

if (!config.openAiApiKey || !config.openAiModel) {
  throw new Error("OPENAI_API_KEY and OPENAI_MODEL are required to start the investigation worker");
}

try {
  await pool.query("SELECT 1");
  console.info("OniShield investigation analysis worker started", {
    tenantId: config.tenantId,
    model: config.openAiModel
  });
  while (!stopping) {
    try {
      const processed = await processOneInvestigationAnalysisJob();
      if (!processed) await delay(POLL_INTERVAL_MS);
    } catch (error) {
      console.error("Investigation analysis failed; retry policy applied", error);
      await delay(POLL_INTERVAL_MS);
    }
  }
} finally {
  await pool.end();
  await authPool?.end();
}
