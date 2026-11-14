import type { PoolClient } from "pg";
import type { DetectionFinding } from "./detection-engine.js";
import { evaluateDetections } from "./detection-engine.js";
import { securityEventSchema, type SecurityEventInput } from "./security-event.js";
import { withTenantTransaction } from "./database.js";

async function insertFindings(
  client: PoolClient,
  tenantId: string,
  findings: readonly DetectionFinding[]
): Promise<number> {
  let insertedCount = 0;
  for (const finding of findings) {
    if (finding.tenant_id !== tenantId) {
      throw new Error("Finding tenant does not match transaction tenant");
    }
    const result = await client.query(
      `INSERT INTO onishield.detection_findings
        (tenant_id, finding_id, rule_id, rule_version, status, title,
         explanation, severity, confidence, first_seen_at, last_seen_at,
         evidence_event_ids, grouping_key_hash, matched_conditions, known_limitations)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
               $12::jsonb, $13, $14::jsonb, $15::jsonb)
       ON CONFLICT (tenant_id, finding_id) DO NOTHING
       RETURNING id`,
      [
        tenantId, finding.finding_id, finding.rule_id, finding.rule_version,
        finding.status, finding.title, finding.explanation, finding.severity,
        finding.confidence, finding.first_seen_at, finding.last_seen_at,
        JSON.stringify(finding.evidence_event_ids), finding.grouping_key_hash,
        JSON.stringify(finding.matched_conditions), JSON.stringify(finding.known_limitations)
      ]
    );
    insertedCount += result.rowCount ?? 0;
  }
  return insertedCount;
}

/** Persists supplied findings idempotently inside an explicit tenant scope. */
export async function persistDetectionFindings(
  tenantId: string,
  findings: readonly DetectionFinding[]
): Promise<number> {
  return withTenantTransaction(tenantId, (client) =>
    insertFindings(client, tenantId, findings)
  );
}

/**
 * Re-evaluates the bounded +/-10 minute neighborhood of an accepted event.
 * This handles out-of-order delivery within that horizon. Older late events
 * require an explicit replay job; this request path never scans the full table.
 */
export async function evaluateAndPersistAroundEvent(
  tenantId: string,
  event: SecurityEventInput
): Promise<number> {
  if (event.tenant_id !== tenantId) {
    throw new Error("Event tenant does not match detection scope");
  }
  return withTenantTransaction(tenantId, async (client) => {
    const rows = await client.query<{ event_json: unknown }>(
      `SELECT event_json
         FROM onishield.security_events
        WHERE tenant_id = $1
          AND observed_at >= $2::timestamptz - INTERVAL '10 minutes'
          AND observed_at <= $2::timestamptz + INTERVAL '10 minutes'
        ORDER BY observed_at ASC, event_id ASC
        LIMIT 5000`,
      [tenantId, event.observed_at]
    );

    const events: SecurityEventInput[] = [];
    for (const row of rows.rows) {
      const parsed = securityEventSchema.safeParse(row.event_json);
      if (parsed.success && parsed.data.tenant_id === tenantId) {
        events.push(parsed.data);
      }
    }

    const findings = evaluateDetections(events);
    return insertFindings(client, tenantId, findings);
  });
}

/** Lists findings only inside an explicit tenant transaction. */
export async function listDetectionFindings(
  tenantId: string,
  limit = 100
): Promise<unknown[]> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
    throw new Error("Finding limit must be between 1 and 500");
  }
  return withTenantTransaction(tenantId, async (client) => {
    const result = await client.query(
      `SELECT finding_id, rule_id, rule_version, status, title, explanation,
              severity, confidence, first_seen_at, last_seen_at,
              evidence_event_ids, grouping_key_hash, matched_conditions,
              known_limitations, created_at, updated_at
         FROM onishield.detection_findings
        WHERE tenant_id = $1
        ORDER BY last_seen_at DESC, id DESC
        LIMIT $2`,
      [tenantId, limit]
    );
    return result.rows;
  });
}
