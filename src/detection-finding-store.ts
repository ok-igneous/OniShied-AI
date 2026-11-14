import type { PoolClient } from "pg";
import type { DetectionFinding } from "./detection-engine.js";
import { withTenantTransaction } from "./database.js";

/**
 * Persists immutable detection snapshots within the caller's tenant scope.
 * Exact finding replays are idempotent. A changed evidence set has a different
 * finding ID and is a distinct snapshot; lifecycle/correlation is a later layer.
 */
export async function persistDetectionFindings(
  tenantId: string,
  findings: readonly DetectionFinding[]
): Promise<number> {
  return withTenantTransaction(tenantId, async (client: PoolClient) => {
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
  return withTenantTransaction(tenantId, async (client: PoolClient) => {
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
