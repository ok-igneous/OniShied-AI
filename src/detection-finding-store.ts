import type { PoolClient } from "pg";
import type { DetectionFinding } from "./detection-engine.js";
import { evaluateDetections } from "./detection-engine.js";
import { securityEventSchema, type SecurityEventInput } from "./security-event.js";
import { withTenantTransaction } from "./database.js";
import { matchEventsIndicatorsInTransaction } from "./threat-intelligence-service.js";

async function insertFindings(
  client: PoolClient,
  tenantId: string,
  findings: readonly DetectionFinding[]
): Promise<{ insertedCount: number; findings: DetectionFinding[] }> {
  let insertedCount = 0;
  const persistedFindings: DetectionFinding[] = [];
  for (const finding of findings) {
    if (finding.tenant_id !== tenantId) {
      throw new Error("Finding tenant does not match transaction tenant");
    }
    // Migration 016 preserves legacy finding IDs and backfills their first
    // evidence reference as the legacy anchor. Reuse that row when its anchor
    // is present in this episode's evidence, rather than creating a duplicate
    // stable-identity row during the first post-upgrade evaluation.
    const legacy = await client.query<{ finding_id: string }>(
      `SELECT f.finding_id
         FROM onishield.detection_findings AS f
        WHERE f.tenant_id = $1
          AND f.finding_id <> $2
          AND f.rule_id = $3
          AND f.rule_version = $4
          AND f.grouping_key_hash = $5
          AND EXISTS (
            SELECT 1
              FROM jsonb_to_recordset($6::jsonb) AS incoming(connector_id TEXT, event_id TEXT)
             WHERE incoming.connector_id = f.episode_anchor_connector_id
               AND incoming.event_id = f.episode_anchor_event_id
          )
        ORDER BY f.created_at ASC, f.finding_id ASC
        LIMIT 1`,
      [tenantId, finding.finding_id, finding.rule_id, finding.rule_version,
       finding.grouping_key_hash, JSON.stringify(finding.evidence_event_refs)]
    );
    const persistedFinding = {
      ...finding,
      finding_id: legacy.rows[0]?.finding_id ?? finding.finding_id
    };
    persistedFindings.push(persistedFinding);
    const result = await client.query<{ inserted: boolean }>(
      `INSERT INTO onishield.detection_findings AS current_finding
        (tenant_id, finding_id, rule_id, rule_version, status, title,
         explanation, severity, confidence, first_seen_at, last_seen_at,
         episode_anchor_connector_id, episode_anchor_event_id,
         evidence_event_ids, evidence_event_refs, grouping_key_hash,
         matched_conditions, known_limitations)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
               $12, $13, $14::jsonb, $15::jsonb, $16, $17::jsonb, $18::jsonb)
       ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
         first_seen_at = LEAST(current_finding.first_seen_at, EXCLUDED.first_seen_at),
         last_seen_at = GREATEST(current_finding.last_seen_at, EXCLUDED.last_seen_at),
         evidence_event_refs = (
           SELECT COALESCE(jsonb_agg(item ORDER BY item->>'connector_id', item->>'event_id'), '[]'::jsonb)
           FROM (
             SELECT DISTINCT item
             FROM jsonb_array_elements(
               current_finding.evidence_event_refs || EXCLUDED.evidence_event_refs
             ) AS refs(item)
           ) AS merged
         ),
         evidence_event_ids = (
           SELECT COALESCE(jsonb_agg(item ORDER BY item), '[]'::jsonb)
           FROM (
             SELECT DISTINCT item
             FROM jsonb_array_elements_text(
               current_finding.evidence_event_ids || EXCLUDED.evidence_event_ids
             ) AS ids(item)
           ) AS merged
         ),
         matched_conditions = (
           SELECT COALESCE(jsonb_agg(item ORDER BY item), '[]'::jsonb)
           FROM (
             SELECT DISTINCT item
             FROM jsonb_array_elements_text(
               current_finding.matched_conditions || EXCLUDED.matched_conditions
             ) AS conditions(item)
           ) AS merged
         ),
         explanation = CASE
           WHEN jsonb_array_length(EXCLUDED.evidence_event_refs) >=
                jsonb_array_length(current_finding.evidence_event_refs)
             THEN EXCLUDED.explanation
           ELSE current_finding.explanation
         END,
         title = EXCLUDED.title,
         updated_at = NOW()
       RETURNING (xmax = 0) AS inserted`,
      [
        tenantId, persistedFinding.finding_id, finding.rule_id, finding.rule_version,
        finding.status, finding.title, finding.explanation, finding.severity,
        finding.confidence, finding.first_seen_at, finding.last_seen_at,
        finding.episode_anchor.connector_id, finding.episode_anchor.event_id,
        JSON.stringify(finding.evidence_event_ids),
        JSON.stringify(finding.evidence_event_refs),
        finding.grouping_key_hash,
        JSON.stringify(finding.matched_conditions),
        JSON.stringify(finding.known_limitations)
      ]
    );
    insertedCount += result.rows.filter((row) => row.inserted).length;

    for (const evidence of finding.evidence_event_refs) {
      await client.query(
        `INSERT INTO onishield.detection_finding_evidence
          (tenant_id, finding_id, connector_id, event_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, finding_id, connector_id, event_id) DO NOTHING`,
        [tenantId, persistedFinding.finding_id, evidence.connector_id, evidence.event_id]
      );
    }
  }
  return { insertedCount, findings: persistedFindings };
}

async function persistFindingThreatMatches(
  client: PoolClient,
  tenantId: string,
  findings: readonly DetectionFinding[],
  evidenceEvents: readonly SecurityEventInput[]
): Promise<void> {
  const referenced = new Set(
    findings.flatMap((finding) => finding.evidence_event_refs.map((ref) =>
      JSON.stringify([ref.connector_id, ref.event_id])
    ))
  );
  const selectedEvents = evidenceEvents.filter((event) =>
    referenced.has(JSON.stringify([event.source.connector_id, event.event_id]))
  );
  if (selectedEvents.length === 0) return;

  // Load the tenant's active indicator set once for this evaluation batch.
  const matches = await matchEventsIndicatorsInTransaction(
    client,
    tenantId,
    selectedEvents
  );
  if (matches.length === 0) return;

  const byEvent = new Map<string, typeof matches>();
  for (const match of matches) {
    const key = JSON.stringify([match.connector_id, match.event_id]);
    const current = byEvent.get(key) ?? [];
    current.push(match);
    byEvent.set(key, current);
  }

  for (const finding of findings) {
    for (const evidence of finding.evidence_event_refs) {
      const key = JSON.stringify([evidence.connector_id, evidence.event_id]);
      for (const match of byEvent.get(key) ?? []) {
        await client.query(
          `INSERT INTO onishield.detection_finding_threat_matches
            (tenant_id, finding_id, connector_id, event_id, threat_match_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (tenant_id, finding_id, threat_match_id) DO NOTHING`,
          [
            tenantId,
            finding.finding_id,
            evidence.connector_id,
            evidence.event_id,
            match.match_id
          ]
        );
      }
    }
  }
}

/** Persists supplied findings idempotently inside an explicit tenant scope. */
export async function persistDetectionFindings(
  tenantId: string,
  findings: readonly DetectionFinding[]
): Promise<number> {
  return withTenantTransaction(tenantId, async (client) =>
    (await insertFindings(client, tenantId, findings)).insertedCount
  );
}

/**
 * Re-evaluates the bounded +/-10 minute neighborhood of an accepted event.
 * Findings and their indicator evidence links are persisted atomically.
 */
export async function evaluateAndPersistAroundEvent(
  tenantId: string,
  event: SecurityEventInput
): Promise<number> {
  if (event.tenant_id !== tenantId) {
    throw new Error("Event tenant does not match detection scope");
  }
  return withTenantTransaction(tenantId, async (client) => {
    // Serialize evaluation for the exact detector grouping keys. Ingestion is
    // already committed before this transaction starts, so a waiter sees the
    // preceding evaluator's committed event and finding writes.
    const principal = typeof event.data.principal_ref === "string"
      ? event.data.principal_ref.trim() : "";
    const host = typeof event.source.host_ref === "string"
      ? event.source.host_ref.trim() : "";
    const lockKeys: string[] = [];
    if (principal && host) {
      lockKeys.push(JSON.stringify(["sequence", tenantId, host, principal]));
      if (event.event_type === "identity.authentication.failure") {
        const address = typeof event.data.source_address === "string"
          ? event.data.source_address.trim() : "";
        if (address) lockKeys.push(JSON.stringify(["burst", tenantId, host, principal, address]));
      }
    }
    for (const key of lockKeys.sort()) {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [key]);
    }

    const rows = await client.query<{ event_json: unknown }>(
      `SELECT event_json
         FROM onishield.security_events
        WHERE tenant_id = $1
          AND observed_at >= $2::timestamptz - INTERVAL '10 minutes'
          AND observed_at <= $2::timestamptz + INTERVAL '10 minutes'
        ORDER BY observed_at ASC, connector_id ASC, event_id ASC
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
    const persisted = await insertFindings(client, tenantId, findings);
    await persistFindingThreatMatches(client, tenantId, persisted.findings, events);
    return persisted.insertedCount;
  });
}

/** Lists findings with only their exact, tenant-scoped threat-match evidence. */
export async function listDetectionFindings(
  tenantId: string,
  limit = 100
): Promise<unknown[]> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
    throw new Error("Finding limit must be between 1 and 500");
  }
  return withTenantTransaction(tenantId, async (client) => {
    const result = await client.query(
      `SELECT f.finding_id, f.rule_id, f.rule_version, f.status, f.title,
              f.explanation, f.severity, f.confidence, f.first_seen_at,
              f.last_seen_at, f.episode_anchor_connector_id, f.episode_anchor_event_id,
              f.evidence_event_ids, f.evidence_event_refs,
              f.grouping_key_hash, f.matched_conditions, f.known_limitations,
              f.created_at, f.updated_at,
              COALESCE((
                SELECT jsonb_agg(
                  jsonb_build_object(
                    'connector_id', l.connector_id,
                    'event_id', l.event_id,
                    'indicator_id', m.indicator_id::text,
                    'indicator_version', m.indicator_version,
                    'indicator_type', i.indicator_type,
                    'matched_field_path', m.matched_field_path,
                    'confidence', i.confidence,
                    'tlp', i.tlp,
                    'indicator_status', i.status,
                    'source_id', i.source_id::text,
                    'matcher_version', m.matcher_version,
                    'matched_at', m.matched_at
                  ) ORDER BY m.matched_at DESC
                )
                FROM onishield.detection_finding_threat_matches AS l
                JOIN onishield.threat_indicator_matches AS m
                  ON m.id = l.threat_match_id
                 AND m.tenant_id = l.tenant_id
                 AND m.connector_id = l.connector_id
                 AND m.event_id = l.event_id
                JOIN onishield.threat_indicators AS i
                  ON i.tenant_id = m.tenant_id
                 AND i.id = m.indicator_id
                 AND i.version = m.indicator_version
                WHERE l.tenant_id = f.tenant_id
                  AND l.finding_id = f.finding_id
              ), '[]'::jsonb) AS threat_intelligence_matches
         FROM onishield.detection_findings AS f
        WHERE f.tenant_id = $1
        ORDER BY f.last_seen_at DESC, f.id DESC
        LIMIT $2`,
      [tenantId, limit]
    );
    return result.rows;
  });
}
