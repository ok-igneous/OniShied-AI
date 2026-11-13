import { withTenantTransaction } from "./database.js";
import {
  matchThreatIndicators,
  type ThreatIndicator
} from "./threat-intelligence.js";

const MAX_INDICATOR_CANDIDATES = 10_000;

interface StoredEventRow {
  event_json: unknown;
}

interface StoredMatchRow {
  id: string;
  matched_at: string;
}

interface StoredIndicatorRow {
  id: string;
  version: number;
  indicator_type: ThreatIndicator["type"];
  value_normalized: string;
  status: ThreatIndicator["status"];
  valid_from: string;
  expires_at: string | null;
  confidence: number;
  tlp: ThreatIndicator["tlp"];
  source_id: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Matches one stored event inside a tenant-scoped transaction.
 * This performs no network requests and never executes response actions.
 */
export async function matchStoredEventIndicators(input: {
  tenantId: string;
  connectorId: string;
  eventId: string;
}) {
  if (!input.tenantId || !input.connectorId || !input.eventId) {
    throw new Error("Tenant, connector, and event identifiers are required");
  }

  return withTenantTransaction(input.tenantId, async (client) => {
    const eventResult = await client.query<StoredEventRow>(
      "SELECT event_json FROM onishield.security_events " +
      "WHERE tenant_id = $1 AND connector_id = $2 AND event_id = $3 LIMIT 1",
      [input.tenantId, input.connectorId, input.eventId]
    );

    if (eventResult.rowCount !== 1) {
      throw new Error("Security event not found in the requested tenant scope");
    }

    const eventDocument = eventResult.rows[0]?.event_json;
    if (!isRecord(eventDocument) || !isRecord(eventDocument.data)) {
      throw new Error("Stored security event has an invalid data structure");
    }

    const indicatorResult = await client.query<StoredIndicatorRow>(
      "SELECT id::text, version, indicator_type, value_normalized, " +
      "status, valid_from::text, expires_at::text, confidence, tlp, source_id::text " +
      "FROM onishield.threat_indicators " +
      "WHERE tenant_id = $1 AND status = 'active' AND valid_from <= NOW() " +
      "AND (expires_at IS NULL OR expires_at > NOW()) " +
      "ORDER BY id LIMIT $2",
      [input.tenantId, MAX_INDICATOR_CANDIDATES + 1]
    );

    if (indicatorResult.rows.length > MAX_INDICATOR_CANDIDATES) {
      throw new Error("Tenant threat indicator candidate limit exceeded");
    }

    const indicators: ThreatIndicator[] = indicatorResult.rows.map((row) => ({
      id: row.id,
      version: row.version,
      type: row.indicator_type,
      value_normalized: row.value_normalized,
      status: row.status,
      valid_from: row.valid_from,
      expires_at: row.expires_at,
      confidence: row.confidence,
      tlp: row.tlp,
      source_id: row.source_id
    }));

    const matches = matchThreatIndicators({
      eventId: input.eventId,
      data: eventDocument.data,
      indicators
    });

    const persistedMatches: Array<typeof matches[number] & {
      tenant_id: string;
      match_id: string;
    }> = [];

    for (const match of matches) {
      const values = [
        input.tenantId,
        match.event_id,
        match.indicator_id,
        match.indicator_version,
        match.matched_field_path,
        match.matcher_version
      ];

      const inserted = await client.query<StoredMatchRow>(
        "INSERT INTO onishield.threat_indicator_matches " +
        "(tenant_id, event_id, indicator_id, indicator_version, " +
        "matched_field_path, matcher_version, matched_at) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7) " +
        "ON CONFLICT (tenant_id, event_id, indicator_id, indicator_version, " +
        "matched_field_path, matcher_version) DO NOTHING " +
        "RETURNING id::text, matched_at::text",
        [...values, match.matched_at]
      );

      const stored = inserted.rows[0] ?? (await client.query<StoredMatchRow>(
        "SELECT id::text, matched_at::text " +
        "FROM onishield.threat_indicator_matches " +
        "WHERE tenant_id = $1 AND event_id = $2 AND indicator_id = $3 " +
        "AND indicator_version = $4 AND matched_field_path = $5 " +
        "AND matcher_version = $6",
        values
      )).rows[0];

      if (!stored) {
        throw new Error("Persisted threat indicator match could not be read");
      }

      persistedMatches.push({
        ...match,
        tenant_id: input.tenantId,
        match_id: stored.id,
        matched_at: stored.matched_at
      });
    }

    return persistedMatches;
  });
}
