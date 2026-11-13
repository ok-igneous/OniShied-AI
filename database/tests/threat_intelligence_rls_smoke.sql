-- Verify threat-intelligence tables enforce the same tenant boundary as events.
-- Run as an administrator after migrations; this transaction is fully rolled back.
BEGIN;
SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'ti-tenant-a', true);

WITH source_row AS (
  INSERT INTO onishield.threat_intelligence_sources
    (tenant_id, source_key, display_name, source_kind, license_ref)
  VALUES
    ('ti-tenant-a', 'synthetic-lab', 'Synthetic lab source', 'synthetic', 'internal-test')
  RETURNING tenant_id, id
),
indicator_row AS (
  INSERT INTO onishield.threat_indicators
    (tenant_id, indicator_key, version, indicator_type, value_normalized,
     source_id, source_record_ref, confidence, confidence_rubric_version,
     assessed_by, status, tlp)
  SELECT tenant_id, 'synthetic-indicator-1', 1, 'ipv4', '192.0.2.44',
         id, 'fixture-1', 80, 'test-v1', 'test-reviewer', 'pending', 'green'
    FROM source_row
  RETURNING tenant_id, id, version
)
INSERT INTO onishield.threat_indicator_matches
  (tenant_id, event_id, indicator_id, indicator_version,
   matched_field_path, matcher_version)
SELECT tenant_id, 'synthetic-event-1', id, version,
       'data.source_ip', 'exact-v1'
  FROM indicator_row;

SELECT set_config('app.tenant_id', 'ti-tenant-b', true);

DO $$
DECLARE
  source_count INTEGER;
  indicator_count INTEGER;
  match_count INTEGER;
BEGIN
  SELECT count(*) INTO source_count
    FROM onishield.threat_intelligence_sources;
  SELECT count(*) INTO indicator_count
    FROM onishield.threat_indicators;
  SELECT count(*) INTO match_count
    FROM onishield.threat_indicator_matches;

  IF source_count <> 0 OR indicator_count <> 0 OR match_count <> 0 THEN
    RAISE EXCEPTION 'Threat intelligence RLS failed: cross-tenant rows visible';
  END IF;
END
$$;

ROLLBACK;
