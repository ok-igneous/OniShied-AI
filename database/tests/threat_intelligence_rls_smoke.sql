-- Verify threat-intelligence tables enforce the same tenant boundary as events.
-- Source records are provisioned by the owner; runtime can only read them.
-- This transaction is fully rolled back.
BEGIN;
SELECT set_config('app.tenant_id', 'ti-tenant-a', true);
SET LOCAL ROLE onishield_owner;

INSERT INTO onishield.threat_intelligence_sources
  (tenant_id, source_key, display_name, source_kind, license_ref)
VALUES
  ('ti-tenant-a', 'synthetic-lab', 'Synthetic lab source', 'synthetic', 'internal-test');

SET LOCAL ROLE onishield_app;

WITH source_row AS (
  SELECT tenant_id, id
    FROM onishield.threat_intelligence_sources
   WHERE source_key = 'synthetic-lab'
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
  FROM indicator_row
ON CONFLICT (
  tenant_id, event_id, indicator_id, indicator_version,
  matched_field_path, matcher_version
) DO NOTHING;

-- A replay of the same evidence must not create a second match row.
INSERT INTO onishield.threat_indicator_matches
  (tenant_id, event_id, indicator_id, indicator_version,
   matched_field_path, matcher_version)
SELECT tenant_id, 'synthetic-event-1', id, version,
       'data.source_ip', 'exact-v1'
  FROM onishield.threat_indicators
 WHERE indicator_key = 'synthetic-indicator-1'
ON CONFLICT (
  tenant_id, event_id, indicator_id, indicator_version,
  matched_field_path, matcher_version
) DO NOTHING;

DO $$
DECLARE
  match_count INTEGER;
BEGIN
  SELECT count(*) INTO match_count
    FROM onishield.threat_indicator_matches
   WHERE event_id = 'synthetic-event-1';
  IF match_count <> 1 THEN
    RAISE EXCEPTION 'Match replay is not idempotent';
  END IF;

  BEGIN
    INSERT INTO onishield.threat_indicators
      (tenant_id, indicator_key, version, indicator_type, value_normalized,
       source_id, source_record_ref, confidence, confidence_rubric_version,
       assessed_by, status, tlp)
    SELECT tenant_id, 'runtime-active-attempt', 1, 'domain', 'bad.test',
           source_id, 'fixture-active-attempt', 80, 'test-v1',
           'runtime', 'active', 'green'
      FROM onishield.threat_indicators
     WHERE indicator_key = 'synthetic-indicator-1';

    RAISE EXCEPTION 'Runtime unexpectedly inserted an active indicator';
  EXCEPTION
    WHEN insufficient_privilege THEN
      NULL;
  END;
END
$$;

SELECT set_config('app.tenant_id', 'ti-tenant-b', true);

DO $$
DECLARE
  source_count INTEGER;
  indicator_count INTEGER;
  match_count INTEGER;
BEGIN
  SELECT count(*) INTO source_count FROM onishield.threat_intelligence_sources;
  SELECT count(*) INTO indicator_count FROM onishield.threat_indicators;
  SELECT count(*) INTO match_count FROM onishield.threat_indicator_matches;

  IF source_count <> 0 OR indicator_count <> 0 OR match_count <> 0 THEN
    RAISE EXCEPTION 'Threat intelligence RLS failed: cross-tenant rows visible';
  END IF;
END
$$;

ROLLBACK;
