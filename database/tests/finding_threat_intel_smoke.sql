-- Verify finding-to-threat-match evidence links preserve exact event identity.
-- All rows are synthetic and the transaction is rolled back.
BEGIN;
SELECT set_config('app.tenant_id', 'finding-ti-tenant-a', true);
SET LOCAL ROLE onishield_owner;

INSERT INTO onishield.threat_intelligence_sources
  (tenant_id, source_key, display_name, source_kind, license_ref)
VALUES
  ('finding-ti-tenant-a', 'finding-ti-source', 'Finding test source', 'synthetic', 'internal-test');

INSERT INTO onishield.threat_indicators
  (tenant_id, indicator_key, version, indicator_type, value_normalized,
   source_id, source_record_ref, confidence, confidence_rubric_version,
   assessed_by, status, tlp)
SELECT tenant_id, 'finding-ti-indicator', 1, 'domain', 'suspicious.test',
       id, 'finding-fixture', 90, 'test-v1', 'fixture-author', 'pending', 'green'
  FROM onishield.threat_intelligence_sources
 WHERE source_key = 'finding-ti-source';

SET LOCAL ROLE onishield_reviewer;
SELECT set_config('app.threat_review_reason', 'Synthetic CI fixture approval', true);
UPDATE onishield.threat_indicators
   SET status = 'active'
 WHERE tenant_id = 'finding-ti-tenant-a'
   AND indicator_key = 'finding-ti-indicator';

SET LOCAL ROLE onishield_app;

INSERT INTO onishield.security_events
  (tenant_id, connector_id, event_id, schema_version, event_type,
   observed_at, severity_hint, event_json, payload_sha256)
VALUES
  ('finding-ti-tenant-a', 'connector-evidence', 'evt-1', '0.1.0',
   'network.connection.observed', NOW(), 'info',
   '{"data":{"domain":"suspicious.test"}}'::jsonb, repeat('d', 64));

INSERT INTO onishield.threat_indicator_matches
  (tenant_id, connector_id, event_id, indicator_id, indicator_version,
   matched_field_path, matcher_version)
SELECT tenant_id, 'connector-evidence', 'evt-1', id, version,
       'data.domain', 'exact-v1'
  FROM onishield.threat_indicators
 WHERE indicator_key = 'finding-ti-indicator'
ON CONFLICT (
  tenant_id, connector_id, event_id, indicator_id, indicator_version,
  matched_field_path, matcher_version
) DO NOTHING;

INSERT INTO onishield.detection_findings
  (tenant_id, finding_id, rule_id, rule_version, status, title, explanation,
   severity, confidence, first_seen_at, last_seen_at, evidence_event_ids,
   evidence_event_refs, grouping_key_hash, matched_conditions, known_limitations)
VALUES
  ('finding-ti-tenant-a', repeat('c', 64), 'AUTH_FAILURE_BURST', '1.0.0',
   'open', 'Synthetic finding', 'Synthetic test finding', 'medium', 'high',
   NOW(), NOW(), '["connector-evidence:evt-1"]'::jsonb,
   '[{"connector_id":"connector-evidence","event_id":"evt-1"}]'::jsonb,
   repeat('e', 64), '["test"]'::jsonb, '["synthetic"]'::jsonb);

INSERT INTO onishield.detection_finding_threat_matches
  (tenant_id, finding_id, connector_id, event_id, threat_match_id)
SELECT tenant_id, repeat('c', 64), connector_id, event_id, id
  FROM onishield.threat_indicator_matches
 WHERE event_id = 'evt-1';

DO $$
DECLARE
  link_count INTEGER;
BEGIN
  SELECT count(*) INTO link_count
    FROM onishield.detection_finding_threat_matches
   WHERE finding_id = repeat('c', 64);
  IF link_count <> 1 THEN
    RAISE EXCEPTION 'Finding did not retain its threat-intelligence evidence link';
  END IF;

  BEGIN
    INSERT INTO onishield.detection_finding_threat_matches
      (tenant_id, finding_id, connector_id, event_id, threat_match_id)
    SELECT tenant_id, repeat('c', 64), 'wrong-connector', event_id, id
      FROM onishield.threat_indicator_matches
     WHERE event_id = 'evt-1';
    RAISE EXCEPTION 'Finding accepted a threat match under the wrong connector';
  EXCEPTION
    WHEN foreign_key_violation THEN NULL;
  END;
END
$$;

SELECT set_config('app.tenant_id', 'finding-ti-tenant-b', true);
DO $$
DECLARE
  link_count INTEGER;
  finding_count INTEGER;
BEGIN
  SELECT count(*) INTO link_count
    FROM onishield.detection_finding_threat_matches;
  SELECT count(*) INTO finding_count
    FROM onishield.detection_findings;
  IF link_count <> 0 OR finding_count <> 0 THEN
    RAISE EXCEPTION 'Finding threat-match RLS leaked cross-tenant evidence';
  END IF;
END
$$;

ROLLBACK;
