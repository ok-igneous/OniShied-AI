-- Run as database administrator after migrations and runtime grants.
-- Verifies tenant isolation, episode identity storage, and idempotent evidence links.
BEGIN;
SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'finding-tenant-a', true);

INSERT INTO onishield.security_events
  (tenant_id, connector_id, event_id, schema_version, event_type, observed_at,
   event_json, payload_sha256)
VALUES
  ('finding-tenant-a', 'connector-a', 'event-a', '0.1.0',
   'identity.authentication.failure', NOW(), '{}'::jsonb, repeat('c', 64)),
  ('finding-tenant-a', 'connector-a', 'event-b', '0.1.0',
   'identity.authentication.failure', NOW(), '{}'::jsonb, repeat('d', 64))
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;

INSERT INTO onishield.detection_findings
  (tenant_id, finding_id, rule_id, rule_version, status, title, explanation,
   severity, confidence, first_seen_at, last_seen_at,
   episode_anchor_connector_id, episode_anchor_event_id,
   evidence_event_ids, evidence_event_refs, grouping_key_hash,
   matched_conditions, known_limitations)
VALUES
  ('finding-tenant-a', repeat('a', 64), 'AUTH_FAILURE_BURST', '1.0.0', 'open',
   'Synthetic auth burst', 'Synthetic test finding', 'medium', 'high',
   NOW(), NOW(), 'connector-a', 'event-a',
   '["connector-a:event-a","connector-a:event-b"]'::jsonb,
   '[{"connector_id":"connector-a","event_id":"event-a"},{"connector_id":"connector-a","event_id":"event-b"}]'::jsonb,
   repeat('b', 64), '["threshold_met"]'::jsonb, '["synthetic_only"]'::jsonb)
ON CONFLICT (tenant_id, finding_id) DO NOTHING;

INSERT INTO onishield.detection_finding_evidence
  (tenant_id, finding_id, connector_id, event_id)
VALUES
  ('finding-tenant-a', repeat('a', 64), 'connector-a', 'event-a'),
  ('finding-tenant-a', repeat('a', 64), 'connector-a', 'event-b')
ON CONFLICT (tenant_id, finding_id, connector_id, event_id) DO NOTHING;

-- A duplicate evidence write must not create another row.
INSERT INTO onishield.detection_finding_evidence
  (tenant_id, finding_id, connector_id, event_id)
VALUES ('finding-tenant-a', repeat('a', 64), 'connector-a', 'event-a')
ON CONFLICT (tenant_id, finding_id, connector_id, event_id) DO NOTHING;

DO $$
DECLARE finding_count INTEGER; evidence_count INTEGER;
BEGIN
  SELECT count(*) INTO finding_count FROM onishield.detection_findings;
  SELECT count(*) INTO evidence_count FROM onishield.detection_finding_evidence;
  IF finding_count <> 1 OR evidence_count <> 2 THEN
    RAISE EXCEPTION 'Finding/evidence idempotency failed: findings %, evidence %',
      finding_count, evidence_count;
  END IF;
END $$;

SELECT set_config('app.tenant_id', 'finding-tenant-b', true);
DO $$
DECLARE finding_count INTEGER; evidence_count INTEGER;
BEGIN
  SELECT count(*) INTO finding_count FROM onishield.detection_findings;
  SELECT count(*) INTO evidence_count FROM onishield.detection_finding_evidence;
  IF finding_count <> 0 OR evidence_count <> 0 THEN
    RAISE EXCEPTION 'Finding evidence RLS failed: findings %, evidence %',
      finding_count, evidence_count;
  END IF;
END $$;
ROLLBACK;
