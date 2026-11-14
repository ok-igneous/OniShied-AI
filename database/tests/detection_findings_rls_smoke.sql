-- Run as database administrator after migrations and runtime grants.
-- Verifies tenant isolation, stable anchors, and idempotent evidence merging.
BEGIN;
SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'finding-tenant-a', true);

INSERT INTO onishield.security_events
  (tenant_id, connector_id, event_id, schema_version, event_type, observed_at,
   event_json, payload_sha256)
VALUES
  ('finding-tenant-a', 'connector-a', 'event-a', '0.1.0',
   'identity.authentication.failure', NOW() - INTERVAL '1 minute', '{}'::jsonb, repeat('c', 64)),
  ('finding-tenant-a', 'connector-a', 'event-b', '0.1.0',
   'identity.authentication.failure', NOW(), '{}'::jsonb, repeat('d', 64))
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;

-- Initial threshold crossing creates an episode anchored to event-a.
INSERT INTO onishield.detection_findings
  (tenant_id, finding_id, rule_id, rule_version, status, title, explanation,
   severity, confidence, first_seen_at, last_seen_at,
   episode_anchor_connector_id, episode_anchor_event_id,
   evidence_event_ids, evidence_event_refs, grouping_key_hash,
   matched_conditions, known_limitations)
VALUES
  ('finding-tenant-a', repeat('a', 64), 'AUTH_FAILURE_BURST', '1.0.0', 'open',
   'Synthetic auth burst', 'Synthetic test finding', 'medium', 'high',
   NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute',
   'connector-a', 'event-a',
   '["connector-a:event-a"]'::jsonb,
   '[{"connector_id":"connector-a","event_id":"event-a"}]'::jsonb,
   repeat('b', 64), '["threshold_met"]'::jsonb, '["synthetic_only"]'::jsonb);

-- A later evaluation adds event-b to the same stable episode. The evidence
-- union is atomic with the row conflict update and preserves the anchor.
INSERT INTO onishield.detection_findings
  (tenant_id, finding_id, rule_id, rule_version, status, title, explanation,
   severity, confidence, first_seen_at, last_seen_at,
   episode_anchor_connector_id, episode_anchor_event_id,
   evidence_event_ids, evidence_event_refs, grouping_key_hash,
   matched_conditions, known_limitations)
VALUES
  ('finding-tenant-a', repeat('a', 64), 'AUTH_FAILURE_BURST', '1.0.0', 'open',
   'Synthetic auth burst', 'Synthetic test finding', 'medium', 'high',
   NOW(), NOW() + INTERVAL '1 minute',
   'connector-a', 'event-a',
   '["connector-a:event-b"]'::jsonb,
   '[{"connector_id":"connector-a","event_id":"event-b"}]'::jsonb,
   repeat('b', 64), '["later_evidence"]'::jsonb, '["synthetic_only"]'::jsonb)
ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
  first_seen_at = LEAST(detection_findings.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(detection_findings.last_seen_at, EXCLUDED.last_seen_at),
  evidence_event_refs = (
    SELECT COALESCE(jsonb_agg(item ORDER BY item->>'connector_id', item->>'event_id'), '[]'::jsonb)
    FROM (
      SELECT DISTINCT item
      FROM jsonb_array_elements(detection_findings.evidence_event_refs || EXCLUDED.evidence_event_refs) AS refs(item)
    ) AS merged
  ),
  evidence_event_ids = (
    SELECT COALESCE(jsonb_agg(item ORDER BY item), '[]'::jsonb)
    FROM (
      SELECT DISTINCT item
      FROM jsonb_array_elements_text(detection_findings.evidence_event_ids || EXCLUDED.evidence_event_ids) AS ids(item)
    ) AS merged
  ),
  matched_conditions = (
    SELECT COALESCE(jsonb_agg(item ORDER BY item), '[]'::jsonb)
    FROM (
      SELECT DISTINCT item
      FROM jsonb_array_elements_text(detection_findings.matched_conditions || EXCLUDED.matched_conditions) AS conditions(item)
    ) AS merged
  ),
  updated_at = NOW();

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
DECLARE finding_count INTEGER; evidence_count INTEGER; reference_count INTEGER;
BEGIN
  SELECT count(*) INTO finding_count FROM onishield.detection_findings;
  SELECT count(*) INTO evidence_count FROM onishield.detection_finding_evidence;
  SELECT jsonb_array_length(evidence_event_refs) INTO reference_count
    FROM onishield.detection_findings WHERE finding_id = repeat('a', 64);
  IF finding_count <> 1 OR evidence_count <> 2 OR reference_count <> 2 THEN
    RAISE EXCEPTION 'Finding/evidence merge failed: findings %, evidence %, refs %',
      finding_count, evidence_count, reference_count;
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
