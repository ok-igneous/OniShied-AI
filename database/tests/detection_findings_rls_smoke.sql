-- Run as database administrator after migrations and runtime grants.
-- Verifies tenant isolation and exact-finding replay idempotency.
BEGIN;
SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'finding-tenant-a', true);

INSERT INTO onishield.detection_findings
  (tenant_id, finding_id, rule_id, rule_version, status, title, explanation,
   severity, confidence, first_seen_at, last_seen_at, evidence_event_ids,
   grouping_key_hash, matched_conditions, known_limitations)
VALUES
  ('finding-tenant-a', repeat('a', 64), 'AUTH_FAILURE_BURST', '1.0.0', 'open',
   'Synthetic auth burst', 'Synthetic test finding', 'medium', 'high',
   NOW(), NOW(), '["event-a","event-b"]'::jsonb, repeat('b', 64),
   '["threshold_met"]'::jsonb, '["synthetic_only"]'::jsonb)
ON CONFLICT (tenant_id, finding_id) DO NOTHING;

INSERT INTO onishield.detection_findings
  (tenant_id, finding_id, rule_id, rule_version, status, title, explanation,
   severity, confidence, first_seen_at, last_seen_at, evidence_event_ids,
   grouping_key_hash, matched_conditions, known_limitations)
VALUES
  ('finding-tenant-a', repeat('a', 64), 'AUTH_FAILURE_BURST', '1.0.0', 'open',
   'Synthetic auth burst', 'Synthetic test finding', 'medium', 'high',
   NOW(), NOW(), '["event-a","event-b"]'::jsonb, repeat('b', 64),
   '["threshold_met"]'::jsonb, '["synthetic_only"]'::jsonb)
ON CONFLICT (tenant_id, finding_id) DO NOTHING;

DO $$
DECLARE row_count INTEGER;
BEGIN
  SELECT count(*) INTO row_count FROM onishield.detection_findings;
  IF row_count <> 1 THEN
    RAISE EXCEPTION 'Finding replay is not idempotent';
  END IF;
END $$;

SELECT set_config('app.tenant_id', 'finding-tenant-b', true);
DO $$
DECLARE row_count INTEGER;
BEGIN
  SELECT count(*) INTO row_count FROM onishield.detection_findings;
  IF row_count <> 0 THEN
    RAISE EXCEPTION 'Finding RLS failed: cross-tenant row visible';
  END IF;
END $$;
ROLLBACK;
