-- Run as database administrator after migrations and runtime grants.
-- Verifies transactional job identity, idempotency, and tenant RLS.
BEGIN;
SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'replay-tenant-a', true);
INSERT INTO onishield.security_events
  (tenant_id, connector_id, event_id, schema_version, event_type, observed_at,
   event_json, payload_sha256)
VALUES
  ('replay-tenant-a', 'replay-connector', 'replay-event-a', '0.1.0',
   'identity.authentication.failure', NOW(), '{}'::jsonb, repeat('e', 64))
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;
INSERT INTO onishield.detection_replay_jobs (tenant_id, connector_id, event_id)
VALUES ('replay-tenant-a', 'replay-connector', 'replay-event-a')
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;
INSERT INTO onishield.detection_replay_jobs (tenant_id, connector_id, event_id)
VALUES ('replay-tenant-a', 'replay-connector', 'replay-event-a')
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;
DO $$
DECLARE job_count INTEGER;
BEGIN
  SELECT count(*) INTO job_count FROM onishield.detection_replay_jobs;
  IF job_count <> 1 THEN
    RAISE EXCEPTION 'Replay enqueue is not idempotent: % jobs', job_count;
  END IF;
END $$;
SELECT set_config('app.tenant_id', 'replay-tenant-b', true);
DO $$
DECLARE job_count INTEGER;
BEGIN
  SELECT count(*) INTO job_count FROM onishield.detection_replay_jobs;
  IF job_count <> 0 THEN
    RAISE EXCEPTION 'Replay queue RLS failed: % cross-tenant jobs visible', job_count;
  END IF;
END $$;
ROLLBACK;
