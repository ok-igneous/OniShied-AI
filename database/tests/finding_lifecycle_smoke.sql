-- Run as a database administrator after applying all migrations.
-- Exercises a valid transition, immutable audit write, invalid transition,
-- and denial of direct status mutation by the ingestion/runtime role.
BEGIN;
SET LOCAL ROLE onishield_owner;
SELECT set_config('app.tenant_id', 'lifecycle-tenant-a', true);

INSERT INTO onishield.operators
  (id, email, password_hash, display_name, status)
VALUES
  ('11111111-1111-4111-8111-111111111111',
   'lifecycle-smoke@example.invalid', 'not-used-in-smoke', 'Lifecycle Smoke', 'active');

INSERT INTO onishield.operator_memberships
  (id, tenant_id, operator_id, role, status)
OVERRIDING SYSTEM VALUE
VALUES
  (987654321, 'lifecycle-tenant-a',
   '11111111-1111-4111-8111-111111111111', 'security_analyst', 'active');

INSERT INTO onishield.security_events
  (tenant_id, connector_id, event_id, schema_version, event_type,
   observed_at, event_json, payload_sha256)
VALUES
  ('lifecycle-tenant-a', 'lifecycle-connector', 'lifecycle-event',
   '0.1.0', 'identity.authentication.failure', NOW(),
   '{}'::jsonb, repeat('f', 64));

INSERT INTO onishield.detection_findings
  (tenant_id, finding_id, rule_id, rule_version, status, title, explanation,
   severity, confidence, first_seen_at, last_seen_at,
   episode_anchor_connector_id, episode_anchor_event_id,
   evidence_event_ids, evidence_event_refs, grouping_key_hash,
   matched_conditions, known_limitations)
VALUES
  ('lifecycle-tenant-a', repeat('a', 64), 'AUTH_FAILURE_BURST', '1.0.0',
   'open', 'Smoke finding', 'Lifecycle smoke finding', 'medium', 'high',
   NOW(), NOW(), 'lifecycle-connector', 'lifecycle-event',
   '["lifecycle-event"]'::jsonb,
   '[{"connector_id":"lifecycle-connector","event_id":"lifecycle-event"}]'::jsonb,
   repeat('b', 64), '["threshold_met"]'::jsonb, '[]'::jsonb);

INSERT INTO onishield.operator_sessions
  (tenant_id, operator_id, membership_id, token_hash, expires_at, step_up_at)
VALUES
  ('lifecycle-tenant-a', '11111111-1111-4111-8111-111111111111',
   987654321, repeat('c', 64), NOW() + INTERVAL '1 hour', NOW());

SET LOCAL ROLE onishield_auth;
SELECT * FROM onishield.transition_detection_finding(
  repeat('c', 64), repeat('a', 64), 'acknowledged',
  'Analyst accepted this finding for investigation.', 'lifecycle-smoke-valid'
);

DO $$
BEGIN
  BEGIN
    PERFORM * FROM onishield.transition_detection_finding(
      repeat('c', 64), repeat('a', 64), 'reopened',
      'This transition is intentionally invalid.', 'lifecycle-smoke-invalid'
    );
    RAISE EXCEPTION 'Invalid lifecycle transition was accepted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'Invalid lifecycle transition was accepted' THEN RAISE; END IF;
    IF SQLERRM <> 'Invalid finding status transition' THEN RAISE; END IF;
  END;
END $$;

SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'lifecycle-tenant-a', true);
DO $$
BEGIN
  BEGIN
    UPDATE onishield.detection_findings
       SET status = 'resolved'
     WHERE tenant_id = 'lifecycle-tenant-a' AND finding_id = repeat('a', 64);
    RAISE EXCEPTION 'Runtime role unexpectedly changed finding status';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END $$;

ROLLBACK;
