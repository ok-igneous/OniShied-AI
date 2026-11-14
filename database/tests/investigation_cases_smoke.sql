-- Run as database administrator after migrations 001-020.
-- Validates case isolation, analysis job leasing, immutable report persistence, and audit integrity.
BEGIN;
SET LOCAL ROLE onishield_owner;
SELECT set_config('app.tenant_id','investigation-tenant-a',true);

INSERT INTO onishield.operators(id,email,password_hash,display_name,status) VALUES
 ('22222222-2222-4222-8222-222222222222','investigation-a@example.invalid','unused','Investigator A','active'),
 ('33333333-3333-4333-8333-333333333333','investigation-b@example.invalid','unused','Investigator B','active');

INSERT INTO onishield.operator_memberships(id,tenant_id,operator_id,role,status)
 OVERRIDING SYSTEM VALUE VALUES
 (987654322,'investigation-tenant-a','22222222-2222-4222-8222-222222222222','security_analyst','active'),
 (987654323,'investigation-tenant-b','33333333-3333-4333-8333-333333333333','security_analyst','active');

INSERT INTO onishield.security_events
 (tenant_id,connector_id,event_id,schema_version,event_type,observed_at,event_json,payload_sha256)
VALUES
 ('investigation-tenant-a','investigation-connector','investigation-event',
  '0.1.0','identity.authentication.failure',NOW(),'{}'::jsonb,repeat('d',64));

INSERT INTO onishield.detection_findings
 (tenant_id,finding_id,rule_id,rule_version,status,title,explanation,severity,confidence,
  first_seen_at,last_seen_at,episode_anchor_connector_id,episode_anchor_event_id,
  evidence_event_ids,evidence_event_refs,grouping_key_hash,matched_conditions,known_limitations)
VALUES
 ('investigation-tenant-a',repeat('e',64),'AUTH_FAILURE_BURST','1.0.0','open',
  'Investigation smoke finding','Smoke evidence','high','high',NOW(),NOW(),
  'investigation-connector','investigation-event',
  '["investigation-event"]'::jsonb,
  '[{"connector_id":"investigation-connector","event_id":"investigation-event"}]'::jsonb,
  repeat('f',64),'["threshold_met"]'::jsonb,'[]'::jsonb);

INSERT INTO onishield.detection_finding_evidence
 (tenant_id,finding_id,connector_id,event_id)
VALUES ('investigation-tenant-a',repeat('e',64),'investigation-connector','investigation-event');

INSERT INTO onishield.operator_sessions
 (tenant_id,operator_id,membership_id,token_hash,expires_at,step_up_at)
VALUES
 ('investigation-tenant-a','22222222-2222-4222-8222-222222222222',987654322,
  repeat('a',64),NOW()+INTERVAL '1 hour',NOW()),
 ('investigation-tenant-b','33333333-3333-4333-8333-333333333333',987654323,
  repeat('b',64),NOW()+INTERVAL '1 hour',NOW());

SET LOCAL ROLE onishield_auth;
DO $$
DECLARE cid UUID; detail JSONB; inserted BOOLEAN;
BEGIN
  cid := onishield.create_investigation_case(
    repeat('a',64),'Authentication activity review',ARRAY[repeat('e',64)],
    'Eight failed logins require analyst review.','investigation-smoke-create'
  );
  detail := onishield.get_investigation_case(repeat('a',64),cid);
  IF detail->'case'->>'id' <> cid::text
     OR jsonb_array_length(detail->'findings') <> 1
     OR jsonb_array_length(detail->'findings'->0->'evidence') <> 1
     OR detail->'findings'->0->'finding'->>'severity' <> 'high'
     OR jsonb_array_length(detail->'activity') <> 2 THEN
    RAISE EXCEPTION 'Investigation detail did not include expected case, finding, and activity';
  END IF;
  inserted := onishield.add_investigation_finding(
    repeat('a',64),cid,repeat('e',64),
    'Retrying the same association must be idempotent.','investigation-smoke-duplicate'
  );
  IF inserted THEN RAISE EXCEPTION 'Duplicate association was reported as inserted'; END IF;
  PERFORM onishield.add_investigation_note(
    repeat('a',64),cid,'Analyst note: verify the affected account owner.','investigation-smoke-note'
  );
  IF jsonb_array_length(onishield.get_investigation_case(repeat('a',64),cid)->'activity') <> 3 THEN
    RAISE EXCEPTION 'Append-only activity did not record the note';
  END IF;
  BEGIN
    PERFORM onishield.get_investigation_case(repeat('b',64),cid);
    RAISE EXCEPTION 'Cross-tenant operator unexpectedly read case';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'Cross-tenant operator unexpectedly read case' THEN RAISE; END IF;
    IF SQLERRM <> 'Investigation case not found' THEN RAISE; END IF;
  END;
END $$;

SET LOCAL ROLE onishield_owner;
DO $$
BEGIN
  IF (SELECT count(*) FROM onishield.investigation_cases
       WHERE tenant_id='investigation-tenant-a') <> 1 THEN
    RAISE EXCEPTION 'Expected one tenant A investigation case';
  END IF;
  IF (SELECT count(*) FROM onishield.investigation_activity
       WHERE tenant_id='investigation-tenant-a' AND activity_type='note_added') <> 1 THEN
    RAISE EXCEPTION 'Expected one persisted investigation note';
  END IF;
END $$;


SET LOCAL ROLE onishield_auth;
DO $
DECLARE cid UUID; job UUID;
BEGIN
  SELECT id INTO cid FROM onishield.investigation_cases
   WHERE tenant_id='investigation-tenant-a' AND title='Authentication activity review';
  job := onishield.request_investigation_analysis(
    repeat('a',64),cid,'investigation-analysis-smoke-request'
  );
  IF job IS NULL THEN RAISE EXCEPTION 'Analysis request did not create or return a job'; END IF;
END $;

SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id','investigation-tenant-a',true);
DO $
DECLARE claimed RECORD; version_number INTEGER;
BEGIN
  SELECT * INTO claimed FROM onishield.claim_investigation_analysis_job(
    'investigation-tenant-a',180000
  );
  IF claimed.job_id IS NULL OR claimed.input->'findings' IS NULL THEN
    RAISE EXCEPTION 'Analysis worker did not claim a job with evidence input';
  END IF;
  IF jsonb_array_length(claimed.input->'findings'->0->'evidence') <> 1 THEN
    RAISE EXCEPTION 'Analysis worker input did not include canonical evidence';
  END IF;
  version_number := onishield.complete_investigation_analysis_job(
    'investigation-tenant-a',claimed.job_id,claimed.lease_token,
    'openai','test-model','investigation-report-v1',repeat('c',64),
    '{"summary":"Test report","summary_evidence_refs":[{"connector_id":"investigation-connector","event_id":"investigation-event"}],"timeline":[],"hypotheses":[],"recommendations":[],"limitations":[]}'::jsonb
  );
  IF version_number <> 1 THEN RAISE EXCEPTION 'Expected first report version'; END IF;
END $;

SET LOCAL ROLE onishield_owner;
DO $
DECLARE report_id UUID;
BEGIN
  SELECT id INTO report_id FROM onishield.investigation_analysis_reports
   WHERE tenant_id='investigation-tenant-a';
  IF report_id IS NULL THEN RAISE EXCEPTION 'Expected immutable investigation report'; END IF;
  BEGIN
    UPDATE onishield.investigation_analysis_reports
       SET report='{"tampered":true}'::jsonb WHERE id=report_id;
    RAISE EXCEPTION 'Investigation report unexpectedly updated';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'Investigation analysis reports are immutable' THEN RAISE; END IF;
  END;
  BEGIN
    DELETE FROM onishield.investigation_analysis_reports WHERE id=report_id;
    RAISE EXCEPTION 'Investigation report unexpectedly deleted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'Investigation analysis reports are immutable' THEN RAISE; END IF;
  END;
END $;

SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id','investigation-tenant-a',true);
DO $
BEGIN
  BEGIN
    UPDATE onishield.investigation_activity SET reason='tampered audit entry'
     WHERE tenant_id='investigation-tenant-a';
    RAISE EXCEPTION 'Runtime role unexpectedly modified append-only activity';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
ROLLBACK;
