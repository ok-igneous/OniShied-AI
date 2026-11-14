-- Durable, tenant-scoped AI investigation analysis queue and immutable reports.
BEGIN;

CREATE TABLE onishield.investigation_analysis_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  case_id UUID NOT NULL,
  requested_by_operator_id UUID NOT NULL,
  requested_by_membership_id BIGINT NOT NULL,
  request_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','processing','completed','dead_letter')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  lease_token UUID,
  lease_until TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT investigation_analysis_jobs_case_fk
    FOREIGN KEY (tenant_id,case_id) REFERENCES onishield.investigation_cases(tenant_id,id),
  CONSTRAINT investigation_analysis_jobs_actor_fk
    FOREIGN KEY (tenant_id,requested_by_membership_id,requested_by_operator_id)
    REFERENCES onishield.operator_memberships(tenant_id,id,operator_id),
  CONSTRAINT investigation_analysis_jobs_tenant_id_unique UNIQUE (tenant_id,id),
  CONSTRAINT investigation_analysis_jobs_request_unique UNIQUE (tenant_id,request_id)
);

CREATE INDEX investigation_analysis_jobs_claim_idx
  ON onishield.investigation_analysis_jobs(tenant_id,status,available_at,created_at);

CREATE UNIQUE INDEX investigation_analysis_one_active_job_per_case_idx
  ON onishield.investigation_analysis_jobs(tenant_id,case_id)
  WHERE status IN ('pending','processing');

CREATE TABLE onishield.investigation_analysis_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  case_id UUID NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  job_id UUID NOT NULL,
  provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
  model TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 128),
  template_version TEXT NOT NULL,
  evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  report JSONB NOT NULL CHECK (jsonb_typeof(report)='object'),
  created_by_operator_id UUID NOT NULL,
  created_by_membership_id BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT investigation_analysis_reports_case_fk
    FOREIGN KEY (tenant_id,case_id) REFERENCES onishield.investigation_cases(tenant_id,id),
  CONSTRAINT investigation_analysis_reports_job_fk
    FOREIGN KEY (tenant_id,job_id) REFERENCES onishield.investigation_analysis_jobs(tenant_id,id),
  CONSTRAINT investigation_analysis_reports_actor_fk
    FOREIGN KEY (tenant_id,created_by_membership_id,created_by_operator_id)
    REFERENCES onishield.operator_memberships(tenant_id,id,operator_id),
  CONSTRAINT investigation_analysis_reports_version_unique UNIQUE (tenant_id,case_id,version),
  CONSTRAINT investigation_analysis_reports_job_unique UNIQUE (tenant_id,job_id)
);

CREATE INDEX investigation_analysis_reports_latest_idx
  ON onishield.investigation_analysis_reports(tenant_id,case_id,version DESC);

ALTER TABLE onishield.investigation_activity DROP CONSTRAINT investigation_activity_activity_type_check;
ALTER TABLE onishield.investigation_activity ADD CONSTRAINT investigation_activity_activity_type_check
  CHECK (activity_type IN ('case_created','finding_associated','note_added','report_generated'));

ALTER TABLE onishield.investigation_analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.investigation_analysis_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY investigation_analysis_jobs_tenant ON onishield.investigation_analysis_jobs
  USING (tenant_id=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY investigation_analysis_jobs_owner ON onishield.investigation_analysis_jobs
  TO onishield_owner USING (true) WITH CHECK (true);

ALTER TABLE onishield.investigation_analysis_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.investigation_analysis_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY investigation_analysis_reports_tenant ON onishield.investigation_analysis_reports
  USING (tenant_id=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY investigation_analysis_reports_owner ON onishield.investigation_analysis_reports
  TO onishield_owner USING (true) WITH CHECK (true);

REVOKE ALL ON onishield.investigation_analysis_jobs, onishield.investigation_analysis_reports
  FROM PUBLIC,onishield_app,onishield_auth;
GRANT USAGE,SELECT ON SEQUENCE onishield.investigation_activity_id_seq TO onishield_owner;


CREATE FUNCTION onishield.reject_investigation_report_mutation()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,onishield AS $
BEGIN
  RAISE EXCEPTION 'Investigation analysis reports are immutable';
END $;

CREATE TRIGGER investigation_analysis_reports_immutable
BEFORE UPDATE OR DELETE ON onishield.investigation_analysis_reports
FOR EACH ROW EXECUTE FUNCTION onishield.reject_investigation_report_mutation();

CREATE FUNCTION onishield.request_investigation_analysis(
  p_token_hash TEXT,p_case_id UUID,p_request_id TEXT
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE session_row RECORD; job UUID;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' OR p_request_id IS NULL OR
     length(p_request_id)<1 OR length(p_request_id)>128 THEN
    RAISE EXCEPTION 'Invalid investigation analysis request';
  END IF;
  SELECT ss.tenant_id,ss.operator_id,ss.membership_id,ss.step_up_at,m.role
    INTO session_row
    FROM onishield.operator_sessions ss
    JOIN onishield.operators o ON o.id=ss.operator_id
    JOIN onishield.operator_memberships m ON m.id=ss.membership_id
      AND m.tenant_id=ss.tenant_id AND m.operator_id=ss.operator_id
   WHERE ss.token_hash=p_token_hash AND ss.revoked_at IS NULL
     AND ss.expires_at>NOW() AND o.status='active' AND m.status='active'
   FOR UPDATE OF ss;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized investigation analysis'; END IF;
  IF session_row.role NOT IN ('owner','admin','security_analyst') THEN
    RAISE EXCEPTION 'Forbidden investigation analysis';
  END IF;
  IF session_row.step_up_at IS NULL OR session_row.step_up_at<NOW()-INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'Investigation step-up required';
  END IF;
  PERFORM set_config('app.tenant_id',session_row.tenant_id,true);
  PERFORM 1 FROM onishield.investigation_cases c
   WHERE c.tenant_id=session_row.tenant_id AND c.id=p_case_id
     AND c.status NOT IN ('resolved','closed') FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Investigation case not found or closed'; END IF;
  SELECT id INTO job FROM onishield.investigation_analysis_jobs
   WHERE tenant_id=session_row.tenant_id AND case_id=p_case_id
     AND status IN ('pending','processing') ORDER BY created_at DESC LIMIT 1;
  IF job IS NOT NULL THEN RETURN job; END IF;
  SELECT id INTO job FROM onishield.investigation_analysis_jobs
   WHERE tenant_id=session_row.tenant_id AND case_id=p_case_id
     AND created_at>NOW()-INTERVAL '10 minutes'
   ORDER BY created_at DESC LIMIT 1;
  IF job IS NOT NULL THEN RETURN job; END IF;
  INSERT INTO onishield.investigation_analysis_jobs
    (tenant_id,case_id,requested_by_operator_id,requested_by_membership_id,request_id)
  VALUES(session_row.tenant_id,p_case_id,session_row.operator_id,session_row.membership_id,p_request_id)
  ON CONFLICT (tenant_id,request_id) DO NOTHING
  RETURNING id INTO job;
  IF job IS NULL THEN
    SELECT id INTO job FROM onishield.investigation_analysis_jobs
     WHERE tenant_id=session_row.tenant_id AND request_id=p_request_id;
  END IF;
  RETURN job;
END $$;

-- Called only by the tenant-scoped worker connection. No raw event payloads are returned.
CREATE FUNCTION onishield.load_investigation_analysis_input(
  p_tenant_id TEXT,p_case_id UUID
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE result JSONB;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id<>current_setting('app.tenant_id',true) THEN
    RAISE EXCEPTION 'Investigation tenant context mismatch';
  END IF;
  SELECT jsonb_build_object(
    'case',jsonb_build_object('id',c.id,'title',c.title,'status',c.status,'priority',c.priority,
      'created_at',c.created_at,'updated_at',c.updated_at),
    'findings',COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'finding_id',f.finding_id,'rule_id',f.rule_id,'rule_version',f.rule_version,
        'title',f.title,'explanation',f.explanation,'severity',f.severity,
        'confidence',f.confidence,'first_seen_at',f.first_seen_at,'last_seen_at',f.last_seen_at,
        'matched_conditions',f.matched_conditions,'known_limitations',f.known_limitations,
        'evidence',COALESCE((
          SELECT jsonb_agg(jsonb_build_object(
            'connector_id',e.connector_id,'event_id',e.event_id,
            'observed_at',ev.observed_at,'event_type',ev.event_type
          ) ORDER BY ev.observed_at,e.connector_id,e.event_id)
          FROM onishield.detection_finding_evidence e
          JOIN onishield.security_events ev
            ON ev.tenant_id=e.tenant_id AND ev.connector_id=e.connector_id AND ev.event_id=e.event_id
          WHERE e.tenant_id=f.tenant_id AND e.finding_id=f.finding_id
        ),'[]'::jsonb),
        'threat_matches',COALESCE((
          SELECT jsonb_agg(jsonb_build_object(
            'indicator_type',ti.indicator_type,'indicator_value',ti.value_normalized,
            'indicator_confidence',ti.confidence,'tlp',ti.tlp,
            'indicator_status',ti.status,'indicator_version',ti.version,
            'source_name',src.display_name,'source_kind',src.source_kind,
            'matcher_version',tm.matcher_version,'matched_field_path',tm.matched_field_path,
            'matched_at',tm.matched_at,'valid_from',ti.valid_from,'expires_at',ti.expires_at
          ) ORDER BY tm.matched_at DESC)
          FROM onishield.detection_finding_threat_matches ftm
          JOIN onishield.threat_indicator_matches tm
            ON tm.tenant_id=ftm.tenant_id AND tm.id=ftm.threat_match_id
           AND tm.connector_id=ftm.connector_id AND tm.event_id=ftm.event_id
          JOIN onishield.threat_indicators ti
            ON ti.tenant_id=tm.tenant_id AND ti.id=tm.indicator_id
           AND ti.version=tm.indicator_version
          JOIN onishield.threat_intelligence_sources src
            ON src.tenant_id=ti.tenant_id AND src.id=ti.source_id
          WHERE ftm.tenant_id=f.tenant_id AND ftm.finding_id=f.finding_id
        ),'[]'::jsonb)
      ) ORDER BY f.last_seen_at DESC)
      FROM onishield.investigation_case_findings a
      JOIN onishield.detection_findings f
        ON f.tenant_id=a.tenant_id AND f.finding_id=a.finding_id
      WHERE a.tenant_id=c.tenant_id AND a.case_id=c.id
    ),'[]'::jsonb)
  ) INTO result
  FROM onishield.investigation_cases c
  WHERE c.tenant_id=p_tenant_id AND c.id=p_case_id;
  IF result IS NULL THEN RAISE EXCEPTION 'Investigation case not found'; END IF;
  RETURN result;
END $$;

CREATE FUNCTION onishield.claim_investigation_analysis_job(
  p_tenant_id TEXT,p_lease_ms INTEGER
) RETURNS TABLE(job_id UUID,case_id UUID,lease_token UUID,attempts INTEGER,input JSONB)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE selected RECORD; token UUID;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id<>current_setting('app.tenant_id',true)
     OR p_lease_ms NOT BETWEEN 10000 AND 600000 THEN
    RAISE EXCEPTION 'Invalid investigation worker scope';
  END IF;
  UPDATE onishield.investigation_analysis_jobs
     SET status='dead_letter',lease_token=NULL,lease_until=NULL,
         last_error='worker_lease_expired_after_max_attempts',updated_at=NOW()
   WHERE tenant_id=p_tenant_id AND status='processing'
     AND lease_until<NOW() AND attempts>=6;
  UPDATE onishield.investigation_analysis_jobs
     SET status='dead_letter',last_error='max_attempts_exceeded',updated_at=NOW()
   WHERE tenant_id=p_tenant_id AND status='pending' AND attempts>=6;
  SELECT j.id,j.case_id INTO selected
    FROM onishield.investigation_analysis_jobs j
   WHERE j.tenant_id=p_tenant_id AND (
     (j.status='pending' AND j.available_at<=NOW() AND j.attempts<6) OR
     (j.status='processing' AND j.lease_until<NOW() AND j.attempts<6)
   )
   ORDER BY j.available_at,j.created_at,j.id
   LIMIT 1 FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN RETURN; END IF;
  token:=gen_random_uuid();
  UPDATE onishield.investigation_analysis_jobs j
     SET status='processing',attempts=j.attempts+1,lease_token=token,
         lease_until=NOW()+(p_lease_ms*INTERVAL '1 millisecond'),updated_at=NOW()
   WHERE j.tenant_id=p_tenant_id AND j.id=selected.id;
  RETURN QUERY SELECT selected.id,selected.case_id,token,j.attempts,
    onishield.load_investigation_analysis_input(p_tenant_id,selected.case_id)
    FROM onishield.investigation_analysis_jobs j
   WHERE j.tenant_id=p_tenant_id AND j.id=selected.id;
END $$;

CREATE FUNCTION onishield.complete_investigation_analysis_job(
  p_tenant_id TEXT,p_job_id UUID,p_lease_token UUID,p_provider TEXT,p_model TEXT,
  p_template_version TEXT,p_evidence_digest TEXT,p_report JSONB
) RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE j RECORD; next_version INTEGER;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id<>current_setting('app.tenant_id',true)
    OR p_provider IS NULL OR length(p_provider)>64 OR p_model IS NULL OR length(p_model)>128
    OR p_template_version IS NULL OR length(p_template_version)>64
    OR p_evidence_digest !~ '^[a-f0-9]{64}$' OR jsonb_typeof(p_report)<>'object' THEN
    RAISE EXCEPTION 'Invalid investigation report';
  END IF;
  SELECT * INTO j FROM onishield.investigation_analysis_jobs
   WHERE tenant_id=p_tenant_id AND id=p_job_id AND status='processing'
     AND lease_token=p_lease_token FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Investigation analysis lease lost'; END IF;
  PERFORM 1 FROM onishield.investigation_cases c
   WHERE c.tenant_id=p_tenant_id AND c.id=j.case_id FOR UPDATE;
  SELECT COALESCE(MAX(r.version),0)+1 INTO next_version
    FROM onishield.investigation_analysis_reports r
   WHERE r.tenant_id=p_tenant_id AND r.case_id=j.case_id;
  INSERT INTO onishield.investigation_analysis_reports
    (tenant_id,case_id,version,job_id,provider,model,template_version,evidence_digest,
     report,created_by_operator_id,created_by_membership_id)
  VALUES(p_tenant_id,j.case_id,next_version,j.id,p_provider,p_model,p_template_version,
    p_evidence_digest,p_report,j.requested_by_operator_id,j.requested_by_membership_id);
  UPDATE onishield.investigation_analysis_jobs
     SET status='completed',completed_at=NOW(),lease_token=NULL,lease_until=NULL,
         last_error=NULL,updated_at=NOW()
   WHERE tenant_id=p_tenant_id AND id=j.id;
  INSERT INTO onishield.investigation_activity
    (tenant_id,case_id,actor_operator_id,actor_membership_id,activity_type,reason,request_id)
  VALUES(p_tenant_id,j.case_id,j.requested_by_operator_id,j.requested_by_membership_id,
    'report_generated','AI investigation report generated; report content is immutable.',j.request_id);
  UPDATE onishield.investigation_cases SET updated_at=NOW(),last_activity_at=NOW()
   WHERE tenant_id=p_tenant_id AND id=j.case_id;
  RETURN next_version;
END $$;

CREATE FUNCTION onishield.fail_investigation_analysis_job(
  p_tenant_id TEXT,p_job_id UUID,p_lease_token UUID,p_max_attempts INTEGER,
  p_retry_ms INTEGER,p_error TEXT
) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id<>current_setting('app.tenant_id',true)
    OR p_max_attempts NOT BETWEEN 1 AND 20 OR p_retry_ms NOT BETWEEN 1000 AND 3600000 THEN
    RAISE EXCEPTION 'Invalid investigation retry request';
  END IF;
  UPDATE onishield.investigation_analysis_jobs
     SET status=CASE WHEN attempts>=p_max_attempts THEN 'dead_letter' ELSE 'pending' END,
         available_at=CASE WHEN attempts>=p_max_attempts THEN available_at
           ELSE NOW()+(p_retry_ms*INTERVAL '1 millisecond') END,
         lease_token=NULL,lease_until=NULL,last_error=left(COALESCE(p_error,'unknown'),500),
         updated_at=NOW()
   WHERE tenant_id=p_tenant_id AND id=p_job_id AND status='processing'
     AND lease_token=p_lease_token;
END $$;

CREATE FUNCTION onishield.list_investigation_analysis_reports(
  p_token_hash TEXT,p_case_id UUID
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE session_row RECORD; result JSONB;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Invalid report request'; END IF;
  SELECT ss.tenant_id,m.role INTO session_row
    FROM onishield.operator_sessions ss
    JOIN onishield.operators o ON o.id=ss.operator_id
    JOIN onishield.operator_memberships m ON m.id=ss.membership_id
      AND m.tenant_id=ss.tenant_id AND m.operator_id=ss.operator_id
   WHERE ss.token_hash=p_token_hash AND ss.revoked_at IS NULL
     AND ss.expires_at>NOW() AND o.status='active' AND m.status='active';
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized investigation report'; END IF;
  IF session_row.role NOT IN ('owner','admin','security_analyst','reviewer','viewer') THEN
    RAISE EXCEPTION 'Forbidden investigation report';
  END IF;
  PERFORM set_config('app.tenant_id',session_row.tenant_id,true);
  SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.version DESC),'[]'::jsonb)
    INTO result FROM onishield.investigation_analysis_reports r
   WHERE r.tenant_id=session_row.tenant_id AND r.case_id=p_case_id;
  IF NOT EXISTS (SELECT 1 FROM onishield.investigation_cases c
    WHERE c.tenant_id=session_row.tenant_id AND c.id=p_case_id) THEN
    RAISE EXCEPTION 'Investigation case not found';
  END IF;
  RETURN result;
END $$;

REVOKE ALL ON FUNCTION onishield.request_investigation_analysis(TEXT,UUID,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.load_investigation_analysis_input(TEXT,UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.claim_investigation_analysis_job(TEXT,INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.complete_investigation_analysis_job(TEXT,UUID,UUID,TEXT,TEXT,TEXT,TEXT,JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.fail_investigation_analysis_job(TEXT,UUID,UUID,INTEGER,INTEGER,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.list_investigation_analysis_reports(TEXT,UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.request_investigation_analysis(TEXT,UUID,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.list_investigation_analysis_reports(TEXT,UUID) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.load_investigation_analysis_input(TEXT,UUID) TO onishield_app;
GRANT EXECUTE ON FUNCTION onishield.claim_investigation_analysis_job(TEXT,INTEGER) TO onishield_app;
GRANT EXECUTE ON FUNCTION onishield.complete_investigation_analysis_job(TEXT,UUID,UUID,TEXT,TEXT,TEXT,TEXT,JSONB) TO onishield_app;
GRANT EXECUTE ON FUNCTION onishield.fail_investigation_analysis_job(TEXT,UUID,UUID,INTEGER,INTEGER,TEXT) TO onishield_app;

COMMIT;
