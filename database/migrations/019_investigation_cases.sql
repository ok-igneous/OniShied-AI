-- Tenant-isolated operator investigation cases, associations, and append-only activity.
BEGIN;

CREATE TABLE onishield.investigation_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL CHECK (length(btrim(title)) BETWEEN 3 AND 160),
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','investigating','contained','resolved','closed')),
  priority TEXT NOT NULL DEFAULT 'medium'
    CHECK (priority IN ('low','medium','high','critical')),
  correlation_version TEXT NOT NULL DEFAULT 'manual-v1',
  created_by_membership_id BIGINT NOT NULL,
  assigned_to_membership_id BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT investigation_cases_tenant_id_unique UNIQUE (tenant_id,id),
  CONSTRAINT investigation_cases_creator_fk FOREIGN KEY (tenant_id,created_by_membership_id)
    REFERENCES onishield.operator_memberships (tenant_id,id),
  CONSTRAINT investigation_cases_assignee_fk FOREIGN KEY (tenant_id,assigned_to_membership_id)
    REFERENCES onishield.operator_memberships (tenant_id,id)
);

CREATE INDEX investigation_cases_tenant_recent_idx
  ON onishield.investigation_cases (tenant_id,last_activity_at DESC,id DESC);

CREATE TABLE onishield.investigation_case_findings (
  tenant_id TEXT NOT NULL,
  case_id UUID NOT NULL,
  finding_id TEXT NOT NULL,
  association_reason TEXT NOT NULL CHECK (length(btrim(association_reason)) BETWEEN 10 AND 1000),
  correlation_version TEXT NOT NULL DEFAULT 'manual-v1',
  created_by_membership_id BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id,case_id,finding_id),
  CONSTRAINT investigation_case_findings_case_fk FOREIGN KEY (tenant_id,case_id)
    REFERENCES onishield.investigation_cases (tenant_id,id),
  CONSTRAINT investigation_case_findings_finding_fk FOREIGN KEY (tenant_id,finding_id)
    REFERENCES onishield.detection_findings (tenant_id,finding_id),
  CONSTRAINT investigation_case_findings_membership_fk FOREIGN KEY (tenant_id,created_by_membership_id)
    REFERENCES onishield.operator_memberships (tenant_id,id)
);

-- First release: a finding is assigned to one case only; re-parenting requires
-- a future audited case-merge workflow rather than silent multi-case duplication.
CREATE UNIQUE INDEX investigation_case_findings_one_case_per_finding_idx
  ON onishield.investigation_case_findings (tenant_id,finding_id);

CREATE TABLE onishield.investigation_activity (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  case_id UUID NOT NULL,
  actor_operator_id UUID NOT NULL,
  actor_membership_id BIGINT NOT NULL,
  activity_type TEXT NOT NULL CHECK (activity_type IN
    ('case_created','finding_associated','note_added')),
  reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 10 AND 2000),
  request_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT investigation_activity_case_fk FOREIGN KEY (tenant_id,case_id)
    REFERENCES onishield.investigation_cases (tenant_id,id),
  CONSTRAINT investigation_activity_membership_fk FOREIGN KEY
    (tenant_id,actor_membership_id,actor_operator_id)
    REFERENCES onishield.operator_memberships (tenant_id,id,operator_id)
);

CREATE INDEX investigation_activity_timeline_idx
  ON onishield.investigation_activity (tenant_id,case_id,created_at,id);

ALTER TABLE onishield.investigation_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.investigation_cases FORCE ROW LEVEL SECURITY;
CREATE POLICY investigation_cases_tenant ON onishield.investigation_cases
  USING (tenant_id = current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id',true));
CREATE POLICY investigation_cases_owner ON onishield.investigation_cases
  TO onishield_owner USING (true) WITH CHECK (true);

ALTER TABLE onishield.investigation_case_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.investigation_case_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY investigation_case_findings_tenant ON onishield.investigation_case_findings
  USING (tenant_id = current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id',true));
CREATE POLICY investigation_case_findings_owner ON onishield.investigation_case_findings
  TO onishield_owner USING (true) WITH CHECK (true);

ALTER TABLE onishield.investigation_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.investigation_activity FORCE ROW LEVEL SECURITY;
CREATE POLICY investigation_activity_tenant ON onishield.investigation_activity
  USING (tenant_id = current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id',true));
CREATE POLICY investigation_activity_owner ON onishield.investigation_activity
  TO onishield_owner USING (true) WITH CHECK (true);

REVOKE ALL ON onishield.investigation_cases, onishield.investigation_case_findings,
  onishield.investigation_activity FROM PUBLIC,onishield_app,onishield_auth;
GRANT USAGE,SELECT ON SEQUENCE onishield.investigation_activity_id_seq TO onishield_owner;

CREATE FUNCTION onishield.create_investigation_case(
  p_token_hash TEXT,p_title TEXT,p_finding_ids TEXT[],p_reason TEXT,p_request_id TEXT
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD; new_case UUID; finding TEXT; highest TEXT := 'low';
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' OR length(btrim(p_title)) NOT BETWEEN 3 AND 160
    OR length(btrim(p_reason)) NOT BETWEEN 10 AND 1000
    OR p_request_id IS NULL OR length(p_request_id)>128
    OR COALESCE(array_length(p_finding_ids,1),0) NOT BETWEEN 1 AND 50
    THEN RAISE EXCEPTION 'Invalid investigation case request'; END IF;
  SELECT session_row.tenant_id,session_row.operator_id,session_row.membership_id,m.role,session_row.step_up_at
    INTO trusted FROM onishield.operator_sessions session_row
    JOIN onishield.operators o ON o.id=session_row.operator_id
    JOIN onishield.operator_memberships m ON m.id=session_row.membership_id
      AND m.tenant_id=session_row.tenant_id AND m.operator_id=session_row.operator_id
   WHERE session_row.token_hash=p_token_hash AND session_row.revoked_at IS NULL AND session_row.expires_at>NOW()
     AND o.status='active' AND m.status='active' FOR UPDATE OF session_row;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized investigation request'; END IF;
  IF trusted.role NOT IN ('owner','admin','security_analyst') THEN RAISE EXCEPTION 'Forbidden investigation mutation'; END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at<NOW()-INTERVAL '5 minutes'
    THEN RAISE EXCEPTION 'Investigation step-up required'; END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  IF EXISTS (SELECT 1 FROM unnest(p_finding_ids) x GROUP BY x HAVING count(*)>1)
    THEN RAISE EXCEPTION 'Duplicate finding IDs'; END IF;
  IF (SELECT count(*) FROM onishield.detection_findings f
       WHERE f.tenant_id=trusted.tenant_id AND f.finding_id=ANY(p_finding_ids))
       <> array_length(p_finding_ids,1)
    THEN RAISE EXCEPTION 'Investigation finding not found'; END IF;
  SELECT CASE max(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
    WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
    WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END
    INTO highest FROM onishield.detection_findings
   WHERE tenant_id=trusted.tenant_id AND finding_id=ANY(p_finding_ids);
  INSERT INTO onishield.investigation_cases
    (tenant_id,title,priority,created_by_membership_id)
    VALUES(trusted.tenant_id,btrim(p_title),highest,trusted.membership_id) RETURNING id INTO new_case;
  FOREACH finding IN ARRAY p_finding_ids LOOP
    INSERT INTO onishield.investigation_case_findings
      (tenant_id,case_id,finding_id,association_reason,created_by_membership_id)
      VALUES(trusted.tenant_id,new_case,finding,btrim(p_reason),trusted.membership_id);
    INSERT INTO onishield.investigation_activity
      (tenant_id,case_id,actor_operator_id,actor_membership_id,activity_type,reason,request_id)
      VALUES(trusted.tenant_id,new_case,trusted.operator_id,trusted.membership_id,'finding_associated',
        btrim(p_reason),p_request_id);
  END LOOP;
  INSERT INTO onishield.investigation_activity
    (tenant_id,case_id,actor_operator_id,actor_membership_id,activity_type,reason,request_id)
    VALUES(trusted.tenant_id,new_case,trusted.operator_id,trusted.membership_id,'case_created',
      btrim(p_reason),p_request_id);
  RETURN new_case;
END $$;

CREATE FUNCTION onishield.add_investigation_finding(
  p_token_hash TEXT,p_case_id UUID,p_finding_id TEXT,p_reason TEXT,p_request_id TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' OR length(btrim(p_reason)) NOT BETWEEN 10 AND 1000
    OR p_request_id IS NULL OR length(p_request_id)>128
    THEN RAISE EXCEPTION 'Invalid investigation association request'; END IF;
  SELECT session_row.tenant_id,session_row.operator_id,session_row.membership_id,m.role,session_row.step_up_at INTO trusted
    FROM onishield.operator_sessions session_row JOIN onishield.operators o ON o.id=session_row.operator_id
    JOIN onishield.operator_memberships m ON m.id=session_row.membership_id
      AND m.tenant_id=session_row.tenant_id AND m.operator_id=session_row.operator_id
   WHERE session_row.token_hash=p_token_hash AND session_row.revoked_at IS NULL AND session_row.expires_at>NOW()
     AND o.status='active' AND m.status='active' FOR UPDATE OF session_row;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized investigation request'; END IF;
  IF trusted.role NOT IN ('owner','admin','security_analyst') THEN RAISE EXCEPTION 'Forbidden investigation mutation'; END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at<NOW()-INTERVAL '5 minutes'
    THEN RAISE EXCEPTION 'Investigation step-up required'; END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  PERFORM 1 FROM onishield.investigation_cases c
    WHERE c.tenant_id=trusted.tenant_id AND c.id=p_case_id AND c.status NOT IN ('resolved','closed')
    FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Investigation case not found or closed'; END IF;
  IF NOT EXISTS (SELECT 1 FROM onishield.detection_findings f
    WHERE f.tenant_id=trusted.tenant_id AND f.finding_id=p_finding_id)
    THEN RAISE EXCEPTION 'Investigation finding not found'; END IF;
  INSERT INTO onishield.investigation_case_findings
    (tenant_id,case_id,finding_id,association_reason,created_by_membership_id)
    VALUES(trusted.tenant_id,p_case_id,p_finding_id,btrim(p_reason),trusted.membership_id)
    ON CONFLICT DO NOTHING;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  UPDATE onishield.investigation_cases SET updated_at=NOW(),last_activity_at=NOW()
    WHERE tenant_id=trusted.tenant_id AND id=p_case_id;
  INSERT INTO onishield.investigation_activity
    (tenant_id,case_id,actor_operator_id,actor_membership_id,activity_type,reason,request_id)
    VALUES(trusted.tenant_id,p_case_id,trusted.operator_id,trusted.membership_id,'finding_associated',btrim(p_reason),p_request_id);
  RETURN TRUE;
END $$;

CREATE FUNCTION onishield.add_investigation_note(
  p_token_hash TEXT,p_case_id UUID,p_note TEXT,p_request_id TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' OR length(btrim(p_note)) NOT BETWEEN 10 AND 2000
    OR p_request_id IS NULL OR length(p_request_id)>128
    THEN RAISE EXCEPTION 'Invalid investigation note'; END IF;
  SELECT session_row.tenant_id,session_row.operator_id,session_row.membership_id,m.role,session_row.step_up_at INTO trusted
    FROM onishield.operator_sessions session_row JOIN onishield.operators o ON o.id=session_row.operator_id
    JOIN onishield.operator_memberships m ON m.id=session_row.membership_id
      AND m.tenant_id=session_row.tenant_id AND m.operator_id=session_row.operator_id
   WHERE session_row.token_hash=p_token_hash AND session_row.revoked_at IS NULL AND session_row.expires_at>NOW()
     AND o.status='active' AND m.status='active' FOR UPDATE OF session_row;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized investigation request'; END IF;
  IF trusted.role NOT IN ('owner','admin','security_analyst') THEN RAISE EXCEPTION 'Forbidden investigation mutation'; END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at<NOW()-INTERVAL '5 minutes'
    THEN RAISE EXCEPTION 'Investigation step-up required'; END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  PERFORM 1 FROM onishield.investigation_cases c
    WHERE c.tenant_id=trusted.tenant_id AND c.id=p_case_id AND c.status NOT IN ('resolved','closed')
    FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Investigation case not found or closed'; END IF;
  INSERT INTO onishield.investigation_activity
    (tenant_id,case_id,actor_operator_id,actor_membership_id,activity_type,reason,request_id)
    VALUES(trusted.tenant_id,p_case_id,trusted.operator_id,trusted.membership_id,'note_added',btrim(p_note),p_request_id);
  UPDATE onishield.investigation_cases SET updated_at=NOW(),last_activity_at=NOW()
    WHERE tenant_id=trusted.tenant_id AND id=p_case_id;
  RETURN TRUE;
END $$;

CREATE FUNCTION onishield.get_investigation_case(p_token_hash TEXT,p_case_id UUID)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD; result JSONB;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Invalid investigation token'; END IF;
  SELECT session_row.tenant_id,session_row.operator_id,m.role INTO trusted
    FROM onishield.operator_sessions session_row JOIN onishield.operators o ON o.id=session_row.operator_id
    JOIN onishield.operator_memberships m ON m.id=session_row.membership_id
      AND m.tenant_id=session_row.tenant_id AND m.operator_id=session_row.operator_id
   WHERE session_row.token_hash=p_token_hash AND session_row.revoked_at IS NULL AND session_row.expires_at>NOW()
     AND o.status='active' AND m.status='active';
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized investigation request'; END IF;
  IF trusted.role NOT IN ('owner','admin','security_analyst','reviewer','viewer')
    THEN RAISE EXCEPTION 'Forbidden investigation read'; END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  SELECT jsonb_build_object(
    'case',to_jsonb(c),
    'findings',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'finding',to_jsonb(f),'association_reason',a.association_reason,
      'associated_at',a.created_at,
      'evidence',COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'connector_id',e.connector_id,'event_id',e.event_id
      ) ORDER BY e.connector_id,e.event_id)
      FROM onishield.detection_finding_evidence e
      WHERE e.tenant_id=f.tenant_id AND e.finding_id=f.finding_id),'[]'::jsonb),
      'threat_matches',COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'match_id',tm.id,'connector_id',tm.connector_id,'event_id',tm.event_id,
        'matched_field_path',tm.matched_field_path,'matcher_version',tm.matcher_version,
        'matched_at',tm.matched_at,'indicator_type',ti.indicator_type,
        'indicator_value',ti.value_normalized,'indicator_version',ti.version,
        'indicator_status',ti.status,'confidence',ti.confidence,'tlp',ti.tlp,
        'valid_from',ti.valid_from,'expires_at',ti.expires_at,
        'source_name',src.display_name,'source_kind',src.source_kind
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
      WHERE ftm.tenant_id=f.tenant_id AND ftm.finding_id=f.finding_id),'[]'::jsonb)
    ) ORDER BY f.last_seen_at DESC)
    FROM onishield.investigation_case_findings a
    JOIN onishield.detection_findings f ON f.tenant_id=a.tenant_id AND f.finding_id=a.finding_id
    WHERE a.tenant_id=c.tenant_id AND a.case_id=c.id),'[]'::jsonb),
    'activity',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.created_at,x.id)
      FROM onishield.investigation_activity x
      WHERE x.tenant_id=c.tenant_id AND x.case_id=c.id),'[]'::jsonb)
  ) INTO result FROM onishield.investigation_cases c
  WHERE c.tenant_id=trusted.tenant_id AND c.id=p_case_id;
  IF result IS NULL THEN RAISE EXCEPTION 'Investigation case not found'; END IF;
  RETURN result;
END $$;

CREATE FUNCTION onishield.list_investigation_cases(p_token_hash TEXT,p_limit INTEGER)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD; result JSONB;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' OR p_limit NOT BETWEEN 1 AND 100
    THEN RAISE EXCEPTION 'Invalid investigation list request'; END IF;
  SELECT session_row.tenant_id,m.role INTO trusted FROM onishield.operator_sessions session_row
    JOIN onishield.operators o ON o.id=session_row.operator_id
    JOIN onishield.operator_memberships m ON m.id=session_row.membership_id
      AND m.tenant_id=session_row.tenant_id AND m.operator_id=session_row.operator_id
   WHERE session_row.token_hash=p_token_hash AND session_row.revoked_at IS NULL AND session_row.expires_at>NOW()
     AND o.status='active' AND m.status='active';
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized investigation request'; END IF;
  IF trusted.role NOT IN ('owner','admin','security_analyst','reviewer','viewer')
    THEN RAISE EXCEPTION 'Forbidden investigation read'; END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.last_activity_at DESC),'[]'::jsonb)
    INTO result FROM (
      SELECT c.*,count(a.finding_id)::INTEGER AS finding_count
      FROM onishield.investigation_cases c
      LEFT JOIN onishield.investigation_case_findings a
        ON a.tenant_id=c.tenant_id AND a.case_id=c.id
      WHERE c.tenant_id=trusted.tenant_id
      GROUP BY c.id ORDER BY c.last_activity_at DESC LIMIT p_limit
    ) c;
  RETURN result;
END $$;

REVOKE ALL ON FUNCTION onishield.create_investigation_case(TEXT,TEXT,TEXT[],TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.add_investigation_finding(TEXT,UUID,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.add_investigation_note(TEXT,UUID,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.get_investigation_case(TEXT,UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.list_investigation_cases(TEXT,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.create_investigation_case(TEXT,TEXT,TEXT[],TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.add_investigation_finding(TEXT,UUID,TEXT,TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.add_investigation_note(TEXT,UUID,TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.get_investigation_case(TEXT,UUID) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.list_investigation_cases(TEXT,INTEGER) TO onishield_auth;

COMMIT;
