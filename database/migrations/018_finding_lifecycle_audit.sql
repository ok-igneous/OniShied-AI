-- Analyst-controlled detection finding lifecycle with database-enforced authorization.
BEGIN;

ALTER TABLE onishield.detection_findings
  DROP CONSTRAINT detection_findings_status_check,
  ADD CONSTRAINT detection_findings_status_check
    CHECK (status IN ('open', 'acknowledged', 'investigating', 'resolved', 'reopened', 'suppressed'));

-- The ingestion upsert may enrich evidence/timestamps but must not change status.
REVOKE UPDATE ON onishield.detection_findings FROM onishield_app;
GRANT UPDATE (
  first_seen_at, last_seen_at, evidence_event_refs, evidence_event_ids,
  matched_conditions, updated_at
) ON onishield.detection_findings TO onishield_app;

CREATE POLICY detection_findings_owner_lifecycle
  ON onishield.detection_findings
  TO onishield_owner
  USING (true)
  WITH CHECK (true);

CREATE TABLE onishield.detection_finding_status_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  membership_id BIGINT NOT NULL,
  actor_operator_id UUID NOT NULL,
  previous_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 10 AND 1000),
  request_id TEXT,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT detection_finding_status_audit_finding_fk
    FOREIGN KEY (tenant_id, finding_id)
    REFERENCES onishield.detection_findings (tenant_id, finding_id),
  CONSTRAINT detection_finding_status_audit_membership_fk
    FOREIGN KEY (tenant_id, membership_id, actor_operator_id)
    REFERENCES onishield.operator_memberships (tenant_id, id, operator_id),
  CONSTRAINT detection_finding_status_audit_status_check
    CHECK (previous_status IN ('open','acknowledged','investigating','resolved','reopened','suppressed')
       AND new_status IN ('open','acknowledged','investigating','resolved','reopened','suppressed'))
);

CREATE INDEX detection_finding_status_audit_timeline_idx
  ON onishield.detection_finding_status_audit (tenant_id, finding_id, changed_at DESC, id DESC);

ALTER TABLE onishield.detection_finding_status_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.detection_finding_status_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY detection_finding_status_audit_tenant
  ON onishield.detection_finding_status_audit
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY detection_finding_status_audit_owner
  ON onishield.detection_finding_status_audit
  TO onishield_owner
  USING (true)
  WITH CHECK (true);

REVOKE ALL ON onishield.detection_finding_status_audit FROM PUBLIC, onishield_app, onishield_auth;
GRANT USAGE, SELECT ON SEQUENCE onishield.detection_finding_status_audit_id_seq TO onishield_owner;

CREATE FUNCTION onishield.transition_detection_finding(
  p_token_hash TEXT,
  p_finding_id TEXT,
  p_new_status TEXT,
  p_reason TEXT,
  p_request_id TEXT DEFAULT NULL
) RETURNS TABLE(
  finding_id TEXT,
  previous_status TEXT,
  new_status TEXT,
  actor_operator_id UUID,
  changed_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE
  trusted_session RECORD;
  old_status TEXT;
  changed TIMESTAMPTZ := NOW();
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$'
     OR p_finding_id !~ '^[a-f0-9]{64}$'
     OR p_new_status NOT IN ('acknowledged','investigating','resolved','reopened','suppressed')
     OR length(btrim(COALESCE(p_reason,''))) < 10
     OR length(p_reason) > 1000
     OR (p_request_id IS NOT NULL AND length(p_request_id) > 128) THEN
    RAISE EXCEPTION 'Invalid finding transition request';
  END IF;

  SELECT s.id, s.tenant_id, s.operator_id, s.membership_id, m.role, s.step_up_at
    INTO trusted_session
    FROM onishield.operator_sessions AS s
    JOIN onishield.operators AS o ON o.id = s.operator_id
    JOIN onishield.operator_memberships AS m
      ON m.id = s.membership_id
     AND m.tenant_id = s.tenant_id
     AND m.operator_id = s.operator_id
   WHERE s.token_hash = p_token_hash
     AND s.revoked_at IS NULL
     AND s.expires_at > NOW()
     AND o.status = 'active'
     AND m.status = 'active'
   FOR UPDATE OF s;

  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized finding transition'; END IF;
  IF trusted_session.role NOT IN ('owner','admin','security_analyst') THEN
    RAISE EXCEPTION 'Forbidden finding transition';
  END IF;
  IF trusted_session.step_up_at IS NULL
     OR trusted_session.step_up_at < NOW() - INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'Step-up authentication required';
  END IF;

  PERFORM set_config('app.tenant_id', trusted_session.tenant_id, true);
  SELECT f.status INTO old_status
    FROM onishield.detection_findings AS f
   WHERE f.tenant_id = trusted_session.tenant_id
     AND f.finding_id = p_finding_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Detection finding not found'; END IF;

  IF NOT (
    (old_status = 'open' AND p_new_status IN ('acknowledged','suppressed'))
    OR (old_status = 'acknowledged' AND p_new_status IN ('investigating','resolved'))
    OR (old_status = 'investigating' AND p_new_status = 'resolved')
    OR (old_status = 'resolved' AND p_new_status = 'reopened')
    OR (old_status = 'reopened' AND p_new_status IN ('acknowledged','investigating','resolved'))
  ) THEN
    RAISE EXCEPTION 'Invalid finding status transition';
  END IF;

  UPDATE onishield.detection_findings
     SET status = p_new_status, updated_at = changed
   WHERE tenant_id = trusted_session.tenant_id
     AND finding_id = p_finding_id;

  INSERT INTO onishield.detection_finding_status_audit
    (tenant_id, finding_id, membership_id, actor_operator_id,
     previous_status, new_status, reason, request_id, changed_at)
  VALUES
    (trusted_session.tenant_id, p_finding_id, trusted_session.membership_id,
     trusted_session.operator_id, old_status, p_new_status,
     btrim(p_reason), p_request_id, changed);

  RETURN QUERY SELECT p_finding_id, old_status, p_new_status,
                      trusted_session.operator_id, changed;
END;
$$;

REVOKE ALL ON FUNCTION onishield.transition_detection_finding(TEXT,TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.transition_detection_finding(TEXT,TEXT,TEXT,TEXT,TEXT) TO onishield_auth;

COMMIT;
