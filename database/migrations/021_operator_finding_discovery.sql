-- Authenticated, tenant-scoped finding discovery for the operator console.
BEGIN;

CREATE FUNCTION onishield.list_operator_detection_findings(
  p_token_hash TEXT,
  p_limit INTEGER DEFAULT 50,
  p_status TEXT DEFAULT NULL,
  p_severity TEXT DEFAULT NULL,
  p_query TEXT DEFAULT NULL
) RETURNS TABLE(
  finding_id TEXT, rule_id TEXT, title TEXT, explanation TEXT, status TEXT,
  severity TEXT, confidence TEXT, first_seen_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ,
  evidence_event_refs JSONB, matched_conditions JSONB, associated_case_id UUID
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE trusted_session RECORD;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$'
     OR p_limit IS NULL OR p_limit < 1 OR p_limit > 100
     OR (p_status IS NOT NULL AND p_status NOT IN
       ('open','acknowledged','investigating','resolved','reopened','suppressed'))
     OR (p_severity IS NOT NULL AND p_severity NOT IN ('info','low','medium','high','critical'))
     OR (p_query IS NOT NULL AND length(p_query) > 100) THEN
    RAISE EXCEPTION 'Invalid operator finding query';
  END IF;

  SELECT session_row.tenant_id, membership.role
    INTO trusted_session
    FROM onishield.operator_sessions AS session_row
    JOIN onishield.operators AS operator_row ON operator_row.id = session_row.operator_id
    JOIN onishield.operator_memberships AS membership
      ON membership.id = session_row.membership_id
     AND membership.tenant_id = session_row.tenant_id
     AND membership.operator_id = session_row.operator_id
   WHERE session_row.token_hash = p_token_hash
     AND session_row.revoked_at IS NULL AND session_row.expires_at > NOW()
     AND operator_row.status = 'active' AND membership.status = 'active'
   FOR SHARE OF session_row;

  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized operator finding query'; END IF;
  IF trusted_session.role NOT IN ('owner','admin','security_analyst','reviewer','viewer') THEN
    RAISE EXCEPTION 'Forbidden operator finding query';
  END IF;

  PERFORM set_config('app.tenant_id', trusted_session.tenant_id, true);
  RETURN QUERY
    SELECT finding.finding_id, finding.rule_id, finding.title, finding.explanation,
           finding.status, finding.severity, finding.confidence, finding.first_seen_at,
           finding.last_seen_at, finding.evidence_event_refs, finding.matched_conditions,
           association.case_id
      FROM onishield.detection_findings AS finding
      LEFT JOIN onishield.investigation_case_findings AS association
        ON association.tenant_id = finding.tenant_id
       AND association.finding_id = finding.finding_id
     WHERE finding.tenant_id = trusted_session.tenant_id
       AND (p_status IS NULL OR finding.status = p_status)
       AND (p_severity IS NULL OR finding.severity = p_severity)
       AND (NULLIF(btrim(p_query), '') IS NULL
         OR finding.title ILIKE '%' || btrim(p_query) || '%'
         OR finding.explanation ILIKE '%' || btrim(p_query) || '%'
         OR finding.finding_id = btrim(p_query))
     ORDER BY finding.last_seen_at DESC, finding.id DESC
     LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION
  onishield.list_operator_detection_findings(TEXT,INTEGER,TEXT,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  onishield.list_operator_detection_findings(TEXT,INTEGER,TEXT,TEXT,TEXT) TO onishield_auth;

COMMIT;
