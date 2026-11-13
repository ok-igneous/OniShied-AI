-- Serialize privileged actions against session revocation.
-- A revocation that commits first must prevent a concurrent review/management action.

CREATE OR REPLACE FUNCTION onishield.review_threat_indicator(
  p_token_hash TEXT, p_indicator_id BIGINT, p_new_status TEXT, p_reason TEXT
) RETURNS TABLE(indicator_id BIGINT, old_status TEXT, new_status TEXT,
                actor_operator_id UUID, changed_at TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE
  trusted_session RECORD;
  previous_status TEXT;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$'
     OR p_indicator_id < 1
     OR p_new_status NOT IN ('active','rejected','revoked','expired')
     OR length(btrim(COALESCE(p_reason,''))) < 10
     OR length(p_reason) > 1000 THEN
    RAISE EXCEPTION 'Invalid review request';
  END IF;

  SELECT s.id, s.tenant_id, s.operator_id, m.role
    INTO trusted_session
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id = s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id = s.membership_id AND m.tenant_id = s.tenant_id
     AND m.operator_id = s.operator_id
   WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL
     AND s.expires_at > NOW() AND o.status = 'active'
     AND m.status = 'active'
   FOR UPDATE OF s;

  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized threat indicator review'; END IF;
  IF trusted_session.role NOT IN ('owner','admin','reviewer') THEN
    RAISE EXCEPTION 'Unauthorized threat indicator review'; END IF;

  PERFORM set_config('app.tenant_id', trusted_session.tenant_id, true);
  PERFORM set_config('app.operator_id', trusted_session.operator_id::TEXT, true);
  PERFORM set_config('app.threat_review_reason', btrim(p_reason), true);

  SELECT status INTO previous_status
    FROM onishield.threat_indicators
   WHERE tenant_id = trusted_session.tenant_id AND id = p_indicator_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Threat indicator not found'; END IF;

  UPDATE onishield.threat_indicators
     SET status = p_new_status
   WHERE tenant_id = trusted_session.tenant_id AND id = p_indicator_id;

  RETURN QUERY
    SELECT a.indicator_id, a.old_status, a.new_status,
           a.actor_operator_id, a.changed_at
      FROM onishield.threat_indicator_status_audit a
     WHERE a.tenant_id = trusted_session.tenant_id
       AND a.indicator_id = p_indicator_id
     ORDER BY a.changed_at DESC, a.id DESC
     LIMIT 1;
END;
$$;

CREATE OR REPLACE FUNCTION onishield.revoke_operator_session_by_id(
  p_token_hash TEXT, p_target_session_id UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE current_session RECORD;
  changed_count INTEGER := 0;
BEGIN
  SELECT s.id, s.tenant_id, s.operator_id
    INTO current_session
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id = s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id = s.membership_id AND m.tenant_id = s.tenant_id
     AND m.operator_id = s.operator_id
   WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL
     AND s.expires_at > NOW() AND o.status = 'active' AND m.status = 'active'
   FOR UPDATE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized session revocation'; END IF;

  UPDATE onishield.operator_sessions
     SET revoked_at = NOW()
   WHERE id = p_target_session_id
     AND tenant_id = current_session.tenant_id
     AND operator_id = current_session.operator_id
     AND id <> current_session.id
     AND revoked_at IS NULL;
  GET DIAGNOSTICS changed_count = ROW_COUNT;
  RETURN changed_count > 0;
END;
$$;

REVOKE ALL ON FUNCTION onishield.review_threat_indicator(TEXT,BIGINT,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.review_threat_indicator(TEXT,BIGINT,TEXT,TEXT) TO onishield_auth;
REVOKE ALL ON FUNCTION onishield.revoke_operator_session_by_id(TEXT,UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.revoke_operator_session_by_id(TEXT,UUID) TO onishield_auth;
