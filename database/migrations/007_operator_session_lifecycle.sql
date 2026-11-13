-- Session rotation and operator-controlled session inventory/revocation.
-- Functions derive all identity from a currently valid opaque session.

CREATE FUNCTION onishield.rotate_operator_session(
  p_current_token_hash TEXT, p_new_token_hash TEXT, p_expires_at TIMESTAMPTZ
) RETURNS TABLE(session_id UUID, tenant_id TEXT, operator_id UUID,
                membership_id BIGINT, expires_at TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE current_session RECORD;
BEGIN
  IF p_current_token_hash !~ '^[a-f0-9]{64}$'
     OR p_new_token_hash !~ '^[a-f0-9]{64}$'
     OR p_current_token_hash = p_new_token_hash
     OR p_expires_at <= NOW()
     OR p_expires_at > NOW() + INTERVAL '8 hours' THEN
    RAISE EXCEPTION 'Invalid session rotation request';
  END IF;

  SELECT s.id, s.tenant_id, s.operator_id, s.membership_id
    INTO current_session
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id = s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id = s.membership_id AND m.tenant_id = s.tenant_id
     AND m.operator_id = s.operator_id
   WHERE s.token_hash = p_current_token_hash
     AND s.revoked_at IS NULL AND s.expires_at > NOW()
     AND o.status = 'active' AND m.status = 'active'
   FOR UPDATE OF s;

  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized session rotation'; END IF;

  UPDATE onishield.operator_sessions
     SET revoked_at = NOW()
   WHERE id = current_session.id AND revoked_at IS NULL;

  RETURN QUERY
    INSERT INTO onishield.operator_sessions
      (tenant_id, operator_id, membership_id, token_hash, expires_at)
    VALUES
      (current_session.tenant_id, current_session.operator_id,
       current_session.membership_id, p_new_token_hash, p_expires_at)
    RETURNING id, onishield.operator_sessions.tenant_id,
              onishield.operator_sessions.operator_id,
              onishield.operator_sessions.membership_id,
              onishield.operator_sessions.expires_at;
END;
$$;

CREATE FUNCTION onishield.list_operator_sessions(p_token_hash TEXT)
RETURNS TABLE(session_id UUID, created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
              last_seen_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
              is_current BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE current_session RECORD;
BEGIN
  SELECT s.id, s.tenant_id, s.operator_id
    INTO current_session
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id = s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id = s.membership_id AND m.tenant_id = s.tenant_id
     AND m.operator_id = s.operator_id
   WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL
     AND s.expires_at > NOW() AND o.status = 'active' AND m.status = 'active';
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized session inventory'; END IF;

  RETURN QUERY
    SELECT s.id, s.created_at, s.expires_at, s.last_seen_at, s.revoked_at,
           s.id = current_session.id
      FROM onishield.operator_sessions s
     WHERE s.tenant_id = current_session.tenant_id
       AND s.operator_id = current_session.operator_id
     ORDER BY s.created_at DESC
     LIMIT 50;
END;
$$;

CREATE FUNCTION onishield.revoke_operator_session_by_id(
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
     AND s.expires_at > NOW() AND o.status = 'active' AND m.status = 'active';
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

REVOKE ALL ON FUNCTION onishield.rotate_operator_session(TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.list_operator_sessions(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.revoke_operator_session_by_id(TEXT,UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.rotate_operator_session(TEXT,TEXT,TIMESTAMPTZ) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.list_operator_sessions(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.revoke_operator_session_by_id(TEXT,UUID) TO onishield_auth;
