-- Persistent authentication throttling and authenticated threat-review audit.
-- All privileged functions are owned by onishield_owner through apply-migrations.sql.

CREATE TABLE onishield.operator_login_limits (
  bucket_hash TEXT PRIMARY KEY CHECK (bucket_hash ~ '^[a-f0-9]{64}$'),
  attempts INTEGER NOT NULL CHECK (attempts >= 1),
  window_started_at TIMESTAMPTZ NOT NULL,
  blocked_until TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX operator_login_limits_updated_idx
  ON onishield.operator_login_limits(updated_at);

ALTER TABLE onishield.operator_login_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.operator_login_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_login_limits_owner_all
  ON onishield.operator_login_limits TO onishield_owner
  USING (true) WITH CHECK (true);
REVOKE ALL ON onishield.operator_login_limits FROM PUBLIC, onishield_app, onishield_auth;

CREATE FUNCTION onishield.consume_operator_login_limit(
  p_bucket_hash TEXT, p_max_attempts INTEGER DEFAULT 5,
  p_window_seconds INTEGER DEFAULT 900, p_lock_seconds INTEGER DEFAULT 900
) RETURNS TABLE(allowed BOOLEAN, retry_after_seconds INTEGER)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE current_row onishield.operator_login_limits%ROWTYPE;
  inserted_count INTEGER;
BEGIN
  IF p_bucket_hash !~ '^[a-f0-9]{64}$'
     OR p_max_attempts < 1 OR p_max_attempts > 20
     OR p_window_seconds < 60 OR p_window_seconds > 3600
     OR p_lock_seconds < 60 OR p_lock_seconds > 3600 THEN
    RAISE EXCEPTION 'Invalid login throttle parameters';
  END IF;

  INSERT INTO onishield.operator_login_limits(bucket_hash, attempts, window_started_at)
  VALUES (p_bucket_hash, 1, NOW())
  ON CONFLICT (bucket_hash) DO NOTHING;
  GET DIAGNOSTICS inserted_count = ROW_COUNT;
  IF inserted_count = 1 THEN
    RETURN QUERY SELECT TRUE, 0;
    RETURN;
  END IF;

  SELECT * INTO current_row
  FROM onishield.operator_login_limits
  WHERE bucket_hash = p_bucket_hash
  FOR UPDATE;

  IF current_row.blocked_until > NOW() THEN
    RETURN QUERY SELECT FALSE,
      GREATEST(1, CEIL(EXTRACT(EPOCH FROM (current_row.blocked_until - NOW())))::INTEGER);
    RETURN;
  END IF;

  IF current_row.window_started_at <= NOW() - make_interval(secs => p_window_seconds) THEN
    UPDATE onishield.operator_login_limits
       SET attempts = 1, window_started_at = NOW(), blocked_until = NULL, updated_at = NOW()
     WHERE bucket_hash = p_bucket_hash;
    RETURN QUERY SELECT TRUE, 0;
    RETURN;
  END IF;

  UPDATE onishield.operator_login_limits
     SET attempts = attempts + 1,
         blocked_until = CASE WHEN attempts + 1 > p_max_attempts
                              THEN NOW() + make_interval(secs => p_lock_seconds)
                              ELSE blocked_until END,
         updated_at = NOW()
   WHERE bucket_hash = p_bucket_hash
   RETURNING * INTO current_row;

  RETURN QUERY SELECT current_row.blocked_until IS NULL,
    CASE WHEN current_row.blocked_until IS NULL THEN 0
         ELSE GREATEST(1, CEIL(EXTRACT(EPOCH FROM (current_row.blocked_until - NOW())))::INTEGER) END;
END;
$$;

CREATE FUNCTION onishield.reset_operator_login_limit(p_bucket_hash TEXT)
RETURNS VOID
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
  DELETE FROM onishield.operator_login_limits WHERE bucket_hash = p_bucket_hash
$$;

REVOKE ALL ON FUNCTION onishield.consume_operator_login_limit(TEXT,INTEGER,INTEGER,INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.reset_operator_login_limit(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.consume_operator_login_limit(TEXT,INTEGER,INTEGER,INTEGER) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.reset_operator_login_limit(TEXT) TO onishield_auth;

-- New review records identify the authenticated operator, not only the shared
-- PostgreSQL service login. Existing historical rows remain NULL.
ALTER TABLE onishield.threat_indicator_status_audit
  ADD COLUMN actor_operator_id UUID REFERENCES onishield.operators(id);

-- Disable the legacy shared database reviewer path. Human reviews must pass
-- through the session-verifying function below; a custom GUC is not identity.
DROP POLICY IF EXISTS threat_indicators_reviewer_update ON onishield.threat_indicators;
REVOKE SELECT, UPDATE ON onishield.threat_indicators FROM onishield_reviewer;
REVOKE SELECT ON onishield.threat_indicator_status_audit FROM onishield_reviewer;

CREATE POLICY threat_indicators_owner_review_update
  ON onishield.threat_indicators
  FOR UPDATE TO onishield_owner
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY threat_indicator_audit_owner_read
  ON onishield.threat_indicator_status_audit
  FOR SELECT TO onishield_owner
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE OR REPLACE FUNCTION onishield.audit_threat_indicator_status_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE
  transition_reason TEXT;
  authenticated_operator UUID;
BEGIN
  IF (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
    RAISE EXCEPTION 'Reviewer may change only indicator status';
  END IF;

  IF NOT (
    (OLD.status = 'pending' AND NEW.status IN ('active', 'rejected'))
    OR (OLD.status = 'active' AND NEW.status IN ('revoked', 'expired'))
  ) THEN
    RAISE EXCEPTION 'Illegal threat indicator status transition: % -> %',
      OLD.status, NEW.status;
  END IF;

  transition_reason := current_setting('app.threat_review_reason', true);
  authenticated_operator := NULLIF(current_setting('app.operator_id', true), '')::UUID;
  IF transition_reason IS NULL OR length(btrim(transition_reason)) < 10
     OR length(transition_reason) > 1000 OR authenticated_operator IS NULL THEN
    RAISE EXCEPTION 'Authenticated reviewer and a reason between 10 and 1000 characters are required';
  END IF;

  INSERT INTO onishield.threat_indicator_status_audit
    (tenant_id, indicator_id, indicator_version, old_status, new_status,
     actor_db_role, actor_operator_id, reason)
  VALUES
    (OLD.tenant_id, OLD.id, OLD.version, OLD.status, NEW.status,
     session_user::text, authenticated_operator, btrim(transition_reason));

  RETURN NEW;
END;
$$;

CREATE FUNCTION onishield.review_threat_indicator(
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

  SELECT s.tenant_id, s.operator_id, m.role
    INTO trusted_session
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id = s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id = s.membership_id AND m.tenant_id = s.tenant_id
     AND m.operator_id = s.operator_id
   WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL
     AND s.expires_at > NOW() AND o.status = 'active'
     AND m.status = 'active'
   LIMIT 1;

  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized threat indicator review'; END IF;
  IF trusted_session.role NOT IN ('owner','admin','reviewer') THEN
    RAISE EXCEPTION 'Unauthorized threat indicator review';
  END IF;

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

REVOKE ALL ON FUNCTION onishield.review_threat_indicator(TEXT,BIGINT,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.review_threat_indicator(TEXT,BIGINT,TEXT,TEXT) TO onishield_auth;

-- Opportunistic cleanup is performed by a separately scheduled maintenance task.
