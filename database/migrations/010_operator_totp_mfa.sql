-- Operator TOTP MFA: encrypted secrets, one-time challenges and replay protection.
-- Remove the earlier password-only step-up function so enrolled accounts cannot bypass TOTP.
DROP FUNCTION onishield.mark_operator_session_step_up(TEXT);

ALTER TABLE onishield.operator_sessions ADD COLUMN mfa_enrollment_step_up_at TIMESTAMPTZ;
UPDATE onishield.operator_sessions SET step_up_at=NULL,mfa_enrollment_step_up_at=NULL;

CREATE TABLE onishield.operator_mfa_credentials (
  operator_id UUID PRIMARY KEY REFERENCES onishield.operators(id) ON DELETE CASCADE,
  pending_ciphertext BYTEA,
  pending_nonce BYTEA,
  pending_tag BYTEA,
  pending_expires_at TIMESTAMPTZ,
  active_ciphertext BYTEA,
  active_nonce BYTEA,
  active_tag BYTEA,
  enabled_at TIMESTAMPTZ,
  last_totp_counter BIGINT NOT NULL DEFAULT -1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((pending_ciphertext IS NULL) = (pending_nonce IS NULL)),
  CHECK ((pending_ciphertext IS NULL) = (pending_tag IS NULL)),
  CHECK ((pending_ciphertext IS NULL) = (pending_expires_at IS NULL)),
  CHECK ((active_ciphertext IS NULL) = (active_nonce IS NULL)),
  CHECK ((active_ciphertext IS NULL) = (active_tag IS NULL)),
  CHECK ((enabled_at IS NULL) = (active_ciphertext IS NULL))
);

CREATE TABLE onishield.operator_login_challenges (
  token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  tenant_id TEXT NOT NULL,
  operator_id UUID NOT NULL,
  membership_id BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  FOREIGN KEY (tenant_id,membership_id,operator_id)
    REFERENCES onishield.operator_memberships(tenant_id,id,operator_id),
  CHECK (expires_at > created_at)
);

CREATE TABLE onishield.operator_mfa_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  operator_id UUID NOT NULL REFERENCES onishield.operators(id),
  action TEXT NOT NULL CHECK (action IN ('enrollment_started','enabled','disabled','login_verified','step_up')),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX operator_mfa_audit_operator_idx
  ON onishield.operator_mfa_audit(operator_id,occurred_at DESC);
CREATE INDEX operator_login_challenges_expiry_idx
  ON onishield.operator_login_challenges(expires_at);

REVOKE ALL ON onishield.operator_mfa_credentials,
  onishield.operator_login_challenges, onishield.operator_mfa_audit
  FROM PUBLIC, onishield_app, onishield_auth;

CREATE FUNCTION onishield.get_operator_mfa(p_operator_id UUID)
RETURNS TABLE(enabled BOOLEAN, ciphertext BYTEA, nonce BYTEA, auth_tag BYTEA)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
  SELECT (m.enabled_at IS NOT NULL),m.active_ciphertext,m.active_nonce,m.active_tag
  FROM onishield.operator_mfa_credentials m
  WHERE m.operator_id=p_operator_id
$$;


CREATE FUNCTION onishield.mark_operator_session_mfa_enrollment_step_up(p_token_hash TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE session_id UUID;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' THEN RETURN FALSE; END IF;
  SELECT s.id INTO session_id
  FROM onishield.operator_sessions s
  JOIN onishield.operators o ON o.id=s.operator_id
  JOIN onishield.operator_memberships m
    ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
  WHERE s.token_hash=p_token_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
    AND o.status='active' AND m.status='active'
  FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  UPDATE onishield.operator_sessions SET mfa_enrollment_step_up_at=NOW()
  WHERE id=session_id;
  RETURN TRUE;
END;
$$;

CREATE FUNCTION onishield.store_pending_operator_mfa(
  p_session_hash TEXT,p_ciphertext BYTEA,p_nonce BYTEA,p_auth_tag BYTEA
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
BEGIN
  IF p_session_hash !~ '^[a-f0-9]{64}$'
     OR octet_length(p_ciphertext)<16 OR octet_length(p_ciphertext)>256
     OR octet_length(p_nonce)<>12 OR octet_length(p_auth_tag)<>16 THEN
    RETURN FALSE;
  END IF;
  SELECT s.operator_id INTO trusted
  FROM onishield.operator_sessions s
  JOIN onishield.operators o ON o.id=s.operator_id
  JOIN onishield.operator_memberships m
    ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
  WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
    AND s.step_up_at>=NOW()-INTERVAL '5 minutes'
    AND o.status='active' AND m.status='active'
  FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN FALSE; END IF;

  INSERT INTO onishield.operator_mfa_credentials
    (operator_id,pending_ciphertext,pending_nonce,pending_tag,pending_expires_at,
     active_ciphertext,active_nonce,active_tag,enabled_at,last_totp_counter)
  VALUES
    (trusted.operator_id,p_ciphertext,p_nonce,p_auth_tag,NOW()+INTERVAL '10 minutes',
     NULL,NULL,NULL,NULL,-1)
  ON CONFLICT(operator_id) DO UPDATE SET
    pending_ciphertext=EXCLUDED.pending_ciphertext,
    pending_nonce=EXCLUDED.pending_nonce,
    pending_tag=EXCLUDED.pending_tag,
    pending_expires_at=EXCLUDED.pending_expires_at,
    updated_at=NOW()
  WHERE onishield.operator_mfa_credentials.enabled_at IS NULL;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  INSERT INTO onishield.operator_mfa_audit(operator_id,action)
    VALUES(trusted.operator_id,'enrollment_started');
  RETURN TRUE;
END;
$$;

CREATE FUNCTION onishield.get_pending_operator_mfa(p_session_hash TEXT)
RETURNS TABLE(ciphertext BYTEA,nonce BYTEA,auth_tag BYTEA)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted_operator UUID;
BEGIN
  SELECT s.operator_id INTO trusted_operator
  FROM onishield.operator_sessions s
  JOIN onishield.operators o ON o.id=s.operator_id
  JOIN onishield.operator_memberships m
    ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
  WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
    AND o.status='active' AND m.status='active';
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY
    SELECT c.pending_ciphertext,c.pending_nonce,c.pending_tag
    FROM onishield.operator_mfa_credentials c
    WHERE c.operator_id=trusted_operator AND c.enabled_at IS NULL
      AND c.pending_ciphertext IS NOT NULL AND c.pending_expires_at>NOW();
END;
$$;

CREATE FUNCTION onishield.activate_operator_mfa(p_session_hash TEXT,p_counter BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
BEGIN
  IF p_session_hash !~ '^[a-f0-9]{64}$' OR p_counter<0 THEN RETURN FALSE; END IF;
  SELECT s.operator_id INTO trusted
  FROM onishield.operator_sessions s
  JOIN onishield.operators o ON o.id=s.operator_id
  JOIN onishield.operator_memberships m
    ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
  WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
    AND o.status='active' AND m.status='active'
  FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  UPDATE onishield.operator_mfa_credentials SET
    active_ciphertext=pending_ciphertext,active_nonce=pending_nonce,active_tag=pending_tag,
    pending_ciphertext=NULL,pending_nonce=NULL,pending_tag=NULL,pending_expires_at=NULL,
    enabled_at=NOW(),last_totp_counter=p_counter,updated_at=NOW()
  WHERE operator_id=trusted.operator_id AND pending_ciphertext IS NOT NULL
    AND pending_expires_at>NOW() AND enabled_at IS NULL;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  INSERT INTO onishield.operator_mfa_audit(operator_id,action)
    VALUES(trusted.operator_id,'enabled');
  RETURN TRUE;
END;
$$;

CREATE FUNCTION onishield.create_operator_login_challenge(
  p_token_hash TEXT,p_tenant_id TEXT,p_operator_id UUID,p_membership_id BIGINT,p_expires_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' OR p_expires_at<=NOW()
     OR p_expires_at>NOW()+INTERVAL '5 minutes'
     OR NOT EXISTS (SELECT 1 FROM onishield.operator_mfa_credentials
       WHERE operator_id=p_operator_id AND enabled_at IS NOT NULL) THEN
    RAISE EXCEPTION 'Invalid MFA login challenge';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM onishield.operators o
    JOIN onishield.operator_memberships m ON m.operator_id=o.id
    WHERE o.id=p_operator_id AND o.status='active' AND m.id=p_membership_id
      AND m.tenant_id=p_tenant_id AND m.status='active'
  ) THEN RAISE EXCEPTION 'Invalid MFA login challenge'; END IF;
  INSERT INTO onishield.operator_login_challenges
    (token_hash,tenant_id,operator_id,membership_id,expires_at)
  VALUES(p_token_hash,p_tenant_id,p_operator_id,p_membership_id,p_expires_at);
  RETURN TRUE;
END;
$$;

CREATE FUNCTION onishield.get_operator_login_challenge(p_token_hash TEXT)
RETURNS TABLE(operator_id UUID,expires_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
  SELECT c.operator_id,c.expires_at
  FROM onishield.operator_login_challenges c
  JOIN onishield.operators o ON o.id=c.operator_id
  JOIN onishield.operator_memberships m
    ON m.id=c.membership_id AND m.tenant_id=c.tenant_id AND m.operator_id=c.operator_id
  WHERE c.token_hash=p_token_hash AND c.consumed_at IS NULL AND c.expires_at>NOW()
    AND o.status='active' AND m.status='active'
$$;

CREATE FUNCTION onishield.consume_operator_login_challenge(
  p_challenge_hash TEXT,p_counter BIGINT,p_session_hash TEXT,p_session_expires TIMESTAMPTZ
) RETURNS TABLE(session_id UUID)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE challenge RECORD;
BEGIN
  IF p_challenge_hash !~ '^[a-f0-9]{64}$' OR p_session_hash !~ '^[a-f0-9]{64}$'
     OR p_counter<0 OR p_session_expires<=NOW()
     OR p_session_expires>NOW()+INTERVAL '8 hours' THEN
    RAISE EXCEPTION 'Invalid MFA challenge completion';
  END IF;
  SELECT * INTO challenge FROM onishield.operator_login_challenges
  WHERE token_hash=p_challenge_hash AND consumed_at IS NULL AND expires_at>NOW()
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Invalid MFA challenge'; END IF;
  UPDATE onishield.operator_mfa_credentials SET
    last_totp_counter=p_counter,updated_at=NOW()
  WHERE operator_id=challenge.operator_id AND enabled_at IS NOT NULL
    AND last_totp_counter<p_counter;
  IF NOT FOUND THEN RAISE EXCEPTION 'Invalid or replayed MFA code'; END IF;
  UPDATE onishield.operator_login_challenges SET consumed_at=NOW()
  WHERE token_hash=p_challenge_hash AND consumed_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'MFA challenge already consumed'; END IF;
  INSERT INTO onishield.operator_mfa_audit(operator_id,action)
    VALUES(challenge.operator_id,'login_verified');
  RETURN QUERY
    INSERT INTO onishield.operator_sessions
      (tenant_id,operator_id,membership_id,token_hash,expires_at)
    VALUES
      (challenge.tenant_id,challenge.operator_id,challenge.membership_id,p_session_hash,p_session_expires)
    RETURNING id;
END;
$$;

CREATE FUNCTION onishield.mark_operator_session_step_up(p_token_hash TEXT,p_counter BIGINT DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
  mfa_enabled BOOLEAN;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' THEN RETURN FALSE; END IF;
  SELECT s.id,s.operator_id,m.role INTO trusted
  FROM onishield.operator_sessions s
  JOIN onishield.operators o ON o.id=s.operator_id
  JOIN onishield.operator_memberships m
    ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
  WHERE s.token_hash=p_token_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
    AND o.status='active' AND m.status='active'
  FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  SELECT enabled_at IS NOT NULL INTO mfa_enabled
  FROM onishield.operator_mfa_credentials
  WHERE operator_id=trusted.operator_id FOR UPDATE;
  IF trusted.role IN ('owner','admin','reviewer') AND NOT COALESCE(mfa_enabled,FALSE) THEN
    RETURN FALSE;
  END IF;
  IF COALESCE(mfa_enabled,FALSE) THEN
    IF p_counter IS NULL THEN RETURN FALSE; END IF;
    UPDATE onishield.operator_mfa_credentials SET
      last_totp_counter=p_counter,updated_at=NOW()
    WHERE operator_id=trusted.operator_id AND enabled_at IS NOT NULL
      AND last_totp_counter<p_counter;
    IF NOT FOUND THEN RETURN FALSE; END IF;
  ELSIF p_counter IS NOT NULL THEN
    RETURN FALSE;
  END IF;
  UPDATE onishield.operator_sessions SET step_up_at=NOW() WHERE id=trusted.id;
  INSERT INTO onishield.operator_mfa_audit(operator_id,action)
    VALUES(trusted.operator_id,'step_up');
  RETURN TRUE;
END;
$$;

CREATE FUNCTION onishield.disable_operator_mfa(p_token_hash TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
BEGIN
  SELECT s.id,s.operator_id INTO trusted
  FROM onishield.operator_sessions s
  JOIN onishield.operators o ON o.id=s.operator_id
  JOIN onishield.operator_memberships m
    ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
  WHERE s.token_hash=p_token_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
    AND s.step_up_at>=NOW()-INTERVAL '5 minutes'
    AND o.status='active' AND m.status='active'
  FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  DELETE FROM onishield.operator_mfa_credentials
  WHERE operator_id=trusted.operator_id AND enabled_at IS NOT NULL;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  INSERT INTO onishield.operator_mfa_audit(operator_id,action)
    VALUES(trusted.operator_id,'disabled');
  RETURN TRUE;
END;
$$;

REVOKE ALL ON FUNCTION onishield.get_operator_mfa(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.mark_operator_session_mfa_enrollment_step_up(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.store_pending_operator_mfa(TEXT,BYTEA,BYTEA,BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.get_pending_operator_mfa(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.activate_operator_mfa(TEXT,BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.create_operator_login_challenge(TEXT,TEXT,UUID,BIGINT,TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.get_operator_login_challenge(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.consume_operator_login_challenge(TEXT,BIGINT,TEXT,TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.mark_operator_session_step_up(TEXT,BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.disable_operator_mfa(TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION onishield.get_operator_mfa(UUID) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.mark_operator_session_mfa_enrollment_step_up(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.store_pending_operator_mfa(TEXT,BYTEA,BYTEA,BYTEA) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.get_pending_operator_mfa(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.activate_operator_mfa(TEXT,BIGINT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.create_operator_login_challenge(TEXT,TEXT,UUID,BIGINT,TIMESTAMPTZ) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.get_operator_login_challenge(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.consume_operator_login_challenge(TEXT,BIGINT,TEXT,TIMESTAMPTZ) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.mark_operator_session_step_up(TEXT,BIGINT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.disable_operator_mfa(TEXT) TO onishield_auth;
