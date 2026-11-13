-- One-use operator invitation, email verification, and password-reset lifecycle.
ALTER TABLE onishield.operators
  ADD COLUMN email_verified_at TIMESTAMPTZ;

CREATE TABLE onishield.operator_email_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action_type TEXT NOT NULL CHECK (action_type IN ('invitation','email_verification','password_reset')),
  email TEXT NOT NULL CHECK (email=lower(btrim(email)) AND length(email) BETWEEN 3 AND 254),
  operator_id UUID REFERENCES onishield.operators(id) ON DELETE CASCADE,
  tenant_id TEXT,
  invited_role TEXT CHECK (invited_role IS NULL OR invited_role IN ('admin','security_analyst','reviewer','viewer')),
  invited_display_name TEXT CHECK (invited_display_name IS NULL OR length(btrim(invited_display_name)) BETWEEN 1 AND 120),
  token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  created_by_operator_id UUID REFERENCES onishield.operators(id),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    (action_type='invitation' AND operator_id IS NULL AND tenant_id IS NOT NULL
      AND invited_role IS NOT NULL AND invited_display_name IS NOT NULL
      AND created_by_operator_id IS NOT NULL)
    OR
    (action_type IN ('email_verification','password_reset') AND operator_id IS NOT NULL
      AND tenant_id IS NULL AND invited_role IS NULL AND invited_display_name IS NULL)
  )
);
CREATE INDEX operator_email_actions_lookup_idx
  ON onishield.operator_email_actions(action_type,email,created_at DESC);
CREATE INDEX operator_email_actions_expiry_idx
  ON onishield.operator_email_actions(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE onishield.operator_account_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  operator_id UUID REFERENCES onishield.operators(id) ON DELETE SET NULL,
  action_type TEXT NOT NULL CHECK (action_type IN (
    'invitation_created','invitation_accepted','email_verified',
    'password_reset_requested','password_reset_completed'
  )),
  tenant_id TEXT,
  actor_operator_id UUID REFERENCES onishield.operators(id),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
REVOKE ALL ON onishield.operator_email_actions,onishield.operator_account_audit
  FROM PUBLIC,onishield_app,onishield_auth;

DROP FUNCTION onishield.lookup_operator_credentials(TEXT);
CREATE FUNCTION onishield.lookup_operator_credentials(p_email TEXT)
RETURNS TABLE(operator_id UUID,password_hash TEXT,operator_status TEXT,email_verified BOOLEAN)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
 SELECT id,operators.password_hash,status,email_verified_at IS NOT NULL
 FROM onishield.operators WHERE email=lower(btrim(p_email)) LIMIT 1
$$;

CREATE FUNCTION onishield.create_operator_invitation(
  p_session_hash TEXT,p_email TEXT,p_display_name TEXT,p_role TEXT,
  p_token_hash TEXT,p_expires_at TIMESTAMPTZ
) RETURNS TABLE(action_id UUID,recipient_email TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE actor RECORD; normalized_email TEXT;
BEGIN
  IF p_session_hash IS NULL OR p_token_hash IS NULL OR p_email IS NULL
    OR p_display_name IS NULL OR p_role IS NULL OR p_expires_at IS NULL THEN
    RAISE EXCEPTION 'Invalid operator invitation';
  END IF;
  normalized_email:=lower(btrim(p_email));
  IF p_session_hash !~ '^[a-f0-9]{64}$' OR p_token_hash !~ '^[a-f0-9]{64}$'
    OR normalized_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    OR length(normalized_email)>254 OR length(btrim(p_display_name)) NOT BETWEEN 1 AND 120
    OR p_role NOT IN ('admin','security_analyst','reviewer','viewer')
    OR p_expires_at<=NOW() OR p_expires_at>NOW()+INTERVAL '48 hours' THEN
    RAISE EXCEPTION 'Invalid operator invitation';
  END IF;
  SELECT s.tenant_id,s.operator_id,m.role INTO actor
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id=s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
   WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
     AND o.status='active' AND m.status='active'
   FOR UPDATE OF s;
  IF NOT FOUND OR actor.role NOT IN ('owner','admin')
    OR (actor.role='admin' AND p_role NOT IN ('security_analyst','reviewer','viewer')) THEN
    RAISE EXCEPTION 'Forbidden operator invitation';
  END IF;
  IF EXISTS(SELECT 1 FROM onishield.operators o JOIN onishield.operator_memberships m
    ON m.operator_id=o.id WHERE o.email=normalized_email AND m.tenant_id=actor.tenant_id
      AND m.status IN ('active','pending')) THEN
    RAISE EXCEPTION 'Operator already belongs to tenant';
  END IF;
  IF EXISTS(SELECT 1 FROM onishield.operators WHERE email=normalized_email) THEN
    RAISE EXCEPTION 'Operator account already exists';
  END IF;
  UPDATE onishield.operator_email_actions SET consumed_at=NOW()
   WHERE action_type='invitation' AND email=normalized_email AND tenant_id=actor.tenant_id
     AND consumed_at IS NULL;
  INSERT INTO onishield.operator_email_actions
    (action_type,email,tenant_id,invited_role,invited_display_name,token_hash,
     created_by_operator_id,expires_at)
  VALUES('invitation',normalized_email,actor.tenant_id,p_role,btrim(p_display_name),
         p_token_hash,actor.operator_id,p_expires_at)
  RETURNING id,email INTO action_id,recipient_email;
  INSERT INTO onishield.operator_account_audit(action_type,tenant_id,actor_operator_id)
    VALUES('invitation_created',actor.tenant_id,actor.operator_id);
  RETURN NEXT;
END;
$$;

CREATE FUNCTION onishield.request_operator_email_verification(
  p_email TEXT,p_token_hash TEXT,p_expires_at TIMESTAMPTZ
) RETURNS TABLE(action_id UUID,recipient_email TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE target RECORD; normalized_email TEXT;
BEGIN
  IF p_email IS NULL OR p_token_hash IS NULL OR p_expires_at IS NULL THEN RETURN; END IF;
  normalized_email:=lower(btrim(p_email));
  IF p_token_hash !~ '^[a-f0-9]{64}$'
    OR normalized_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    OR p_expires_at<=NOW() OR p_expires_at>NOW()+INTERVAL '30 minutes' THEN RETURN; END IF;
  SELECT id,email INTO target FROM onishield.operators
   WHERE email=normalized_email AND status='active' AND email_verified_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE onishield.operator_email_actions SET consumed_at=NOW()
   WHERE operator_id=target.id AND action_type='email_verification' AND consumed_at IS NULL;
  INSERT INTO onishield.operator_email_actions(action_type,email,operator_id,token_hash,expires_at)
    VALUES('email_verification',target.email,target.id,p_token_hash,p_expires_at)
    RETURNING id,email INTO action_id,recipient_email;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION onishield.request_operator_password_reset(
  p_email TEXT,p_token_hash TEXT,p_expires_at TIMESTAMPTZ
) RETURNS TABLE(action_id UUID,recipient_email TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE target RECORD; normalized_email TEXT;
BEGIN
  IF p_email IS NULL OR p_token_hash IS NULL OR p_expires_at IS NULL THEN RETURN; END IF;
  normalized_email:=lower(btrim(p_email));
  IF p_token_hash !~ '^[a-f0-9]{64}$'
    OR normalized_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    OR p_expires_at<=NOW() OR p_expires_at>NOW()+INTERVAL '30 minutes' THEN RETURN; END IF;
  SELECT id,email INTO target FROM onishield.operators
   WHERE email=normalized_email AND status='active' AND email_verified_at IS NOT NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE onishield.operator_email_actions SET consumed_at=NOW()
   WHERE operator_id=target.id AND action_type='password_reset' AND consumed_at IS NULL;
  INSERT INTO onishield.operator_email_actions(action_type,email,operator_id,token_hash,expires_at)
    VALUES('password_reset',target.email,target.id,p_token_hash,p_expires_at)
    RETURNING id,email INTO action_id,recipient_email;
  INSERT INTO onishield.operator_account_audit(operator_id,action_type)
    VALUES(target.id,'password_reset_requested');
  RETURN NEXT;
END;
$$;

CREATE FUNCTION onishield.accept_operator_invitation(p_token_hash TEXT,p_password_hash TEXT)
RETURNS TABLE(tenant_id TEXT,operator_id UUID,membership_id BIGINT,email TEXT,
              display_name TEXT,role TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE invite RECORD; new_operator UUID; new_membership BIGINT;
BEGIN
  IF p_token_hash IS NULL OR p_password_hash IS NULL
    OR p_token_hash !~ '^[a-f0-9]{64}$'
    OR p_password_hash !~ '^scrypt\$16384\$8\$1\$[a-f0-9]{32}\$[a-f0-9]{128}$' THEN
    RAISE EXCEPTION 'Invalid invitation acceptance';
  END IF;
  SELECT * INTO invite FROM onishield.operator_email_actions
   WHERE token_hash=p_token_hash AND action_type='invitation'
     AND consumed_at IS NULL AND expires_at>NOW() FOR UPDATE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM onishield.operators WHERE email=invite.email) THEN
    RAISE EXCEPTION 'Invalid or expired invitation';
  END IF;
  INSERT INTO onishield.operators(email,password_hash,display_name,status,email_verified_at)
    VALUES(invite.email,p_password_hash,invite.invited_display_name,'active',NOW())
    RETURNING id INTO new_operator;
  INSERT INTO onishield.operator_memberships(tenant_id,operator_id,role,status)
    VALUES(invite.tenant_id,new_operator,invite.invited_role,'active')
    RETURNING id INTO new_membership;
  UPDATE onishield.operator_email_actions SET consumed_at=NOW() WHERE id=invite.id;
  INSERT INTO onishield.operator_account_audit(operator_id,action_type,tenant_id,actor_operator_id)
    VALUES(new_operator,'invitation_accepted',invite.tenant_id,invite.created_by_operator_id);
  RETURN QUERY SELECT invite.tenant_id,new_operator,new_membership,invite.email,
                      invite.invited_display_name,invite.invited_role;
END;
$$;

CREATE FUNCTION onishield.consume_operator_email_verification(p_token_hash TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE action RECORD;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$' THEN RETURN FALSE; END IF;
  SELECT * INTO action FROM onishield.operator_email_actions
   WHERE token_hash=p_token_hash AND action_type='email_verification'
     AND consumed_at IS NULL AND expires_at>NOW() FOR UPDATE;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  UPDATE onishield.operators SET email_verified_at=NOW(),updated_at=NOW()
   WHERE id=action.operator_id AND email=action.email AND status='active'
     AND email_verified_at IS NULL;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  UPDATE onishield.operator_email_actions SET consumed_at=NOW() WHERE id=action.id;
  INSERT INTO onishield.operator_account_audit(operator_id,action_type)
    VALUES(action.operator_id,'email_verified');
  RETURN TRUE;
END;
$$;

CREATE FUNCTION onishield.consume_operator_password_reset(p_token_hash TEXT,p_password_hash TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE action RECORD;
BEGIN
  IF p_token_hash IS NULL OR p_password_hash IS NULL
    OR p_token_hash !~ '^[a-f0-9]{64}$'
    OR p_password_hash !~ '^scrypt\$16384\$8\$1\$[a-f0-9]{32}\$[a-f0-9]{128}$' THEN
    RETURN FALSE;
  END IF;
  SELECT * INTO action FROM onishield.operator_email_actions
   WHERE token_hash=p_token_hash AND action_type='password_reset'
     AND consumed_at IS NULL AND expires_at>NOW() FOR UPDATE;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  UPDATE onishield.operators SET password_hash=p_password_hash,updated_at=NOW()
   WHERE id=action.operator_id AND email=action.email AND status='active'
     AND email_verified_at IS NOT NULL;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  UPDATE onishield.operator_email_actions SET consumed_at=NOW() WHERE id=action.id;
  UPDATE onishield.operator_sessions SET revoked_at=NOW()
   WHERE operator_id=action.operator_id AND revoked_at IS NULL;
  INSERT INTO onishield.operator_account_audit(operator_id,action_type)
    VALUES(action.operator_id,'password_reset_completed');
  RETURN TRUE;
END;
$$;

REVOKE ALL ON FUNCTION onishield.create_operator_invitation(TEXT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.request_operator_email_verification(TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.request_operator_password_reset(TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.accept_operator_invitation(TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.consume_operator_email_verification(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.consume_operator_password_reset(TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.create_operator_invitation(TEXT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.request_operator_email_verification(TEXT,TEXT,TIMESTAMPTZ) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.request_operator_password_reset(TEXT,TEXT,TIMESTAMPTZ) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.accept_operator_invitation(TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.consume_operator_email_verification(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.consume_operator_password_reset(TEXT,TEXT) TO onishield_auth;
