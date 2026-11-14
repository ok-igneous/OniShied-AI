-- One-time, tenant-bound endpoint enrollment and per-device credential lifecycle.
CREATE TABLE onishield.endpoint_agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  display_name TEXT NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
  platform TEXT NOT NULL CHECK (platform IN ('windows','linux')),
  hostname TEXT NOT NULL CHECK (length(btrim(hostname)) BETWEEN 1 AND 255),
  agent_version TEXT NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 64),
  credential_hash TEXT NOT NULL UNIQUE CHECK (credential_hash ~ '^[a-f0-9]{64}$'),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','quarantined')),
  enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_by_operator_id UUID NOT NULL REFERENCES onishield.operators(id),
  UNIQUE (tenant_id,id)
);
CREATE INDEX endpoint_agents_tenant_recent_idx
  ON onishield.endpoint_agents(tenant_id,enrolled_at DESC);
CREATE TABLE onishield.endpoint_enrollment_tokens (
  token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  tenant_id TEXT NOT NULL,
  display_name TEXT NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
  platform TEXT NOT NULL CHECK (platform IN ('windows','linux')),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_by_membership_id BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (tenant_id,created_by_membership_id)
    REFERENCES onishield.operator_memberships(tenant_id,id),
  CHECK (expires_at > created_at)
);
CREATE INDEX endpoint_enrollment_expiry_idx
  ON onishield.endpoint_enrollment_tokens(expires_at) WHERE consumed_at IS NULL;

ALTER TABLE onishield.endpoint_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.endpoint_agents FORCE ROW LEVEL SECURITY;
CREATE POLICY endpoint_agents_tenant_scope ON onishield.endpoint_agents
  USING (tenant_id=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY endpoint_agents_owner_all ON onishield.endpoint_agents
  TO onishield_owner USING (true) WITH CHECK (true);

ALTER TABLE onishield.endpoint_enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.endpoint_enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY endpoint_enrollment_owner_all ON onishield.endpoint_enrollment_tokens
  TO onishield_owner USING (true) WITH CHECK (true);

REVOKE ALL ON onishield.endpoint_agents, onishield.endpoint_enrollment_tokens
  FROM PUBLIC,onishield_app,onishield_auth;

CREATE FUNCTION onishield.create_endpoint_enrollment_token(
  p_session_hash TEXT,p_token_hash TEXT,p_display_name TEXT,p_platform TEXT
) RETURNS TABLE(expires_at TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD; token_expiry TIMESTAMPTZ;
BEGIN
  IF p_session_hash !~ '^[a-f0-9]{64} !~ '^[a-f0-9]{64}$'
     OR length(btrim(COALESCE(p_display_name,''))) NOT BETWEEN 1 AND 120
     OR p_platform NOT IN ('windows','linux') THEN
    RAISE EXCEPTION 'Invalid endpoint enrollment request';
  END IF;
  SELECT s.tenant_id,s.operator_id,s.membership_id,m.role,s.step_up_at
    INTO trusted
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id=s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
   WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
     AND o.status='active' AND m.status='active'
   FOR UPDATE OF s;
  IF NOT FOUND OR trusted.role NOT IN ('owner','admin') THEN
    RAISE EXCEPTION 'Unauthorized endpoint enrollment';
  END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at < NOW()-INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'Step-up authentication required';
  END IF;
  token_expiry := NOW()+INTERVAL '15 minutes';
  INSERT INTO onishield.endpoint_enrollment_tokens(
    token_hash,tenant_id,display_name,platform,expires_at,created_by_membership_id
  ) VALUES (
    p_token_hash,trusted.tenant_id,btrim(p_display_name),p_platform,token_expiry,trusted.membership_id
  );
  RETURN QUERY SELECT token_expiry;
END; $$;

CREATE FUNCTION onishield.claim_endpoint_enrollment(
  p_enrollment_hash TEXT,p_credential_hash TEXT,p_hostname TEXT,p_agent_version TEXT,p_platform TEXT
) RETURNS TABLE(agent_id UUID,tenant_id TEXT,display_name TEXT,platform TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE enrollment RECORD; created_agent UUID;
BEGIN
  IF p_enrollment_hash !~ '^[a-f0-9]{64}$' OR p_credential_hash !~ '^[a-f0-9]{64}$'
     OR length(btrim(COALESCE(p_hostname,''))) NOT BETWEEN 1 AND 255
     OR length(COALESCE(p_agent_version,'')) NOT BETWEEN 1 AND 64
     OR p_platform NOT IN ('windows','linux') THEN
    RAISE EXCEPTION 'Invalid endpoint enrollment claim';
  END IF;
  SELECT t.tenant_id,t.display_name,t.platform,t.expires_at,t.consumed_at,m.status
    INTO enrollment
    FROM onishield.endpoint_enrollment_tokens t
    JOIN onishield.operator_memberships m
      ON m.tenant_id=t.tenant_id AND m.id=t.created_by_membership_id
    JOIN onishield.operators o ON o.id=m.operator_id AND o.status='active'
   WHERE t.token_hash=p_enrollment_hash
   FOR UPDATE OF t;
  IF NOT FOUND OR enrollment.consumed_at IS NOT NULL OR enrollment.expires_at<=NOW()
     OR enrollment.status <> 'active' OR enrollment.platform <> p_platform THEN
    RAISE EXCEPTION 'Invalid or expired endpoint enrollment token';
  END IF;
  UPDATE onishield.endpoint_enrollment_tokens SET consumed_at=NOW()
   WHERE token_hash=p_enrollment_hash AND consumed_at IS NULL;
  INSERT INTO onishield.endpoint_agents(
    tenant_id,display_name,platform,hostname,agent_version,credential_hash,created_by_operator_id
  ) VALUES (
    enrollment.tenant_id,enrollment.display_name,p_platform,btrim(p_hostname),p_agent_version,
    p_credential_hash,(SELECT operator_id FROM onishield.operator_memberships
      WHERE tenant_id=enrollment.tenant_id AND id=(
        SELECT created_by_membership_id FROM onishield.endpoint_enrollment_tokens
        WHERE token_hash=p_enrollment_hash
      ))
  ) RETURNING id INTO created_agent;
  RETURN QUERY SELECT created_agent,enrollment.tenant_id,enrollment.display_name,enrollment.platform;
END; $$;

CREATE FUNCTION onishield.revoke_endpoint_agent(
  p_session_hash TEXT,p_agent_id UUID,p_reason TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
BEGIN
  IF p_session_hash !~ '^[a-f0-9]{64}$' OR p_agent_id IS NULL
     OR length(btrim(COALESCE(p_reason,''))) NOT BETWEEN 10 AND 500 THEN
    RAISE EXCEPTION 'Invalid endpoint revocation request';
  END IF;
  SELECT s.tenant_id,m.role,s.step_up_at
    INTO trusted
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id=s.operator_id
    JOIN onishield.operator_memberships m ON m.id=s.membership_id
      AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
   WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
     AND o.status='active' AND m.status='active'
   FOR UPDATE OF s;
  IF NOT FOUND OR trusted.role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'Unauthorized endpoint revocation'; END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at < NOW()-INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'Step-up authentication required';
  END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  UPDATE onishield.endpoint_agents SET status='revoked',revoked_at=COALESCE(revoked_at,NOW())
   WHERE tenant_id=trusted.tenant_id AND id=p_agent_id AND status<>'revoked';
  RETURN FOUND;
END; $$;

REVOKE ALL ON FUNCTION onishield.create_endpoint_enrollment_token(TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.claim_endpoint_enrollment(TEXT,TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.revoke_endpoint_agent(TEXT,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.create_endpoint_enrollment_token(TEXT,TEXT,TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.claim_endpoint_enrollment(TEXT,TEXT,TEXT,TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.revoke_endpoint_agent(TEXT,UUID,TEXT) TO onishield_auth;
 OR p_token_hash !~ '^[a-f0-9]{64}$'
     OR length(btrim(COALESCE(p_display_name,''))) NOT BETWEEN 1 AND 120
     OR p_platform NOT IN ('windows','linux') THEN
    RAISE EXCEPTION 'Invalid endpoint enrollment request';
  END IF;
  SELECT s.tenant_id,s.operator_id,s.membership_id,m.role,s.step_up_at
    INTO trusted
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id=s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
   WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
     AND o.status='active' AND m.status='active'
   FOR UPDATE OF s;
  IF NOT FOUND OR trusted.role NOT IN ('owner','admin') THEN
    RAISE EXCEPTION 'Unauthorized endpoint enrollment';
  END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at < NOW()-INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'Step-up authentication required';
  END IF;
  INSERT INTO onishield.endpoint_enrollment_tokens(
    token_hash,tenant_id,display_name,platform,expires_at,created_by_membership_id
  ) VALUES (
    p_token_hash,trusted.tenant_id,btrim(p_display_name),p_platform,NOW()+INTERVAL '15 minutes',trusted.membership_id
  );
  RETURN QUERY SELECT NOW()+INTERVAL '15 minutes';
END; $$;

CREATE FUNCTION onishield.claim_endpoint_enrollment(
  p_enrollment_hash TEXT,p_credential_hash TEXT,p_hostname TEXT,p_agent_version TEXT,p_platform TEXT
) RETURNS TABLE(agent_id UUID,tenant_id TEXT,display_name TEXT,platform TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE enrollment RECORD; created_agent UUID;
BEGIN
  IF p_enrollment_hash !~ '^[a-f0-9]{64}$' OR p_credential_hash !~ '^[a-f0-9]{64}$'
     OR length(btrim(COALESCE(p_hostname,''))) NOT BETWEEN 1 AND 255
     OR length(COALESCE(p_agent_version,'')) NOT BETWEEN 1 AND 64
     OR p_platform NOT IN ('windows','linux') THEN
    RAISE EXCEPTION 'Invalid endpoint enrollment claim';
  END IF;
  SELECT t.tenant_id,t.display_name,t.platform,t.expires_at,t.consumed_at,m.status
    INTO enrollment
    FROM onishield.endpoint_enrollment_tokens t
    JOIN onishield.operator_memberships m
      ON m.tenant_id=t.tenant_id AND m.id=t.created_by_membership_id
   WHERE t.token_hash=p_enrollment_hash
   FOR UPDATE OF t;
  IF NOT FOUND OR enrollment.consumed_at IS NOT NULL OR enrollment.expires_at<=NOW()
     OR enrollment.status <> 'active' OR enrollment.platform <> p_platform THEN
    RAISE EXCEPTION 'Invalid or expired endpoint enrollment token';
  END IF;
  UPDATE onishield.endpoint_enrollment_tokens SET consumed_at=NOW()
   WHERE token_hash=p_enrollment_hash AND consumed_at IS NULL;
  INSERT INTO onishield.endpoint_agents(
    tenant_id,display_name,platform,hostname,agent_version,credential_hash,created_by_operator_id
  ) VALUES (
    enrollment.tenant_id,enrollment.display_name,p_platform,btrim(p_hostname),p_agent_version,
    p_credential_hash,(SELECT operator_id FROM onishield.operator_memberships
      WHERE tenant_id=enrollment.tenant_id AND id=(
        SELECT created_by_membership_id FROM onishield.endpoint_enrollment_tokens
        WHERE token_hash=p_enrollment_hash
      ))
  ) RETURNING id INTO created_agent;
  RETURN QUERY SELECT created_agent,enrollment.tenant_id,enrollment.display_name,enrollment.platform;
END; $$;

CREATE FUNCTION onishield.revoke_endpoint_agent(
  p_session_hash TEXT,p_agent_id UUID,p_reason TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE trusted RECORD;
BEGIN
  IF p_session_hash !~ '^[a-f0-9]{64}$' OR p_agent_id IS NULL
     OR length(btrim(COALESCE(p_reason,''))) NOT BETWEEN 10 AND 500 THEN
    RAISE EXCEPTION 'Invalid endpoint revocation request';
  END IF;
  SELECT s.tenant_id,m.role,s.step_up_at
    INTO trusted
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id=s.operator_id
    JOIN onishield.operator_memberships m ON m.id=s.membership_id
      AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
   WHERE s.token_hash=p_session_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
     AND o.status='active' AND m.status='active'
   FOR UPDATE OF s;
  IF NOT FOUND OR trusted.role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'Unauthorized endpoint revocation'; END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at < NOW()-INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'Step-up authentication required';
  END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  UPDATE onishield.endpoint_agents SET status='revoked',revoked_at=COALESCE(revoked_at,NOW())
   WHERE tenant_id=trusted.tenant_id AND id=p_agent_id AND status<>'revoked';
  RETURN FOUND;
END; $$;

REVOKE ALL ON FUNCTION onishield.create_endpoint_enrollment_token(TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.claim_endpoint_enrollment(TEXT,TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.revoke_endpoint_agent(TEXT,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.create_endpoint_enrollment_token(TEXT,TEXT,TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.claim_endpoint_enrollment(TEXT,TEXT,TEXT,TEXT,TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.revoke_endpoint_agent(TEXT,UUID,TEXT) TO onishield_auth;
