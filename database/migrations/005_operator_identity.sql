-- Operator identity schema and narrowly scoped authentication functions.
-- Auth functions are granted only to the separate onishield_auth login role.
CREATE TABLE onishield.operators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended','disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (email = lower(btrim(email)) AND length(email) BETWEEN 3 AND 254)
);
CREATE UNIQUE INDEX operators_email_unique_idx ON onishield.operators(email);
CREATE TABLE onishield.operator_memberships (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, tenant_id TEXT NOT NULL,
 operator_id UUID NOT NULL REFERENCES onishield.operators(id),
 role TEXT NOT NULL CHECK (role IN ('owner','admin','security_analyst','reviewer','viewer')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended','revoked')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(tenant_id,operator_id),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,id,operator_id)
);
CREATE TABLE onishield.operator_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id TEXT NOT NULL,
 operator_id UUID NOT NULL, membership_id BIGINT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), revoked_at TIMESTAMPTZ,
 FOREIGN KEY(tenant_id,membership_id,operator_id) REFERENCES onishield.operator_memberships(tenant_id,id,operator_id),
 CHECK(expires_at > created_at)
);
CREATE INDEX operator_memberships_operator_idx ON onishield.operator_memberships(operator_id,status);
CREATE INDEX operator_sessions_tenant_operator_idx ON onishield.operator_sessions(tenant_id,operator_id,expires_at);
ALTER TABLE onishield.operator_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.operator_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_memberships_tenant_scope ON onishield.operator_memberships USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY operator_memberships_owner_all ON onishield.operator_memberships TO onishield_owner USING(true) WITH CHECK(true);
ALTER TABLE onishield.operator_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.operator_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_sessions_tenant_scope ON onishield.operator_sessions USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY operator_sessions_owner_all ON onishield.operator_sessions TO onishield_owner USING(true) WITH CHECK(true);
GRANT USAGE ON SCHEMA onishield TO onishield_app;
GRANT SELECT ON onishield.operator_memberships TO onishield_app;
GRANT SELECT,INSERT,UPDATE ON onishield.operator_sessions TO onishield_app;
GRANT USAGE,SELECT ON SEQUENCE onishield.operator_memberships_id_seq TO onishield_app;
REVOKE ALL ON onishield.operators FROM onishield_app;
REVOKE INSERT,UPDATE,DELETE ON onishield.operator_memberships FROM onishield_app;
REVOKE DELETE ON onishield.operator_sessions FROM onishield_app;
CREATE FUNCTION onishield.lookup_operator_credentials(p_email TEXT)
RETURNS TABLE(operator_id UUID,password_hash TEXT,operator_status TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
 SELECT id,operators.password_hash,status FROM onishield.operators WHERE email=lower(btrim(p_email)) LIMIT 1
$$;
CREATE FUNCTION onishield.create_operator_session(p_token_hash TEXT,p_tenant_id TEXT,p_operator_id UUID,p_membership_id BIGINT,p_expires_at TIMESTAMPTZ)
RETURNS TABLE(session_id UUID,expires_at TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
BEGIN
 IF p_token_hash !~ '^[a-f0-9]{64}$' OR p_expires_at<=NOW() OR p_expires_at>NOW()+INTERVAL '8 hours' THEN RAISE EXCEPTION 'Invalid session parameters'; END IF;
 IF NOT EXISTS(SELECT 1 FROM onishield.operators o JOIN onishield.operator_memberships m ON m.operator_id=o.id WHERE o.id=p_operator_id AND o.status='active' AND m.id=p_membership_id AND m.tenant_id=p_tenant_id AND m.status='active') THEN RAISE EXCEPTION 'Operator or tenant membership is not active'; END IF;
 RETURN QUERY INSERT INTO onishield.operator_sessions(token_hash,tenant_id,operator_id,membership_id,expires_at) VALUES(p_token_hash,p_tenant_id,p_operator_id,p_membership_id,p_expires_at) RETURNING id,operator_sessions.expires_at;
END; $$;
CREATE FUNCTION onishield.resolve_operator_session(p_token_hash TEXT)
RETURNS TABLE(tenant_id TEXT,operator_id UUID,membership_id BIGINT,operator_email TEXT,display_name TEXT,role TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
BEGIN
 RETURN QUERY SELECT s.tenant_id,s.operator_id,s.membership_id,o.email,o.display_name,m.role FROM onishield.operator_sessions s JOIN onishield.operators o ON o.id=s.operator_id JOIN onishield.operator_memberships m ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id WHERE s.token_hash=p_token_hash AND s.revoked_at IS NULL AND s.expires_at>NOW() AND o.status='active' AND m.status='active';
 UPDATE onishield.operator_sessions SET last_seen_at=NOW() WHERE token_hash=p_token_hash AND revoked_at IS NULL AND expires_at>NOW();
END; $$;
CREATE FUNCTION onishield.revoke_operator_session(p_token_hash TEXT) RETURNS BOOLEAN
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
 UPDATE onishield.operator_sessions SET revoked_at=COALESCE(revoked_at,NOW()) WHERE token_hash=p_token_hash AND revoked_at IS NULL RETURNING TRUE
$$;
REVOKE ALL ON FUNCTION onishield.lookup_operator_credentials(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.create_operator_session(TEXT,TEXT,UUID,BIGINT,TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.resolve_operator_session(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.revoke_operator_session(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.lookup_operator_credentials(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.create_operator_session(TEXT,TEXT,UUID,BIGINT,TIMESTAMPTZ) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.resolve_operator_session(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.revoke_operator_session(TEXT) TO onishield_auth;

CREATE FUNCTION onishield.lookup_operator_membership(p_operator_id UUID,p_tenant_id TEXT)
RETURNS TABLE(membership_id BIGINT,role TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
 SELECT m.id,m.role FROM onishield.operator_memberships m
 JOIN onishield.operators o ON o.id=m.operator_id
 WHERE m.operator_id=p_operator_id AND m.tenant_id=p_tenant_id
 AND m.status='active' AND o.status='active' LIMIT 1
$$;
REVOKE ALL ON FUNCTION onishield.lookup_operator_membership(UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.lookup_operator_membership(UUID,TEXT) TO onishield_auth;
