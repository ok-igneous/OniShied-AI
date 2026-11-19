-- Tenant-scoped Autopilot policy simulation. No execution adapter is created.
BEGIN;

CREATE TABLE onishield.autopilot_policies (
  tenant_id TEXT PRIMARY KEY,
  policy_version INTEGER NOT NULL CHECK (policy_version >= 1),
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  mode TEXT NOT NULL DEFAULT 'off'
    CHECK (mode IN ('off', 'observe', 'low_risk', 'guarded')),
  max_risk_tier SMALLINT NOT NULL DEFAULT 0 CHECK (max_risk_tier BETWEEN 0 AND 2),
  allowed_actions TEXT[] NOT NULL DEFAULT '{}',
  target_scope TEXT[] NOT NULL DEFAULT '{}',
  rate_limit_per_hour INTEGER NOT NULL DEFAULT 10 CHECK (rate_limit_per_hour BETWEEN 1 AND 1000),
  concurrency_limit INTEGER NOT NULL DEFAULT 1 CHECK (concurrency_limit BETWEEN 1 AND 20),
  expires_at TIMESTAMPTZ,
  emergency_paused BOOLEAN NOT NULL DEFAULT FALSE,
  updated_by UUID NOT NULL REFERENCES onishield.operators(id),
  change_reason TEXT NOT NULL CHECK (length(btrim(change_reason)) BETWEEN 10 AND 1000),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((enabled AND mode <> 'off') OR (NOT enabled AND mode = 'off')),
  CHECK (allowed_actions <@ ARRAY['evidence.collect','alert.label.add','network.block']::TEXT[]),
  CHECK (cardinality(allowed_actions) <= 20),
  CHECK (cardinality(target_scope) <= 500)
);

CREATE TABLE onishield.autopilot_policy_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  actor_operator_id UUID NOT NULL REFERENCES onishield.operators(id),
  action TEXT NOT NULL CHECK (action IN ('created','updated')),
  reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 10 AND 1000),
  policy_snapshot JSONB NOT NULL CHECK (jsonb_typeof(policy_snapshot) = 'object'),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE onishield.autopilot_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.autopilot_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY autopilot_policy_owner_access ON onishield.autopilot_policies
  FOR ALL TO onishield_owner USING (TRUE) WITH CHECK (TRUE);

ALTER TABLE onishield.autopilot_policy_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.autopilot_policy_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY autopilot_audit_owner_insert ON onishield.autopilot_policy_audit
  FOR INSERT TO onishield_owner WITH CHECK (TRUE);
CREATE POLICY autopilot_audit_owner_read ON onishield.autopilot_policy_audit
  FOR SELECT TO onishield_owner USING (TRUE);

REVOKE ALL ON onishield.autopilot_policies, onishield.autopilot_policy_audit
  FROM PUBLIC, onishield_app, onishield_auth, onishield_reviewer;

CREATE FUNCTION onishield.get_autopilot_policy(p_token_hash TEXT)
RETURNS TABLE(
  tenant_id TEXT, policy_version INTEGER, enabled BOOLEAN, mode TEXT,
  max_risk_tier SMALLINT, allowed_actions TEXT[], target_scope TEXT[],
  rate_limit_per_hour INTEGER, concurrency_limit INTEGER, expires_at TIMESTAMPTZ,
  emergency_paused BOOLEAN, updated_at TIMESTAMPTZ
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, onishield AS $$
DECLARE trusted RECORD;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  SELECT s.tenant_id, s.operator_id, m.role INTO trusted
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id = s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id = s.membership_id AND m.tenant_id = s.tenant_id
     AND m.operator_id = s.operator_id
   WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL
     AND s.expires_at > NOW() AND o.status = 'active' AND m.status = 'active';
  IF NOT FOUND THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  IF trusted.role NOT IN ('owner','admin','security_analyst','reviewer','viewer') THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;
  PERFORM set_config('app.tenant_id', trusted.tenant_id, TRUE);
  RETURN QUERY SELECT p.tenant_id,p.policy_version,p.enabled,p.mode,p.max_risk_tier,
    p.allowed_actions,p.target_scope,p.rate_limit_per_hour,p.concurrency_limit,
    p.expires_at,p.emergency_paused,p.updated_at
  FROM onishield.autopilot_policies p WHERE p.tenant_id = trusted.tenant_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT trusted.tenant_id,0,FALSE,'off'::TEXT,0::SMALLINT,
      ARRAY[]::TEXT[],ARRAY[]::TEXT[],10,1,NULL::TIMESTAMPTZ,FALSE,NULL::TIMESTAMPTZ;
  END IF;
END;
$$;

CREATE FUNCTION onishield.save_autopilot_policy(
  p_token_hash TEXT, p_expected_version INTEGER, p_enabled BOOLEAN, p_mode TEXT,
  p_max_risk_tier SMALLINT, p_allowed_actions TEXT[], p_target_scope TEXT[],
  p_rate_limit_per_hour INTEGER, p_concurrency_limit INTEGER,
  p_expires_at TIMESTAMPTZ, p_emergency_paused BOOLEAN, p_change_reason TEXT
) RETURNS TABLE(policy_version INTEGER, updated_at TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, onishield AS $$
DECLARE trusted RECORD; current_version INTEGER; next_version INTEGER;
  audit_action TEXT; snapshot JSONB;
BEGIN
  IF p_token_hash !~ '^[a-f0-9]{64}$' OR p_expected_version < 0
    OR p_mode NOT IN ('off','observe','low_risk','guarded')
    OR p_max_risk_tier NOT BETWEEN 0 AND 2
    OR p_enabled <> (p_mode <> 'off')
    OR p_rate_limit_per_hour NOT BETWEEN 1 AND 1000
    OR p_concurrency_limit NOT BETWEEN 1 AND 20
    OR cardinality(p_allowed_actions) > 20 OR cardinality(p_target_scope) > 500
    OR NOT (p_allowed_actions <@ ARRAY['evidence.collect','alert.label.add','network.block']::TEXT[])
    OR length(btrim(COALESCE(p_change_reason,''))) NOT BETWEEN 10 AND 1000
    OR (p_expires_at IS NOT NULL AND p_expires_at <= NOW()) THEN
    RAISE EXCEPTION 'Invalid Autopilot policy';
  END IF;

  SELECT s.id,s.tenant_id,s.operator_id,m.role,s.step_up_at
    INTO trusted
    FROM onishield.operator_sessions s
    JOIN onishield.operators o ON o.id=s.operator_id
    JOIN onishield.operator_memberships m
      ON m.id=s.membership_id AND m.tenant_id=s.tenant_id AND m.operator_id=s.operator_id
   WHERE s.token_hash=p_token_hash AND s.revoked_at IS NULL AND s.expires_at>NOW()
     AND o.status='active' AND m.status='active'
   FOR UPDATE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'Forbidden'; END IF;
  IF trusted.role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'Forbidden'; END IF;
  IF trusted.step_up_at IS NULL OR trusted.step_up_at < NOW()-INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'Step-up authentication required';
  END IF;

  PERFORM set_config('app.tenant_id',trusted.tenant_id,TRUE);
  PERFORM pg_advisory_xact_lock(hashtextextended(trusted.tenant_id, 0));
  SELECT p.policy_version INTO current_version
    FROM onishield.autopilot_policies p WHERE p.tenant_id=trusted.tenant_id FOR UPDATE;
  IF NOT FOUND THEN current_version := 0; END IF;
  IF current_version <> p_expected_version THEN RAISE EXCEPTION 'Stale Autopilot policy version'; END IF;
  next_version := current_version + 1;
  audit_action := CASE WHEN current_version = 0 THEN 'created' ELSE 'updated' END;

  INSERT INTO onishield.autopilot_policies(
    tenant_id,policy_version,enabled,mode,max_risk_tier,allowed_actions,target_scope,
    rate_limit_per_hour,concurrency_limit,expires_at,emergency_paused,updated_by,
    change_reason,updated_at
  ) VALUES (
    trusted.tenant_id,next_version,p_enabled,p_mode,p_max_risk_tier,p_allowed_actions,
    p_target_scope,p_rate_limit_per_hour,p_concurrency_limit,p_expires_at,
    p_emergency_paused,trusted.operator_id,btrim(p_change_reason),NOW()
  )
  ON CONFLICT (tenant_id) DO UPDATE SET
    policy_version=EXCLUDED.policy_version,enabled=EXCLUDED.enabled,mode=EXCLUDED.mode,
    max_risk_tier=EXCLUDED.max_risk_tier,allowed_actions=EXCLUDED.allowed_actions,
    target_scope=EXCLUDED.target_scope,rate_limit_per_hour=EXCLUDED.rate_limit_per_hour,
    concurrency_limit=EXCLUDED.concurrency_limit,expires_at=EXCLUDED.expires_at,
    emergency_paused=EXCLUDED.emergency_paused,updated_by=EXCLUDED.updated_by,
    change_reason=EXCLUDED.change_reason,updated_at=NOW();

  SELECT to_jsonb(p) INTO snapshot FROM onishield.autopilot_policies p
   WHERE p.tenant_id=trusted.tenant_id;
  INSERT INTO onishield.autopilot_policy_audit(
    tenant_id,policy_version,actor_operator_id,action,reason,policy_snapshot
  ) VALUES (
    trusted.tenant_id,next_version,trusted.operator_id,audit_action,
    btrim(p_change_reason),snapshot
  );
  RETURN QUERY SELECT next_version,NOW();
END;
$$;

REVOKE ALL ON FUNCTION onishield.get_autopilot_policy(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.save_autopilot_policy(TEXT,INTEGER,BOOLEAN,TEXT,SMALLINT,TEXT[],TEXT[],INTEGER,INTEGER,TIMESTAMPTZ,BOOLEAN,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.get_autopilot_policy(TEXT) TO onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.save_autopilot_policy(TEXT,INTEGER,BOOLEAN,TEXT,SMALLINT,TEXT[],TEXT[],INTEGER,INTEGER,TIMESTAMPTZ,BOOLEAN,TEXT) TO onishield_auth;

COMMIT;
