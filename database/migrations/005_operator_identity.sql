-- Operator identity foundation. Authentication endpoints remain disabled until
-- session lifecycle and identity-provider integration are implemented and tested.

CREATE TABLE onishield.operators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'suspended', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT operators_email_normalized CHECK (
    email = lower(btrim(email)) AND length(email) BETWEEN 3 AND 254
  )
);

CREATE UNIQUE INDEX operators_email_unique_idx ON onishield.operators (email);

CREATE TABLE onishield.operator_memberships (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  operator_id UUID NOT NULL REFERENCES onishield.operators(id),
  role TEXT NOT NULL CHECK (
    role IN ('owner', 'admin', 'security_analyst', 'reviewer', 'viewer')
  ),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'suspended', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, operator_id),
  UNIQUE (tenant_id, id)
);

CREATE TABLE onishield.operator_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  operator_id UUID NOT NULL,
  membership_id BIGINT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  FOREIGN KEY (tenant_id, membership_id)
    REFERENCES onishield.operator_memberships (tenant_id, id),
  FOREIGN KEY (operator_id) REFERENCES onishield.operators(id),
  CHECK (expires_at > created_at)
);

CREATE INDEX operator_memberships_operator_idx
  ON onishield.operator_memberships (operator_id, status);
CREATE INDEX operator_sessions_tenant_operator_idx
  ON onishield.operator_sessions (tenant_id, operator_id, expires_at);

ALTER TABLE onishield.operator_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.operator_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_memberships_tenant_scope
  ON onishield.operator_memberships
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE onishield.operator_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.operator_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_sessions_tenant_scope
  ON onishield.operator_sessions
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Password hashes and operator records are intentionally not readable by the
-- normal application DB role. No authentication endpoint is enabled by this
-- migration alone. A narrowly scoped authentication service is a later gate.
GRANT USAGE ON SCHEMA onishield TO onishield_app;
GRANT SELECT ON onishield.operator_memberships TO onishield_app;
GRANT SELECT, INSERT, UPDATE ON onishield.operator_sessions TO onishield_app;
GRANT USAGE, SELECT ON SEQUENCE onishield.operator_memberships_id_seq TO onishield_app;

-- Explicitly deny application access to password hashes and operator lifecycle.
REVOKE ALL ON onishield.operators FROM onishield_app;
REVOKE INSERT, UPDATE, DELETE ON onishield.operator_memberships FROM onishield_app;
REVOKE DELETE ON onishield.operator_sessions FROM onishield_app;
