-- Reviewer-only threat indicator transitions with database-enforced audit.
-- The reviewer role is not granted to the runtime application role.

CREATE TABLE onishield.threat_indicator_status_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  indicator_id BIGINT NOT NULL,
  indicator_version INTEGER NOT NULL,
  old_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  actor_db_role TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 1000),
  changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (tenant_id, indicator_id, indicator_version)
    REFERENCES onishield.threat_indicators (tenant_id, id, version),
  CHECK (old_status IN ('pending', 'active')),
  CHECK (new_status IN ('active', 'rejected', 'revoked', 'expired')),
  CHECK (old_status <> new_status)
);

CREATE INDEX threat_indicator_status_audit_lookup_idx
  ON onishield.threat_indicator_status_audit
    (tenant_id, indicator_id, changed_at DESC);

ALTER TABLE onishield.threat_indicator_status_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.threat_indicator_status_audit FORCE ROW LEVEL SECURITY;

CREATE POLICY threat_indicator_audit_tenant_insert
  ON onishield.threat_indicator_status_audit
  FOR INSERT TO onishield_owner
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY threat_indicator_audit_tenant_read
  ON onishield.threat_indicator_status_audit
  FOR SELECT TO onishield_reviewer
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY threat_indicators_reviewer_update
  ON onishield.threat_indicators
  FOR UPDATE TO onishield_reviewer
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT USAGE ON SCHEMA onishield TO onishield_reviewer;
GRANT SELECT ON onishield.threat_indicators TO onishield_reviewer;
GRANT UPDATE (status) ON onishield.threat_indicators TO onishield_reviewer;
GRANT SELECT ON onishield.threat_indicator_status_audit TO onishield_reviewer;

CREATE FUNCTION onishield.audit_threat_indicator_status_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, onishield
AS $$
DECLARE
  transition_reason TEXT;
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
  IF transition_reason IS NULL OR length(btrim(transition_reason)) < 10
     OR length(transition_reason) > 1000 THEN
    RAISE EXCEPTION 'A review reason between 10 and 1000 characters is required';
  END IF;

  INSERT INTO onishield.threat_indicator_status_audit
    (tenant_id, indicator_id, indicator_version, old_status, new_status,
     actor_db_role, reason)
  VALUES
    (OLD.tenant_id, OLD.id, OLD.version, OLD.status, NEW.status,
     session_user::text, btrim(transition_reason));

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION onishield.audit_threat_indicator_status_change() FROM PUBLIC;

CREATE TRIGGER threat_indicator_status_audit_trigger
BEFORE UPDATE OF status ON onishield.threat_indicators
FOR EACH ROW
EXECUTE FUNCTION onishield.audit_threat_indicator_status_change();

-- Audit rows are append-only for all application and reviewer principals.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
  ON onishield.threat_indicator_status_audit FROM onishield_app, onishield_reviewer;
GRANT USAGE, SELECT ON SEQUENCE
  onishield.threat_indicator_status_audit_id_seq TO onishield_owner;
