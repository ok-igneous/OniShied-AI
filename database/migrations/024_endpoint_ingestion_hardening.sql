BEGIN;

-- Defense in depth: the database enforces the event-kind contract even when
-- callers invoke the SECURITY DEFINER ingestion function without HTTP/Zod.
CREATE FUNCTION onishield.endpoint_telemetry_event_is_valid(p_event JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
SET search_path=pg_catalog,onishield AS $$
DECLARE kind TEXT; payload JSONB;
BEGIN
  IF jsonb_typeof(p_event) IS DISTINCT FROM 'object'
     OR jsonb_object_length(p_event) <> 10
     OR NOT (p_event ?& ARRAY['agent_id','event_id','sequence','boot_id',
       'observed_at','collected_at','agent_version','platform','kind','data'])
     OR jsonb_typeof(p_event->'agent_id') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_event->'event_id') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_event->'boot_id') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_event->'sequence') IS DISTINCT FROM 'number'
     OR (p_event->>'sequence') !~ '^[1-9][0-9]*$'
     OR (p_event->>'sequence')::NUMERIC > 9007199254740991
     OR jsonb_typeof(p_event->'observed_at') IS DISTINCT FROM 'string'
     OR (p_event->>'observed_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$'
     OR jsonb_typeof(p_event->'collected_at') IS DISTINCT FROM 'string'
     OR (p_event->>'collected_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$'
     OR jsonb_typeof(p_event->'agent_version') IS DISTINCT FROM 'string'
     OR length(p_event->>'agent_version') NOT BETWEEN 1 AND 64
     OR p_event->>'platform' NOT IN ('windows','linux')
     OR jsonb_typeof(p_event->'kind') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_event->'data') IS DISTINCT FROM 'object' THEN
    RETURN FALSE;
  END IF;
  kind := p_event->>'kind';
  payload := p_event->'data';

  IF kind='heartbeat' THEN
    RETURN jsonb_object_length(payload)=4
      AND payload ?& ARRAY['os_version','hostname','capabilities','clock_skew_ms']
      AND jsonb_typeof(payload->'os_version')='string'
      AND length(payload->>'os_version') BETWEEN 1 AND 128
      AND jsonb_typeof(payload->'hostname')='string'
      AND length(payload->>'hostname') BETWEEN 1 AND 255
      AND jsonb_typeof(payload->'capabilities')='array'
      AND jsonb_array_length(payload->'capabilities')<=5
      AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(payload->'capabilities') AS capability(value)
        WHERE capability.value #>> '{}' NOT IN
          ('process_start','authentication','network_connection','file_integrity','service_change')
      )
      AND jsonb_typeof(payload->'clock_skew_ms')='number'
      AND (payload->>'clock_skew_ms') ~ '^-?[0-9]+$'
      AND (payload->>'clock_skew_ms')::NUMERIC BETWEEN -86400000 AND 86400000;
  ELSIF kind='process_start' THEN
    RETURN jsonb_object_length(payload) BETWEEN 3 AND 5
      AND payload ?& ARRAY['process_id','image_path_ref','signer_status']
      AND (payload - ARRAY['process_id','parent_process_id','image_path_ref','image_sha256','signer_status'])='{}'::JSONB
      AND jsonb_typeof(payload->'process_id')='number'
      AND (payload->>'process_id') ~ '^[1-9][0-9]*$'
      AND (payload->>'process_id')::NUMERIC<=4294967295
      AND (NOT (payload ? 'parent_process_id') OR
        (jsonb_typeof(payload->'parent_process_id')='number' AND
         (payload->>'parent_process_id') ~ '^[1-9][0-9]*$' AND
         (payload->>'parent_process_id')::NUMERIC<=4294967295))
      AND payload->>'image_path_ref' ~ '^[a-f0-9]{64}$'
      AND (NOT (payload ? 'image_sha256') OR payload->>'image_sha256' ~ '^[a-f0-9]{64}$')
      AND payload->>'signer_status' IN ('valid','invalid','unsigned','unknown');
  ELSIF kind='authentication' THEN
    RETURN jsonb_object_length(payload) BETWEEN 3 AND 4
      AND payload ?& ARRAY['result','mechanism','principal_ref']
      AND (payload - ARRAY['result','mechanism','principal_ref','source_address'])='{}'::JSONB
      AND payload->>'result' IN ('success','failure')
      AND payload->>'mechanism' IN ('interactive','remote','service','privilege','unknown')
      AND payload->>'principal_ref' ~ '^[a-f0-9]{64}$'
      AND (NOT (payload ? 'source_address') OR
        (jsonb_typeof(payload->'source_address')='string' AND
         pg_input_is_valid(payload->>'source_address','inet')));
  ELSIF kind='network_connection' THEN
    RETURN jsonb_object_length(payload) BETWEEN 5 AND 6
      AND payload ?& ARRAY['protocol','direction','local_port','remote_port','remote_address']
      AND (payload - ARRAY['protocol','direction','local_port','remote_port','remote_address','process_id'])='{}'::JSONB
      AND payload->>'protocol' IN ('tcp','udp')
      AND payload->>'direction' IN ('outbound','inbound')
      AND jsonb_typeof(payload->'local_port')='number'
      AND (payload->>'local_port') ~ '^[0-9]+$'
      AND (payload->>'local_port')::INTEGER BETWEEN 1 AND 65535
      AND jsonb_typeof(payload->'remote_port')='number'
      AND (payload->>'remote_port') ~ '^[0-9]+$'
      AND (payload->>'remote_port')::INTEGER BETWEEN 1 AND 65535
      AND pg_input_is_valid(payload->>'remote_address','inet')
      AND (NOT (payload ? 'process_id') OR
        (jsonb_typeof(payload->'process_id')='number' AND
         (payload->>'process_id') ~ '^[1-9][0-9]*$' AND
         (payload->>'process_id')::NUMERIC<=4294967295));
  ELSIF kind='file_integrity' THEN
    RETURN jsonb_object_length(payload) BETWEEN 3 AND 5
      AND payload ?& ARRAY['action','path_ref','monitored_scope']
      AND (payload - ARRAY['action','path_ref','previous_sha256','current_sha256','monitored_scope'])='{}'::JSONB
      AND payload->>'action' IN ('created','modified','deleted')
      AND payload->>'path_ref' ~ '^[a-f0-9]{64}$'
      AND payload->>'monitored_scope' IN ('system','startup','application_config')
      AND (NOT (payload ? 'previous_sha256') OR payload->>'previous_sha256' ~ '^[a-f0-9]{64}$')
      AND (NOT (payload ? 'current_sha256') OR payload->>'current_sha256' ~ '^[a-f0-9]{64}$')
      AND NOT (payload->>'action'='deleted' AND payload ? 'current_sha256');
  ELSIF kind='service_change' THEN
    RETURN jsonb_object_length(payload) BETWEEN 2 AND 3
      AND payload ?& ARRAY['action','service_ref']
      AND (payload - ARRAY['action','service_ref','binary_sha256'])='{}'::JSONB
      AND payload->>'action' IN ('installed','started','stopped','removed','configuration_changed')
      AND payload->>'service_ref' ~ '^[a-f0-9]{64}$'
      AND (NOT (payload ? 'binary_sha256') OR payload->>'binary_sha256' ~ '^[a-f0-9]{64}$');
  END IF;
  RETURN FALSE;
EXCEPTION WHEN OTHERS THEN
  RETURN FALSE;
END; $$;

ALTER TABLE onishield.endpoint_telemetry_events
  ADD CONSTRAINT endpoint_telemetry_event_schema_check
  CHECK (onishield.endpoint_telemetry_event_is_valid(event_json) IS TRUE);

-- Durable per-agent event-attempt budget. Failed transactions do not consume
-- quota; successful and duplicate insert attempts count at the DB boundary.
CREATE TABLE onishield.endpoint_telemetry_rate_limits (
  tenant_id TEXT NOT NULL,
  agent_id UUID NOT NULL,
  minute_bucket TIMESTAMPTZ NOT NULL,
  event_attempts INTEGER NOT NULL CHECK (event_attempts BETWEEN 1 AND 1000),
  PRIMARY KEY (tenant_id,agent_id,minute_bucket),
  FOREIGN KEY (tenant_id,agent_id)
    REFERENCES onishield.endpoint_agents(tenant_id,id)
);
ALTER TABLE onishield.endpoint_telemetry_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.endpoint_telemetry_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY endpoint_telemetry_rate_limits_tenant_scope
  ON onishield.endpoint_telemetry_rate_limits
  USING (tenant_id=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY endpoint_telemetry_rate_limits_owner_all
  ON onishield.endpoint_telemetry_rate_limits TO onishield_owner
  USING (true) WITH CHECK (true);
REVOKE ALL ON onishield.endpoint_telemetry_rate_limits FROM PUBLIC,onishield_app,onishield_auth;

CREATE FUNCTION onishield.enforce_endpoint_telemetry_rate_limit()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,onishield AS $$
DECLARE bucket TIMESTAMPTZ := date_trunc('minute',clock_timestamp());
DECLARE current_count INTEGER;
BEGIN
  INSERT INTO onishield.endpoint_telemetry_rate_limits(
    tenant_id,agent_id,minute_bucket,event_attempts
  ) VALUES (NEW.tenant_id,NEW.agent_id,bucket,1)
  ON CONFLICT (tenant_id,agent_id,minute_bucket) DO UPDATE
    SET event_attempts=onishield.endpoint_telemetry_rate_limits.event_attempts+1
    WHERE onishield.endpoint_telemetry_rate_limits.event_attempts<1000
  RETURNING event_attempts INTO current_count;
  IF current_count IS NULL THEN
    RAISE EXCEPTION 'Endpoint telemetry rate limit exceeded';
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER endpoint_telemetry_rate_limit_before_insert
  BEFORE INSERT ON onishield.endpoint_telemetry_events
  FOR EACH ROW EXECUTE FUNCTION onishield.enforce_endpoint_telemetry_rate_limit();

REVOKE ALL ON FUNCTION onishield.endpoint_telemetry_event_is_valid(JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION onishield.enforce_endpoint_telemetry_rate_limit() FROM PUBLIC;

-- The public telemetry route uses a dedicated login role. It can invoke only
-- this narrow SECURITY DEFINER function and cannot read/write application tables.
GRANT USAGE ON SCHEMA onishield TO onishield_ingest;
REVOKE ALL ON ALL TABLES IN SCHEMA onishield FROM onishield_ingest;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA onishield FROM onishield_ingest;
REVOKE ALL ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB)
  FROM PUBLIC,onishield_auth;
GRANT EXECUTE ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB)
  TO onishield_ingest;

COMMIT;
