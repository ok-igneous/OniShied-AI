-- Credential-authenticated endpoint telemetry with per-device replay protection.
CREATE TABLE onishield.endpoint_telemetry_events (
  tenant_id TEXT NOT NULL,
  agent_id UUID NOT NULL,
  boot_id UUID NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  event_id UUID NOT NULL,
  event_kind TEXT NOT NULL CHECK (event_kind IN (
    'heartbeat','process_start','authentication','network_connection','file_integrity','service_change'
  )),
  observed_at TIMESTAMPTZ NOT NULL,
  collected_at TIMESTAMPTZ NOT NULL,
  event_json JSONB NOT NULL CHECK (jsonb_typeof(event_json)='object'),
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id,agent_id,boot_id,sequence),
  UNIQUE (tenant_id,agent_id,event_id),
  FOREIGN KEY (tenant_id,agent_id)
    REFERENCES onishield.endpoint_agents(tenant_id,id)
);
CREATE INDEX endpoint_telemetry_recent_idx
  ON onishield.endpoint_telemetry_events(tenant_id,agent_id,observed_at DESC);
ALTER TABLE onishield.endpoint_telemetry_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.endpoint_telemetry_events FORCE ROW LEVEL SECURITY;
CREATE POLICY endpoint_telemetry_tenant_scope ON onishield.endpoint_telemetry_events
  USING (tenant_id=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY endpoint_telemetry_owner_all ON onishield.endpoint_telemetry_events
  TO onishield_owner USING (true) WITH CHECK (true);
REVOKE ALL ON onishield.endpoint_telemetry_events FROM PUBLIC,onishield_app,onishield_auth;

CREATE FUNCTION onishield.ingest_endpoint_telemetry(
  p_credential_hash TEXT,p_events JSONB
) RETURNS TABLE(accepted_count INTEGER,duplicate_count INTEGER,agent_id UUID)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE
  trusted RECORD;
  item JSONB;
  inserted_count INTEGER := 0;
  duplicates INTEGER := 0;
  event_agent UUID;
  event_boot UUID;
  event_id_value UUID;
  event_sequence BIGINT;
  existing_event JSONB;
  existing_id UUID;
BEGIN
  IF p_credential_hash !~ '^[a-f0-9]{64}

  SELECT a.id,a.tenant_id,a.platform,a.status
    INTO trusted
    FROM onishield.endpoint_agents a
   WHERE a.credential_hash=p_credential_hash
   FOR UPDATE;
  IF NOT FOUND OR trusted.status <> 'active' THEN
    RAISE EXCEPTION 'Unauthorized endpoint credential';
  END IF;

  FOR item IN SELECT value FROM jsonb_array_elements(p_events) LOOP
    BEGIN
      event_agent := (item->>'agent_id')::UUID;
      event_boot := (item->>'boot_id')::UUID;
      event_id_value := (item->>'event_id')::UUID;
      event_sequence := (item->>'sequence')::BIGINT;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'Invalid endpoint event identity';
    END;
    IF event_agent <> trusted.id OR item->>'platform' <> trusted.platform
       OR event_sequence <= 0
       OR item->>'kind' NOT IN (
         'heartbeat','process_start','authentication','network_connection','file_integrity','service_change'
       )
       OR (item->>'observed_at') IS NULL OR (item->>'collected_at') IS NULL THEN
      RAISE EXCEPTION 'Endpoint event identity or platform mismatch';
    END IF;

    INSERT INTO onishield.endpoint_telemetry_events(
      tenant_id,agent_id,boot_id,sequence,event_id,event_kind,
      observed_at,collected_at,event_json
    ) VALUES (
      trusted.tenant_id,trusted.id,event_boot,event_sequence,event_id_value,item->>'kind',
      (item->>'observed_at')::TIMESTAMPTZ,(item->>'collected_at')::TIMESTAMPTZ,item
    ) ON CONFLICT DO NOTHING;

    IF FOUND THEN
      inserted_count := inserted_count + 1;
    ELSE
      SELECT e.event_json,e.event_id INTO existing_event,existing_id
        FROM onishield.endpoint_telemetry_events e
       WHERE e.tenant_id=trusted.tenant_id AND e.agent_id=trusted.id
         AND e.boot_id=event_boot AND e.sequence=event_sequence;
      IF NOT FOUND OR existing_id <> event_id_value OR existing_event <> item THEN
        RAISE EXCEPTION 'Endpoint sequence replay conflict';
      END IF;
      duplicates := duplicates + 1;
    END IF;
  END LOOP;

  UPDATE onishield.endpoint_agents
     SET last_seen_at=GREATEST(COALESCE(last_seen_at,'-infinity'::TIMESTAMPTZ),NOW())
   WHERE tenant_id=trusted.tenant_id AND id=trusted.id;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  RETURN QUERY SELECT inserted_count,duplicates,trusted.id;
END; $$;
REVOKE ALL ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) TO onishield_auth;

     OR jsonb_typeof(p_events) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'Invalid endpoint telemetry batch';
  END IF;
  IF jsonb_array_length(p_events) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'Invalid endpoint telemetry batch';
  END IF;

  SELECT a.id,a.tenant_id,a.platform,a.status
    INTO trusted
    FROM onishield.endpoint_agents a
   WHERE a.credential_hash=p_credential_hash
   FOR UPDATE;
  IF NOT FOUND OR trusted.status <> 'active' THEN
    RAISE EXCEPTION 'Unauthorized endpoint credential';
  END IF;

  FOR item IN SELECT value FROM jsonb_array_elements(p_events) LOOP
    BEGIN
      event_agent := (item->>'agent_id')::UUID;
      event_boot := (item->>'boot_id')::UUID;
      event_id_value := (item->>'event_id')::UUID;
      event_sequence := (item->>'sequence')::BIGINT;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'Invalid endpoint event identity';
    END;
    IF event_agent <> trusted.id OR item->>'platform' <> trusted.platform
       OR event_sequence <= 0
       OR item->>'kind' NOT IN (
         'heartbeat','process_start','authentication','network_connection','file_integrity','service_change'
       )
       OR (item->>'observed_at') IS NULL OR (item->>'collected_at') IS NULL THEN
      RAISE EXCEPTION 'Endpoint event identity or platform mismatch';
    END IF;

    INSERT INTO onishield.endpoint_telemetry_events(
      tenant_id,agent_id,boot_id,sequence,event_id,event_kind,
      observed_at,collected_at,event_json
    ) VALUES (
      trusted.tenant_id,trusted.id,event_boot,event_sequence,event_id_value,item->>'kind',
      (item->>'observed_at')::TIMESTAMPTZ,(item->>'collected_at')::TIMESTAMPTZ,item
    ) ON CONFLICT DO NOTHING;

    IF FOUND THEN
      inserted_count := inserted_count + 1;
    ELSE
      SELECT e.event_json,e.event_id INTO existing_event,existing_id
        FROM onishield.endpoint_telemetry_events e
       WHERE e.tenant_id=trusted.tenant_id AND e.agent_id=trusted.id
         AND e.boot_id=event_boot AND e.sequence=event_sequence;
      IF NOT FOUND OR existing_id <> event_id_value OR existing_event <> item THEN
        RAISE EXCEPTION 'Endpoint sequence replay conflict';
      END IF;
      duplicates := duplicates + 1;
    END IF;
  END LOOP;

  UPDATE onishield.endpoint_agents
     SET last_seen_at=GREATEST(COALESCE(last_seen_at,'-infinity'::TIMESTAMPTZ),NOW())
   WHERE tenant_id=trusted.tenant_id AND id=trusted.id;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  RETURN QUERY SELECT inserted_count,duplicates,trusted.id;
END; $$;
REVOKE ALL ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) TO onishield_auth;
