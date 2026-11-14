-- Make threat-intelligence match identity consistent with canonical event identity.
-- Historical matches are backfilled only when their tenant/event ID maps to exactly
-- one stored event. Ambiguous or orphaned records abort this migration; guessing a
-- connector would risk attaching evidence to the wrong source.
BEGIN;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM onishield.threat_indicator_matches AS m
    WHERE (
      SELECT COUNT(*)
      FROM onishield.security_events AS e
      WHERE e.tenant_id = m.tenant_id
        AND e.event_id = m.event_id
    ) <> 1
  ) THEN
    RAISE EXCEPTION
      'Cannot backfill threat match connector_id: one or more matches have zero or multiple candidate security events';
  END IF;
END;
$$;

ALTER TABLE onishield.threat_indicator_matches
  ADD COLUMN connector_id TEXT;

UPDATE onishield.threat_indicator_matches AS m
SET connector_id = e.connector_id
FROM onishield.security_events AS e
WHERE e.tenant_id = m.tenant_id
  AND e.event_id = m.event_id;

ALTER TABLE onishield.threat_indicator_matches
  ALTER COLUMN connector_id SET NOT NULL;

-- Drop the original unnamed UNIQUE constraint by its exact column set.
DO $$
DECLARE
  old_constraint_name TEXT;
BEGIN
  SELECT c.conname
  INTO old_constraint_name
  FROM pg_constraint AS c
  WHERE c.conrelid = 'onishield.threat_indicator_matches'::regclass
    AND c.contype = 'u'
    AND (
      SELECT array_agg(a.attname::TEXT ORDER BY a.attname::TEXT)
      FROM unnest(c.conkey) AS key(attnum)
      JOIN pg_attribute AS a
        ON a.attrelid = c.conrelid AND a.attnum = key.attnum
    ) = ARRAY[
      'event_id',
      'indicator_id',
      'indicator_version',
      'matched_field_path',
      'matcher_version',
      'tenant_id'
    ]::TEXT[]
  LIMIT 1;

  IF old_constraint_name IS NULL THEN
    RAISE EXCEPTION 'Original threat match uniqueness constraint was not found';
  END IF;

  EXECUTE format(
    'ALTER TABLE onishield.threat_indicator_matches DROP CONSTRAINT %I',
    old_constraint_name
  );
END;
$$;

ALTER TABLE onishield.threat_indicator_matches
  ADD CONSTRAINT threat_matches_event_same_tenant_connector
  FOREIGN KEY (tenant_id, connector_id, event_id)
  REFERENCES onishield.security_events (tenant_id, connector_id, event_id);

ALTER TABLE onishield.threat_indicator_matches
  ADD CONSTRAINT threat_matches_connector_scoped_unique
  UNIQUE (
    tenant_id,
    connector_id,
    event_id,
    indicator_id,
    indicator_version,
    matched_field_path,
    matcher_version
  );

DROP INDEX IF EXISTS onishield.threat_indicator_matches_event_idx;
CREATE INDEX threat_indicator_matches_event_idx
  ON onishield.threat_indicator_matches
    (tenant_id, connector_id, event_id, matched_at DESC);

COMMIT;
