# Canonical Security Event Schema (v0)

**Status:** Initial contract proposal for the first controlled demonstrator.

The schema is source-neutral. Connectors must normalize source-specific records into this contract while preserving source provenance. The schema is intentionally small; extend it through a reviewed versioned change rather than adding arbitrary fields.

## Required fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Contract version, initially `0.1.0` |
| `event_id` | string | Stable unique identifier assigned by the source or connector |
| `tenant_id` | string | Internal tenant scope; never trust this value without server-side authorization |
| `source` | object | Connector identity and product/type |
| `event_type` | string | Namespaced normalized event type |
| `observed_at` | date-time | When the source says the event occurred |
| `ingested_at` | date-time | When OniShield accepted the event |
| `provenance` | object | Source record reference and collection method |
| `data` | object | Normalized event-specific fields |

## Initial JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://onishield.invalid/schemas/security-event-0.1.0.json",
  "title": "OniShield Security Event",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "event_id",
    "tenant_id",
    "source",
    "event_type",
    "observed_at",
    "ingested_at",
    "provenance",
    "data"
  ],
  "properties": {
    "schema_version": { "const": "0.1.0" },
    "event_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "tenant_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "source": {
      "type": "object",
      "additionalProperties": false,
      "required": ["connector_id", "kind"],
      "properties": {
        "connector_id": { "type": "string", "minLength": 1, "maxLength": 128 },
        "kind": { "type": "string", "minLength": 1, "maxLength": 64 },
        "version": { "type": "string", "maxLength": 64 },
        "host_ref": { "type": "string", "maxLength": 128 }
      }
    },
    "event_type": {
      "type": "string",
      "pattern": "^[a-z0-9]+(\\.[a-z0-9_-]+){1,5}$",
      "maxLength": 128
    },
    "observed_at": { "type": "string", "format": "date-time" },
    "ingested_at": { "type": "string", "format": "date-time" },
    "severity_hint": {
      "type": "string",
      "enum": ["unknown", "info", "low", "medium", "high", "critical"]
    },
    "provenance": {
      "type": "object",
      "additionalProperties": false,
      "required": ["record_ref", "collection_method"],
      "properties": {
        "record_ref": { "type": "string", "minLength": 1, "maxLength": 256 },
        "collection_method": {
          "type": "string",
          "enum": ["agent", "api", "syslog", "file_import", "synthetic_replay"]
        },
        "raw_digest": {
          "type": "string",
          "pattern": "^[a-f0-9]{64}$"
        }
      }
    },
    "data": {
      "type": "object",
      "maxProperties": 100
    }
  }
}
```

The `tenant_id` in an incoming payload is a routing hint only. The ingestion service must derive the effective tenant from the authenticated connector identity and reject mismatches. A JSON Schema validator must enforce format assertions for date-time fields.

## Synthetic example

```json
{
  "schema_version": "0.1.0",
  "event_id": "lab-evt-000001",
  "tenant_id": "lab-tenant",
  "source": {
    "connector_id": "lab-connector-01",
    "kind": "synthetic-lab",
    "version": "0.1.0",
    "host_ref": "lab-workstation-01"
  },
  "event_type": "identity.authentication.failure",
  "observed_at": "2026-11-11T12:00:00Z",
  "ingested_at": "2026-11-11T12:00:02Z",
  "severity_hint": "medium",
  "provenance": {
    "record_ref": "scenario-auth-burst-01",
    "collection_method": "synthetic_replay"
  },
  "data": {
    "principal_ref": "user-test-01",
    "failure_count_window": 8,
    "window_seconds": 60,
    "source_address": "192.0.2.25",
    "result": "failure"
  }
}
```

The IP address above is from the documentation-only TEST-NET-1 range. It is not a real target.

## Ingestion invariants

1. Authenticate the connector before accepting the event.
2. Derive tenant scope from the authenticated connector; reject a mismatching payload tenant.
3. Enforce request size, field length, nesting, and rate limits before expensive processing.
4. Preserve the original source reference and a digest of the raw record where feasible.
5. Make duplicate handling explicit and idempotent using connector identity plus event identity.
6. Treat all values in `data` as untrusted input; escape them in dashboards and never interpret them as instructions.
7. Record server-side receipt time; do not trust a client-provided `ingested_at` without replacing or validating it.
8. Do not treat `severity_hint` as a confirmed detection severity.
9. Reject unknown schema versions with a clear, non-sensitive error.
10. Never trigger a response action directly from ingestion.

## Open questions before implementation

- Which first telemetry source and operating system will produce these events?
- Should tenant IDs be UUIDs or opaque internal identifiers?
- Which fields need a formal typed union for the first event families?
- What retention and raw-event storage policy applies to the lab and later customer deployments?
- Which event deduplication window and replay semantics are required?
