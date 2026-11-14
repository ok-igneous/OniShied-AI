# Threat Intelligence Service Contract

**Status:** Tenant-scoped schema and deterministic matching code committed; database execution and CI remain unverified.  
**Initial mode:** Curated synthetic indicators only.

## Purpose and boundaries

Store and evaluate provenance-backed threat context that may help explain a detection. An indicator match is contextual evidence, not proof of compromise and never an authorization to respond.

Initial scope is synthetic indicators and manually curated records. Automatic public-feed ingestion, commercial feeds, TAXII/STIX integrations, cross-tenant sharing, global intelligence, and automatic blocking are deferred. Before any feed is connected, review licensing, redistribution rights, privacy, rate limits, expiry, and deletion terms.

## Database model (migration 003)

- `threat_intelligence_sources`: tenant-owned source identity, source kind, and mandatory license reference.
- `threat_indicators`: tenant-owned immutable-version records with normalized value, source provenance, validity, confidence rubric, assessor, status, TLP, and optional content digest.
- `threat_indicator_matches`: tenant-owned event references and evidence paths, pinned to an exact indicator version and matcher version. Migration 014 adds `connector_id`, a composite foreign key to the canonical `(tenant_id, connector_id, event_id)` event identity, and connector-scoped replay uniqueness.
- `detection_finding_threat_matches`: links a finding to the exact threat match and event it cites. Migration 015 enforces tenant, finding, connector and event identity with composite foreign keys and RLS.
- Composite tenant foreign keys prevent an indicator from referencing another tenant's source or a match from referencing another tenant's indicator.
- All four threat-intelligence and finding-association tables use ENABLE and FORCE ROW LEVEL SECURITY with transaction-local `app.tenant_id` policies.
- Runtime grants are SELECT-only on sources and SELECT/INSERT on indicators and matches. The migration runner explicitly revokes the generic runtime INSERT grant on sources.
- Runtime indicator inserts are constrained by RLS to `pending` status. Runtime cannot activate, revoke, update, or delete records.
- Reviewer-only status transitions and append-only audit controls are specified in [THREAT_INTELLIGENCE_REVIEW.md](./THREAT_INTELLIGENCE_REVIEW.md).
- Global records have no representation in this first schema. Do not implement global visibility by inserting NULL or special tenant IDs.

Migration 014 backfills existing match rows only when each tenant/event ID resolves to exactly one stored event. It aborts on orphaned or ambiguous historical matches instead of guessing a connector. The migrations are committed but have not been executed against PostgreSQL. A separate privileged reviewer workflow and append-only status-transition audit are required before activation/revocation is implemented.

## Implemented deterministic matching

Code:
- `src/threat-intelligence.ts`: canonicalization, strict input validation, explicit event-field mapping, exact matching, validity/status checks, bounded candidate count, and evidence-linked match output.
- `src/threat-intelligence-service.ts`: loads one stored event by tenant + connector + event ID and active indicators inside a tenant-scoped database transaction, then inserts connector-scoped match records with database-enforced idempotency.
- `src/threat-intelligence.test.ts`: unit tests for the pure normalization and matching functions.

Supported indicator types:
- IPv4 and IPv6 addresses.
- IDNA-normalized domain names.
- HTTP/HTTPS URLs with embedded credentials stripped.
- SHA-256 hex digests.
- Conservative ASCII email addresses with IDNA-normalized domains.

Only these explicit event data fields are examined: `source_ip`, `source_address`, `destination_ip`, `domain`, `url`, `file_hash_sha256`, and `email_address`. `source_address` is mapped to IPv4/IPv6 indicators so the authentication detection scenarios can be enriched when their source value is a bare IP address. The matcher does not recursively inspect arbitrary event data. Matching is exact; no DNS lookups, URL requests, file access, regex indicators, or external network activity occur.

Only indicators with status `active`, a valid `valid_from`, and no elapsed `expires_at` can match. Pending, expired, revoked, and rejected indicators are ignored. Candidate processing is capped at 10,000 records per event; exceeding the cap fails closed rather than silently returning partial results.

The matching service is called during bounded detection evaluation for the exact events cited by each finding. Matches are persisted and attached to findings in the same tenant transaction. The authenticated `/v1/findings` response includes match metadata, but not raw indicator values. This is contextual evidence only; it does not change detection severity or authorize an action. The matcher also remains callable for a single stored event. `src/threat-intelligence-access.ts` now provides a fail-closed disclosure-policy evaluator for TLP:CLEAR, GREEN, AMBER, and RED, with tests for tenant boundaries and recipient scope. This is a policy primitive only: it does not authenticate callers, and no read/report/export endpoint is wired to it. Do not expose matches until authenticated identity, tenant authorization, recipient/community/organization membership, and persisted handling metadata are connected and tested.

## Indicator record

Every record must include:
- indicator_id: OniShield-generated opaque identifier
- tenant_id: server-enforced tenant; the first schema is tenant-only
- type: ipv4, ipv6, domain, url, file_hash_sha256, or email_address
- value_normalized: canonical value
- source_id and source_record_ref
- first_seen_at where known and server-side collected_at
- valid_from and expires_at
- confidence: 0–100 with rubric version and assessor
- status: pending, active, expired, revoked, rejected
- tlp: clear, green, amber, red
- license_ref and optional content_digest

Confidence describes confidence in the indicator's correctness, not probability of compromise. Weak or unverified records remain pending. No score, including 100, can authorize response.

## Tenant and handling boundaries

Tenant-provided intelligence is private to that tenant by default. Never promote tenant intelligence to global scope automatically. Global records require a separately designed namespace, authorization role, review process, and RLS policy. Enforce tenant isolation in every query and RLS policy. TLP is a handling restriction, not an authorization substitute; reads and exports must enforce it in the service layer and be tested.

## Deferred internal operations

- submitIndicator(input, actor): validate and create pending record.
- reviewIndicator(id, decision, reviewer): activate or reject with append-only audit.
- revokeIndicator(id, reason, actor): revoke immediately with audit.
- expireIndicators(now): expire stale records and audit transitions.
- getIndicator(id, tenantContext): return an authorized view.

No public write API is needed for the first lab milestone. All operations must be authorized and audited. AI tools cannot create, edit, activate, or revoke intelligence.

## Abuse controls and remaining acceptance tests

Treat source descriptions, URLs, notes, and feed payloads as hostile text. Escape them on display. Bound parsing time, payload size, record count, and refresh frequency. Never let model output change intelligence status.

Still required:
1. Execute migrations 003–015 and PostgreSQL RLS/integration smoke tests in CI and a disposable lab.
2. Verify same-tenant matching and cross-tenant denial with live PostgreSQL.
3. Test database match idempotency on replay, including two connectors that reuse the same event ID.
4. Implement reviewer authorization and append-only status audit before activation/revocation.
5. Connect the TLP evaluator to authenticated read/report/export paths only after recipient scope and membership are backed by trusted server-side identity and persisted data; test every path.
6. Add property/fuzz tests for URL, IDNA, IP, and email edge cases.
7. Ensure indicator matches cannot trigger response actions.

Use only reserved documentation IPs, .test domains, and fabricated synthetic hashes in lab fixtures. Do not import live malicious infrastructure or customer indicators in the initial milestone.
