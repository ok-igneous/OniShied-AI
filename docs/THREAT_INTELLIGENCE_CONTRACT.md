# Threat Intelligence Service Contract

**Status:** Design only; no service is implemented.  
**Initial mode:** Curated synthetic indicators only.

## Purpose and boundaries

Store and evaluate provenance-backed threat context that may help explain a detection. An indicator match is contextual evidence, not proof of compromise and never an authorization to respond.

Initial scope is synthetic indicators and manually curated records. Automatic public-feed ingestion, commercial feeds, TAXII/STIX integrations, cross-tenant sharing, and automatic blocking are deferred. Before any feed is connected, review licensing, redistribution rights, privacy, rate limits, expiry, and deletion terms.

## Indicator record

Every record must include:
- indicator_id: OniShield-generated opaque identifier
- tenant_id: server-enforced tenant; global curated records use a separately authorized namespace
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

## Normalization and matching

- Exact matching only in version one.
- Use vetted parsers for IP addresses and URLs.
- Normalize domains using documented IDNA rules, lowercase DNS names, remove one terminal dot, and reject invalid labels.
- Normalize SHA-256 hashes to lowercase hex with exact length.
- Strip URL credentials; never fetch, resolve, visit, or probe an indicator during ingestion or matching.
- Reject unsupported types, malformed values, control characters, oversized payloads, and arbitrary regular expressions.
- Match only explicitly mapped event fields.
- Pending, expired, revoked, and rejected records never match.
- Record indicator version, event ID, matched field path, matcher version, and match time.
- Deduplicate by indicator version + event ID + field path.

## Tenant and handling boundaries

Tenant-provided intelligence is private to that tenant by default. Never promote tenant intelligence to global scope automatically. Global records require separate write permissions and review. Enforce tenant isolation in every query and RLS policy. TLP is a handling restriction, not an authorization substitute.

## Internal service operations

- submitIndicator(input, actor): validate and create pending record.
- reviewIndicator(id, decision, reviewer): activate or reject with audit.
- revokeIndicator(id, reason, actor): revoke immediately.
- expireIndicators(now): expire stale records and audit transitions.
- matchEvent(eventRef, tenantContext): return authorized evidence-linked matches.
- getIndicator(id, tenantContext): return authorized view.

No public write API is needed for the first lab milestone. All operations must be authorized and audited. AI tools cannot create, edit, activate, or revoke intelligence.

## Match result

A match includes match_id, tenant_id, event_id, indicator_id and version, type, matched_field_path, source_id, source_confidence, validity_state, TLP, matcher_version, and matched_at.

## Abuse controls and tests

Treat source descriptions, URLs, notes, and feed payloads as hostile text. Escape them on display. Bound parsing time, payload size, record count, and refresh frequency. Never let model output change intelligence status.

Acceptance tests:
1. Invalid indicator formats are rejected; normalization is deterministic.
2. Expired, revoked, pending, and rejected records never match.
3. Same-tenant matching works; cross-tenant reads and matches are denied.
4. TLP restrictions apply to reads and exports.
5. Replayed events do not duplicate match records.
6. Prompt-injection text in feed content cannot change policy or tool permissions.
7. Indicator matches cannot trigger response actions.
8. Activation requires provenance, source review, and license reference.
9. Expiry and revocation are auditable.

Use only reserved documentation IPs, .test domains, and fabricated synthetic hashes in lab fixtures. Do not import live malicious infrastructure or customer indicators in the initial milestone.
