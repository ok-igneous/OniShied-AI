# Initial Detection Scenario Catalogue

**Status:** Design specification only; no detection engine is implemented yet.  
**Scope:** Controlled synthetic Linux identity/security telemetry.  
**Safety:** All examples are synthetic. No live systems, credential attacks, or external targets are involved.

## Design rules

1. Detection rules are deterministic and versioned. Identical input and rule versions must produce identical findings.
2. Every finding must cite one or more immutable event IDs and identify the exact rule version.
3. A source-provided severity hint is not a detection result.
4. A rule must define its time window, grouping key, threshold, exclusions, and known blind spots.
5. Missing or malformed fields produce an insufficient-data result, not an invented conclusion.
6. A finding is not proof of compromise. Use labels such as **suspicious activity** until corroborating evidence exists.
7. Rules only create findings. They do not execute response actions.

## Scenario A — Authentication failure burst

**Priority:** P0  
**Event family:** `identity.authentication.failure`  
**Purpose:** Identify repeated failed authentication attempts against one principal.

| Element | Definition |
|---|---|
| Grouping key | tenant + host reference + principal reference + source address |
| Window | 5 minutes |
| Trigger | At least 8 failures in the window |
| Required evidence | Event IDs, count, first/last observed timestamps, principal, host, source address |
| Suggested severity | Medium; raise only with corroborating signals |
| Confidence | High that the threshold was met; not proof of malicious intent |

**Benign cases to test:** mistyped password, stale service credential, scheduled job with expired credentials, user reconnecting after a password change.

**Limitations:** Distributed attempts across many source addresses may evade this simple grouping rule. Shared NAT can combine multiple legitimate users.

## Scenario B — Authentication failure followed by success

**Priority:** P1  
**Event families:** `identity.authentication.failure`, `identity.authentication.success`  
**Purpose:** Highlight a successful login shortly after repeated failures for the same principal.

| Element | Definition |
|---|---|
| Grouping key | tenant + host reference + principal reference |
| Window | 10 minutes |
| Trigger | At least 5 failures followed by a success |
| Required evidence | Ordered event IDs, timestamps, failure count, successful source address |
| Suggested severity | Medium; context-dependent |
| Confidence | High that the event sequence occurred; compromise remains unconfirmed |

**Benign cases to test:** a user repeatedly mistypes a password and then succeeds; password manager autofill correction; legitimate remote access recovery.

**Limitations:** The sequence alone cannot distinguish a user correcting an error from an attacker succeeding.

## Scenario C — Privileged group membership change

**Priority:** P1  
**Event family:** `identity.privilege.membership_changed`  
**Purpose:** Surface a principal being added to a privileged group.

| Element | Definition |
|---|---|
| Grouping key | tenant + host reference + affected principal |
| Window | Single event |
| Trigger | A normalized event explicitly reports addition to a configured privileged group |
| Required evidence | Event ID, actor, affected principal, group, operation, timestamp |
| Suggested severity | High when actor/context is not on an approved change list |
| Confidence | High that the reported change occurred if source integrity is established |

**Benign cases to test:** approved administrator onboarding, change-window activity, automated configuration management.

**Limitations:** Requires reliable source audit events and a tenant-maintained privileged-group catalogue. Do not infer privilege from group names supplied in untrusted free text.

## Scenario D — New privileged login outside approved window

**Priority:** P2; defer until policy data exists  
**Event family:** `identity.authentication.success`  
**Purpose:** Flag a privileged account login outside its tenant-configured maintenance window.

**Required prerequisites:** verified privileged-account inventory, tenant timezone, approved maintenance windows, and trustworthy event timestamps.

**Trigger:** Successful login for a configured privileged principal outside all approved windows.

**Required evidence:** event ID, principal, host, timestamp, timezone, applicable policy version, and reason no approved window matched.

**Limitations:** Time-of-day is weak evidence by itself. Do not implement this rule until timezone, shift, emergency-change, and service-account exceptions are explicitly modelled.

## Finding contract

Every rule result should eventually conform to a versioned structure containing:

- `finding_id`
- `tenant_id`
- `rule_id` and `rule_version`
- `status` (open, suppressed, resolved)
- `title` and concise explanation
- `severity` and separate `confidence`
- `first_seen_at` and `last_seen_at`
- `evidence_event_ids[]`
- `grouping_key_hash` (avoid exposing raw sensitive identifiers in logs)
- `matched_conditions[]`
- `known_limitations[]`

Do not store a model-generated narrative as the source of truth for a deterministic match.

## Validation matrix

| Test | Expected result |
|---|---|
| Threshold is one below configured value | No finding |
| Threshold is met exactly | Finding created |
| Same events replayed | No duplicate finding for same rule version and grouping window |
| Events arrive out of order | Deterministic result after allowed lateness policy |
| Required field missing | Insufficient data; no finding |
| Events belong to different tenants | Never aggregate together |
| Benign threshold crossing | Finding may occur, but must be labelled suspicious, not confirmed compromise |
| Rule version changes | Result records the exact version used |

## Implementation gate

Do not implement or enable these rules against customer telemetry until event ingestion, tenant isolation, idempotency, and database tests pass. First implement and test against the synthetic fixture set only.
