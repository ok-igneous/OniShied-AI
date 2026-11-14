# Endpoint Telemetry Contract — Initial Schema

**Status:** Protocol schema, tenant-bound enrollment, device credentials, telemetry ingestion and canonical event persistence are authored on unmerged PR branches. No endpoint agent binary, installer, signed update channel or production deployment is implemented; migrations and tests remain unverified.

## Objective
Define a narrow Windows/Linux endpoint telemetry format before building an agent. The first agent release should collect security-relevant metadata for deterministic detection and investigation, not act as a general employee-monitoring product.

## Event envelope
Every event carries an agent UUID, event UUID, boot UUID, strictly increasing sequence number for that agent boot, observation and collection timestamps, agent version, platform, and a strict kind-specific data object.

Tenant identity is intentionally absent from the client payload. The server must derive tenant scope from the authenticated device credential. A client-supplied tenant ID is never authorization.

## Initial event kinds
| Kind | Allowed data |
|---|---|
| heartbeat | OS version, hostname, declared capabilities, bounded clock skew |
| process_start | PID/parent PID, keyed opaque image-path reference, optional SHA-256, signer state |
| authentication | success/failure, coarse mechanism, keyed opaque principal reference, optional source IP |
| network_connection | TCP/UDP, direction, local/remote ports, remote IP, optional PID |
| file_integrity | create/modify/delete, keyed opaque path reference, optional before/after SHA-256, monitored scope |
| service_change | install/start/stop/remove/configuration change, keyed opaque service reference, optional binary SHA-256 |

The Zod schema rejects unknown fields, limits batches to 100 events, validates event identities and rejects duplicate (agent_id, boot_id, sequence) values within a batch. The ingestion hardening migration adds a database CHECK validator for kind-specific fields so direct function callers cannot bypass the HTTP schema. A database trigger enforces a per-agent ceiling of 1,000 event insert attempts per minute; this is not a substitute for IP/request throttling or edge abuse monitoring.

## Explicit collection exclusions
The initial agent must not collect keystrokes, clipboard contents, screenshots, microphone/camera data, browser history, full URLs, cookies, session tokens, saved credentials, raw command lines, process environment variables, file contents, document/email text, packet payloads, plain usernames/emails, or arbitrary full filesystem scans.

Path, principal and service references must be keyed HMAC references using a device/tenant-scoped secret; an ordinary unsalted hash is not sufficient for guessable values. Raw path strings and usernames must not be sent to the server in this first protocol.

## Identity, ordering and replay requirements for the future service
1. One-time enrollment claims with short expiry, tenant-bound authorization and explicit operator approval.
2. A unique device identity and per-device revocable credential; store only a verifier/digest, never the bearer secret.
3. Credential rotation, revocation, device quarantine and last-seen/agent-version inventory.
4. Server-derived tenant and device scope; no tenant ID accepted as an authorization input.
5. Monotonic sequence checks per (agent_id, boot_id), idempotency on (agent_id, boot_id, sequence) and stable event ID handling.
6. Bounded batch size, request size, event rate, timestamp skew and retention.
7. TLS-only transport, request authentication, replay protection and audit records for enrollment/revocation.
8. Explicit schema-version negotiation and a safe upgrade policy.
9. Local encrypted spool with bounded disk usage, retry/backoff and explicit health reporting on queue overflow.
10. Signed release artifacts, update verification, least-privilege service accounts, tamper-evident logs and a documented uninstall/recovery path.

## Detection and response boundaries
The endpoint agent is a telemetry collector, not an autonomous response executor. It must not kill processes, quarantine files, change firewall rules, disable accounts or alter system configuration in this milestone. Those actions require a separate typed action registry, policy simulation, approval, rollback design and audit trail.

## Implementation status on unmerged branches
- src/endpoint-telemetry.ts: strict discriminated schemas for six event kinds and bounded batches.
- src/endpoint-telemetry.test.ts: schema boundary tests for unknown sensitive fields, pseudonymous identity, duplicate sequence numbers, batch limits and invalid file-deletion metadata.

PR #29 adds the protocol schema; PR #30 adds enrollment and revocation; PR #31 adds authenticated ingestion, canonical event normalization and durable replay enqueue; the endpoint-ingestion-hardening follow-up adds database-side kind validation, per-agent event-rate enforcement and Fastify route tests. All remain unmerged and unverified. Authentication events currently reach existing deterministic rules; other event kinds are stored without dedicated detections. Credential rotation, device inventory, enrollment-claim throttling, IP/request rate limits, tenant-fair replay scheduling, binaries, packaging, deployment and live telemetry validation remain unimplemented.
