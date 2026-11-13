# OniShield Repository Capability Audit

**Audit date:** 2026-11-13  
**Repository:** `ok-igneous/OniShied-AI`  
**Branch inspected:** `main`  
**Scope:** Repository tree, TypeScript source, SQL migrations/tests, product contracts, package manifest and latest GitHub Actions run.  
**Audit type:** Static repository audit. No code was executed in a local or hosted development environment during this audit.

## Executive finding

OniShield is not an empty repository and it is not yet a functioning autonomous cybersecurity product. It has a meaningful backend foundation: security-event ingestion, tenant-aware PostgreSQL patterns, threat-indicator matching and review controls, and a substantial operator authentication lifecycle.

The product's most important advertised differentiators—production endpoint monitoring, deterministic threat detection, AI investigations, response execution, configurable Autopilot, and backup/restore—are not implemented as end-to-end working capabilities. Several have detailed technical contracts, which is useful design work, but a contract is not an implementation.

**Current maturity:** backend foundation / controlled demonstrator preparation.  
**Production readiness:** not established.  
**Autonomous response:** not implemented.  
**Verified CI:** no.

## 1. Status definitions

| Status | Meaning |
|---|---|
| Implemented in code — unverified | Relevant source, migrations or tests exist, but this audit has not established successful runtime/CI verification. |
| Partial | Some underlying components exist, but the complete end-to-end capability or required user experience is missing. |
| Design only | Requirements/contracts exist; working implementation is not present. |
| Missing | No implementation was found in the inspected repository tree. |
| Not assessed | The available repository evidence was insufficient to make a reliable determination. |

A checked-in test file does not prove that the test passes. A migration file does not prove that the migration has been applied successfully. A design document does not prove that the feature exists.

## 2. Capability matrix

| Capability | Audit status | Repository evidence and gap |
|---|---|---|
| TypeScript/Fastify backend | **Implemented in code — unverified** | `package.json`, `src/server.ts`, `src/config.ts`; build/typecheck have not been observed passing. |
| PostgreSQL connection and tenant transaction helpers | **Implemented in code — unverified** | `src/database.ts`, role/bootstrap SQL, migrations and RLS smoke tests exist. Actual database execution remains unverified. |
| Canonical security-event validation | **Implemented in code — unverified** | `src/security-event.ts` defines a strict Zod schema with source and provenance fields. |
| Authenticated event ingestion | **Implemented in code — unverified** | `src/server.ts` contains the lab connector ingestion path; migrations 001–002 and event digest code/tests are present. A complete deployed connector pipeline is not established. |
| Event digest and duplicate handling | **Implemented in code — unverified** | `src/security-event-digest.ts`, `src/security-event-digest.test.ts`, migration 002. |
| Tenant isolation and database roles | **Implemented in code — unverified** | RLS migrations, bootstrap/grant SQL, tenant-scoped transaction helper and smoke tests exist. No successful CI/database run has been established. |
| Operator identity and session authentication | **Implemented in code — unverified** | Operator auth, crypto, authorization, session lifecycle and related tests/migrations exist. |
| TOTP MFA and recovery codes | **Implemented in code — unverified** | MFA crypto/TOTP modules, auth service, migrations 010–011 and tests exist. Not independently runtime-verified. |
| Login throttling and session revocation | **Implemented in code — unverified** | Auth service, migrations 006–008 and 12,900? No: the repository documents configured throttling; smoke tests exist. Actual behavior remains unverified. |
| Invitation, email verification and password reset backend | **Partial** | `src/operator-account-lifecycle.ts`, `src/email-delivery.ts`, account routes and migration 012 exist. Frontend token pages, live Resend configuration/delivery, remote client lifecycle and deployment hardening remain outstanding. |
| Operator web/desktop/mobile interface | **Missing** | Inspected tree contains backend TypeScript, SQL, docs and scripts; no frontend application or mobile client was found. |
| Threat-indicator normalization and exact matching | **Implemented in code — unverified** | `src/threat-intelligence.ts` and unit tests support explicit field mappings and bounded exact matching. |
| Threat-intelligence persistence and match service | **Implemented in code — unverified** | `src/threat-intelligence-service.ts`, migrations 003–004 and database tests exist. It is an internal callable service, not an end-to-end alert pipeline. |
| Indicator review and audit controls | **Implemented in code — unverified** | Reviewer controls, status transition audit, authz paths and smoke tests exist. |
| TLP disclosure enforcement | **Partial** | A fail-closed policy evaluator and tests exist, but authenticated read/report/export endpoints and recipient membership enforcement are not wired to it. |
| Automatic threat-feed ingestion / TAXII-STIX | **Missing** | Contracts explicitly defer automatic feeds and external feed integrations. |
| Cross-tenant/global threat intelligence network | **Missing** | Current design is tenant-scoped; global sharing and customer-contributed intelligence are deferred. |
| Deterministic detection engine and findings pipeline | **Design only** | `docs/DETECTION_SCENARIOS.md` specifies scenarios and tests, but no detection engine/finding implementation was found in `src/`. |
| AI investigation service | **Design only** | `docs/INVESTIGATION_ENGINE_CONTRACT.md` defines a read-only contract; no model provider/AI service implementation or AI SDK dependency was found in the inspected manifest/source tree. |
| Evidence-linked security advisor | **Design only / missing UI** | Desired output is described in product docs; no implemented advisor service or user interface was found. |
| Response action registry and executor | **Design only** | Contracts define narrow typed actions, authorization and audit; no response executor or endpoint action adapter was found. |
| Production Windows/Linux endpoint agent | **Missing** | No endpoint collector/agent project was found in the inspected tree. The event schema allows agent-originated events but that is not an endpoint agent. |
| Configurable Autopilot policy storage/service/UI | **Design only** | `docs/AUTOPILOT_CONTRACT.md` is detailed; no policy schema, policy API, configuration UI, simulator or executor exists in the inspected tree. |
| Backup scheduler, vault and restore tooling | **Design only** | `docs/BACKUP_AND_RECOVERY.md` specifies architecture and recovery gates; no backup/restore implementation or provider integration was found. |
| AI-agent inventory and runtime monitoring | **Missing / planned** | Product strategy identifies it as a later expansion; no agent inventory or monitoring implementation was found. |
| Security reporting and customer dashboards | **Missing / partial audit foundation** | Database audit records exist for selected identity/review workflows; no complete reporting API or dashboard was found. |
| CI workflow | **Configured; currently blocked before execution** | `.github/workflows/ci.yml` defines PostgreSQL, migrations/smoke tests, unit tests, typecheck, build and source-line checks. Latest run is described below. |

## 3. Important code-level observations

### 3.1 The strongest existing foundation

The repository's strongest implemented work is the control-plane/security foundation:

- Strict event schema and authenticated lab ingestion.
- Tenant-scoped PostgreSQL transaction and RLS patterns.
- Separate database roles and runtime privilege restrictions.
- Operator password/session lifecycle, MFA, recovery codes and authorization.
- Threat-indicator normalization, exact matching, tenant-scoped persistence and review audit.
- Unit tests and PostgreSQL smoke-test scripts for several of these paths.

These are meaningful building blocks. They are not equivalent to a deployed endpoint protection product or a SOC platform.

### 3.2 Threat intelligence is not detection

The matcher compares explicitly mapped event fields with active indicators. It does not establish malicious behavior by itself. The service is not wired into ingestion or a finding pipeline, and an indicator match must not authorize a response.

### 3.3 Authentication is not a finished operator product

The backend has substantial identity and MFA code. However, the current implementation status document records that operator routes are loopback-only and that frontend token pages, remote browser/mobile token transport, TLS/origin controls, device labels, secure client storage and production deployment review remain outstanding. Do not expose the current operator routes publicly as a finished service.

### 3.4 Autopilot is not implemented

The Autopilot contract is strong design documentation: default OFF, tenant opt-in, risk tiers, approval boundaries, fail-closed behavior, emergency pause and immutable execution intent. The repository does not yet contain the policy persistence, simulator, action registry or executor needed to make this feature work.

### 3.5 Backup documentation is not a recovery capability

The backup contract correctly requires isolated credentials, immutable/off-boundary copies, integrity verification, clean-room restore and measured RPO/RTO. No backup scheduler, vault integration, restore workflow or successful restore drill is present in the inspected tree. Do not accept production customer data on the assumption that recovery exists.

## 4. CI and verification findings

The repository has a CI workflow that intends to run:

1. PostgreSQL service startup.
2. Database role provisioning and migrations.
3. Tenant RLS, threat-intelligence, reviewer, operator identity, authentication security and email lifecycle smoke tests.
4. Source-file size enforcement.
5. Unit tests.
6. TypeScript type-check.
7. Build.

The latest run observed during this audit:

- Workflow run: [#339](https://github.com/ok-igneous/OniShied-AI/actions/runs/43473225542)
- Commit: `12a297a2ea9bb97673abbe93867285668622f67c`
- Conclusion: **failure**
- Job runner ID: `0`
- Job steps: none
- Duration: approximately two seconds

This run failed before runner allocation and executed no test, migration, type-check or build steps. It is consistent with the billing restriction previously reported by the project owner. It is not evidence of a code test failure, but it also provides no passing evidence.

**Required action:** resolve the GitHub account's Actions billing/spending restriction, then rerun CI. Do not mark the code verified until a runner executes all required steps and the run passes.

## 5. Recommended priority order

The following order minimizes the risk of building autonomy on top of an unverified foundation.

### P0 — Restore verification first

- [ ] Resolve GitHub Actions account billing/spending restriction.
- [ ] Rerun the existing CI workflow.
- [ ] Fix every actual migration, SQL smoke-test, unit-test, type-check and build failure.
- [ ] Record the successful run URL and exact commit in implementation status.

**Do not add more complex product behavior while the current foundation cannot be continuously verified.**

### P1 — Complete a narrow detection demonstrator

- [ ] Verify authenticated event ingestion end-to-end against PostgreSQL.
- [ ] Implement the first two deterministic scenarios from `DETECTION_SCENARIOS.md`: authentication failure burst and failure-followed-by-success.
- [ ] Add versioned finding storage, evidence event IDs, severity/confidence separation and idempotency.
- [ ] Test threshold boundaries, out-of-order events, duplicate replay, missing fields, cross-tenant isolation and benign cases.
- [ ] Wire threat-indicator matches into finding enrichment without treating matches as proof or response authorization.

### P2 — Read-only investigation

- [ ] Implement server-authorized evidence retrieval for a finding.
- [ ] Build the structured investigation output in `INVESTIGATION_ENGINE_CONTRACT.md`.
- [ ] Keep model tools read-only and tenant-scoped.
- [ ] Validate every evidence reference against the exact retrieved evidence set.
- [ ] Add prompt-injection, fabricated evidence, cross-tenant and provider-failure tests.
- [ ] Keep AI unable to approve or execute actions.

### P3 — Policy simulation before execution

- [ ] Implement tenant-scoped Autopilot policy storage, default OFF.
- [ ] Implement server-owned typed action registry and deterministic risk calculation.
- [ ] Build observe/dry-run simulation and policy decision audit.
- [ ] Add approval queues and emergency pause.
- [ ] Test stale policy, duplicate requests, concurrency, rate limits, blast radius and fail-closed behavior.
- [ ] Do not enable real response execution until detection, investigation, policy and audit are independently verified.

### P4 — Recovery before production claims

- [ ] Select the actual PostgreSQL hosting/backup strategy.
- [ ] Configure an isolated backup destination and separate credentials.
- [ ] Implement encrypted backups/PITR and integrity manifests.
- [ ] Build clean-room restore and tenant-isolation verification.
- [ ] Run restore drills and measure RPO/RTO.
- [ ] Document recovery of keys and credential rotation.

### P5 — Endpoint and AI-agent expansion

- [ ] Choose one operating system and one telemetry source for the first endpoint collector.
- [ ] Implement signed enrollment, least-privilege collection and agent health.
- [ ] Add device inventory and controlled updates.
- [ ] Later, add AI-agent inventory, permission mapping and activity monitoring through a specific supported integration.
- [ ] Validate demand with a small number of pilot customers before expanding integrations.

## 6. Explicit product claims allowed today

Based on the inspected repository, accurate wording is:

> OniShield is an early-stage cybersecurity platform foundation. Its repository includes backend code for security-event ingestion, tenant-aware database controls, operator authentication/MFA and threat-intelligence matching/review. These components remain subject to successful CI and runtime verification. Endpoint protection, deterministic detection, AI investigation, automated response, configurable Autopilot and backup/restore are still under development or at the design stage.

Do not claim that OniShield currently:
- Protects Windows/Linux endpoints in production.
- Detects or stops ransomware end-to-end.
- Has a working AI security analyst.
- Autonomously blocks threats.
- Automatically backs up and restores customer systems.
- Guarantees recovery or a particular RPO/RTO.
- Is production-ready or provides complete cybersecurity protection.

## 7. Audit limitations

This was a static inspection of the public repository tree, selected source files, migrations, tests, documentation, package manifest and latest Actions run. It did not include:

- Running the application or test suite.
- Applying migrations to a live PostgreSQL instance.
- Penetration testing or independent code review.
- Testing a deployed service, frontend or endpoint agent.
- Verifying live Resend delivery or production credentials.
- Inspecting infrastructure outside this repository.

Statuses marked implemented are therefore **implemented in repository code, unverified**, not independently certified.

---

**Audit conclusion:** Preserve the existing backend foundation. The next engineering milestone should be a passing CI run followed by a narrow, deterministic detection demonstrator. Do not prioritize AI-agent governance or autonomous response ahead of verified event ingestion, detection, investigation and recovery foundations.
