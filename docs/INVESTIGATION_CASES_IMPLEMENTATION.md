# Investigation Case Foundation — Implementation Status

## Implemented in migration 019 and operator routes

- Tenant-scoped investigation case table with status, priority, creator, optional assignee, and activity timestamps.
- Case-to-finding association table with tenant-aware foreign keys and uniqueness constraints.
- First-release invariant: one finding belongs to one case. A future move/merge workflow must be explicit and audited.
- Append-only investigation activity for case creation, finding association, and operator notes.
- RLS enabled and forced on all three tables, with tenant policies and narrowly scoped owner policies for security-definer functions.
- Direct runtime table privileges revoked. Mutations are exposed through database functions that validate the opaque operator session, active account/membership, role, tenant, and five-minute step-up.
- Operator APIs:
  - GET /v1/operator/investigations
  - POST /v1/operator/investigations
  - GET /v1/operator/investigations/:caseId
  - POST /v1/operator/investigations/:caseId/findings
  - POST /v1/operator/investigations/:caseId/notes
  - POST /v1/operator/investigations/:caseId/analyze
  - GET /v1/operator/investigations/:caseId/analysis-status
  - GET /v1/operator/investigations/:caseId/reports
- Case detail returns associated findings, exact structured event evidence references, and activity timeline.
- Case priority is initialized from the highest severity among selected findings.
- Duplicate finding association requests are idempotent; unique constraints protect concurrent duplicate writes.
- Viewers can read investigation cases; only owner, admin, and security analyst can create cases, associate findings, or add notes. Mutations require recent step-up.

## AI analysis pipeline (migration 020)

- Durable tenant-scoped analysis jobs with lease tokens, expiry recovery, bounded retries, and dead-letter state.
- Analysis requests require an authenticated owner/admin/security_analyst session and a recent five-minute step-up. Requests are deduplicated per active case, limited to one per case every ten minutes, and capped at 30 per tenant per hour.
- The separate worker uses the OpenAI Responses API with strict JSON Schema output. Configure OPENAI_API_KEY and OPENAI_MODEL; neither setting is required for the API server to start.
- The worker receives bounded case/finding metadata, canonical event references and timestamps, and TLP:CLEAR threat-intelligence provenance only. TLP:GREEN, TLP:AMBER, and TLP:RED matches are withheld from the external provider and counted in the report input. Raw event payloads, credentials, and operator notes are not sent.
- Model output is Zod-validated; every evidence citation must exactly match a canonical connector_id/event_id pair and timeline timestamps must match canonical event timestamps.
- Reports are versioned and append-only. A database trigger rejects report UPDATE and DELETE. Report metadata records provider, model, template version, and evidence digest.
- The worker has no tools or response execution path. Recommendations are advisory and every recommendation requires human approval.
- New routes: POST /v1/operator/investigations/:caseId/analyze and GET /v1/operator/investigations/:caseId/reports. Worker command: npm run start:investigation-worker.

## Operator investigation console

- A responsive operator workspace is served at `/operator`.
- Operators paste an existing operator session token; the console does not collect passwords or issue sessions. The token is held in browser session storage for the tab and can be cleared with Disconnect.
- The console lists cases, creates cases from 1–25 explicitly supplied finding IDs and a human reason, opens case evidence and activity, associates additional findings, and adds analyst notes.
- Authorized analysts can request finding-status transitions with a reason. The database enforces role permissions and recent step-up authentication; the UI reports a step-up-required response rather than bypassing that control.
- The console requests AI analysis, checks queue status, and loads immutable report history.
- API calls use same-origin authenticated endpoints and no-store caching. The page sets a restrictive Content Security Policy and does not load third-party scripts, fonts, images, or analytics.
- The console is an operational first slice, not a complete SOC dashboard. It still lacks an in-console password/MFA login flow, finding discovery/search view, case assignment and status workflow, and alert delivery.

## Deliberate limitations

- No full SOC dashboard, assignment API, case status transition API, or automatic finding-to-case correlation yet.
- Initial case creation requires explicit finding IDs and a human reason. No LLM or text similarity is used to merge cases.
- One finding can belong to only one case in this release, including resolved cases; audited case merge/re-parenting is deferred.
- Case priority is a snapshot at creation; it is not dynamically recomputed when finding severity changes.
- Evidence is referenced from canonical finding evidence; event payloads are not copied into investigation records.
- The SQL smoke tests are authored but not executed. Migrations 019 and 020 have not been applied to a live database. Typecheck, build, unit tests, and CI have not been run. The operator console has been authored but not browser-tested.
- Concurrent duplicate protection relies on database uniqueness and transaction semantics; a concurrent database stress test remains outstanding.

## Verification gate

Do not merge based on authored tests alone. Before merge, execute the full migration sequence and SQL smoke tests on a disposable PostgreSQL database, then run typecheck, build, test, and source-line checks. Verify that the migration runner executes as onishield_owner, and inspect the resulting grants, function owners, RLS policies, and indexes.
