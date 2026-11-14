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
- Case detail returns associated findings, exact structured event evidence references, and activity timeline.
- Case priority is initialized from the highest severity among selected findings.
- Duplicate finding association requests are idempotent; unique constraints protect concurrent duplicate writes.
- Viewers can read investigation cases; only owner, admin, and security analyst can create cases, associate findings, or add notes. Mutations require recent step-up.

## Deliberate limitations

- No AI provider integration, generated report, analysis worker, assignment API, case status transition API, dashboard, or automatic correlation yet.
- Initial case creation requires explicit finding IDs and a human reason. No LLM or text similarity is used to merge cases.
- One finding can belong to only one case in this release, including resolved cases; audited case merge/re-parenting is deferred.
- Case priority is a snapshot at creation; it is not dynamically recomputed when finding severity changes.
- Evidence is referenced from canonical finding evidence; event payloads are not copied into investigation records.
- The SQL smoke test is authored but not executed. Migration 019 has not been applied to a live database. Typecheck, build, unit tests, and CI have not been run.
- Concurrent duplicate protection relies on database uniqueness and transaction semantics; a concurrent database stress test remains outstanding.

## Verification gate

Do not merge based on authored tests alone. Before merge, execute the full migration sequence and SQL smoke tests on a disposable PostgreSQL database, then run typecheck, build, test, and source-line checks. Verify that the migration runner executes as onishield_owner, and inspect the resulting grants, function owners, RLS policies, and indexes.
