# Code Structure and Engineering Standards

**Status:** Mandatory project standard  
**Applies to:** All application code, services, workers, connectors, clients, tests, scripts, and future modules.

## 1. File-size limit

- **Hard maximum: 500 lines per source-code file.** No source file may exceed 500 lines.
- Treat 500 as a ceiling, not a target. Prefer roughly 100–300 lines where practical.
- Count comments, imports, blank lines, and code. Do not evade the limit by compressing code or moving large blocks into generated strings.
- When a file approaches 400 lines, plan a split before adding more functionality.
- If a file exceeds 500 lines, split it as part of the same change. Do not defer the split as cleanup.

Documentation, generated artifacts, lockfiles, and data fixtures are not source-code modules, but must still remain navigable and reasonably sized. Generated files must not be hand-edited.

## 2. Modular design

- Each module must have one clear responsibility and a narrow public interface.
- Separate transport/API handlers, domain logic, validation schemas, persistence/repositories, policy enforcement, integrations, and configuration.
- Keep business rules out of route handlers and database adapters.
- Keep SQL migrations separate from application logic.
- Avoid circular dependencies, hidden side effects, giant utility files, and catch-all modules such as `helpers.ts` that accumulate unrelated behavior.
- Prefer composition and dependency injection over global mutable state.
- Keep interfaces explicit; validate all untrusted input at system boundaries.
- Split by responsibility and domain boundary, not merely to achieve a line count.

## 3. Suggested backend layout

Adapt this layout as the system grows; do not create empty folders or abstractions without a real use.

```text
src/
  app.ts                 # application composition
  server.ts              # process startup and shutdown
  config/
    env.ts
  modules/
    events/
      event.routes.ts
      event.schemas.ts
      event.service.ts
      event.repository.ts
      event.types.ts
    identity/
    tenants/
    detection/
    investigation/
    policies/
    responses/
    audit/
  infrastructure/
    database/
    logging/
    secrets/
  shared/
    errors/
    types/
tests/
database/
  migrations/
  seeds/
```

A module should not import another module's private implementation. Communicate through documented interfaces or application services.

## 4. Secure coding requirements

- Use strict TypeScript settings and runtime validation at trust boundaries.
- Use parameterized SQL; never concatenate untrusted input into SQL statements.
- Apply authentication and authorization independently. Authentication does not imply permission.
- Enforce tenant scope on the server for every read, write, job, and object lookup.
- Apply least privilege to application, worker, migration, and operator identities.
- Do not hardcode credentials, tokens, keys, or sensitive configuration in source control.
- Redact secrets and sensitive personal data from logs, errors, fixtures, and test output.
- Set request/body limits, timeouts, rate limits, and safe failure behavior.
- Pin and review dependencies; run automated vulnerability and secret scanning in CI.
- Do not use AI output as an authorization decision or execute model-provided commands directly.
- Security-sensitive changes require tests for both allowed and denied paths.

## 5. Database security requirements

See [DATABASE_SECURITY.md](DATABASE_SECURITY.md). Database security is a design requirement, not a deployment afterthought.

## 6. Tests and review

- Unit-test domain logic and validation independently of HTTP and database layers.
- Add integration tests for persistence, constraints, transactions, and tenant isolation.
- Test malformed input, authorization failures, replay/idempotency, concurrency, and failure recovery.
- Review migrations for locking, data loss, rollback strategy, and compatibility.
- CI must enforce formatting, linting, type checking, tests, build, dependency scanning, and the 500-line source-file ceiling.
- A pull request must explain any new trust boundary, permission, data type, dependency, or database change.

## 7. Exceptions

There are no routine exceptions to the 500-line source-file ceiling. If a generated or vendor-owned source artifact cannot reasonably be split, exclude it explicitly from the source-file check and document why. Never use this exception for ordinary application code.
