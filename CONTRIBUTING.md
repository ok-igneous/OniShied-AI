# Contributing to OniShield AI

OniShield AI is an early-stage security product. Contributions must prioritize correctness, safety, privacy, and reproducibility over feature count.

## Before contributing

- Read the product vision and security model in `docs/`.
- Open or locate an issue before starting substantial work.
- Confirm the target environment is owned by the project or explicitly authorized for testing.
- Never use real customer data in development unless an approved data-handling plan exists.

## Development workflow

1. Discuss scope and acceptance criteria in an issue.
2. Create a focused branch from the agreed base.
3. Keep changes small and cohesive.
4. Add tests for behavior and failure cases.
5. Run formatting, linting, type checks, and relevant tests.
6. Open a pull request with purpose, implementation notes, test evidence, risks, and rollback considerations.
7. Obtain review before merging security-sensitive changes.

## Security-sensitive changes

Changes involving authentication, authorization, telemetry collection, detection logic, AI tool permissions, response execution, secrets, cryptography, tenant isolation, or audit logs require review by a contributor with relevant security expertise. Never merge a response action without a documented policy, preconditions, failure behavior, and test coverage.

## Pull request requirements

A pull request should state:
- What problem it solves.
- What changed and why.
- How it was tested.
- What permissions or data it touches.
- Whether it changes threat assumptions or response behavior.
- Known limitations and rollback steps.

Do not include credentials, tokens, private keys, customer identifiers, or unredacted sensitive logs.

## Commit and branch conventions

Use descriptive branches such as `feat/event-ingestion`, `fix/audit-ordering`, and `docs/threat-model`. Use concise commit messages with a scope where useful, for example `feat: add normalized security event schema`.

## Code quality

Prefer explicit types, narrow interfaces, defensive parsing, deterministic enforcement, structured logs, and clear error handling. Avoid hidden side effects and broad privileges. Do not add dependencies without explaining why they are needed.

## Contributor conduct

Be respectful, factual, and willing to challenge assumptions. Security claims must be supported by evidence. Report uncertainty rather than overstating confidence.


## Mandatory modularity and database standards

- Follow `docs/CODE_STANDARDS.md`: every source-code file has a hard maximum of 500 lines; aim smaller and split by responsibility before reaching the limit.
- Follow `docs/DATABASE_SECURITY.md` for database roles, tenant isolation, query safety, encryption, backups, and production launch gates.
- Include tests for tenant isolation and denied access paths when changing data access.
- Do not introduce a migration or database privilege change without documenting its operational and rollback implications.
