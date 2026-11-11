# ADR-002: Initial Backend Stack

- **Status:** Accepted for the first controlled demonstrator.
- **Date:** 2026-11-11

## Context

The first milestone needs a small, testable ingestion service with strict input validation, explicit authentication, tenant scoping, and durable event storage. The team needs to move from planning to a reproducible implementation without prematurely building a distributed platform.

## Decision

Use:
- TypeScript on a supported Node.js LTS runtime.
- Fastify for the HTTP API.
- Zod for runtime validation at trust boundaries.
- PostgreSQL for durable event storage and idempotency.
- SQL migrations checked into the repository.
- Linux as the first local lab environment, with synthetic events only.

Use a modular monolith for the first vertical slice. Do not introduce microservices, message brokers, Kubernetes, or an AI provider dependency until measured requirements justify them.

## Initial security constraints

- The lab connector uses a dedicated bearer token supplied through local environment configuration.
- Effective tenant scope is configured server-side and must match the event's declared tenant.
- The configured connector identity must match the event source identity.
- The database enforces event idempotency with a unique constraint.
- The ingestion API does not invoke AI models or response actions.
- Response execution remains disabled.

## Consequences

This stack is quick to run locally and supports strict TypeScript contracts. It is not yet a production deployment architecture. Before onboarding real customers, add managed secret rotation, per-connector credentials, rate limiting, durable audit controls, observability, backup/recovery, and a reviewed deployment model.

## Revisit when

A second connector, multiple tenants, higher ingestion throughput, or customer deployment constraints require changes.
