# ADR-001: Hybrid Deployment and Trust Boundaries

- **Status:** Proposed; validate through prototype.
- **Date:** 2026-11-11

## Context

OniShield AI targets business and organizational security workflows across desktop and mobile. A purely cloud-hosted design may not have safe or reliable access to local telemetry and response interfaces. A fully local design complicates centralized management, updates, and multi-organization operations.

## Decision

Prototype a hybrid model:
- cloud services handle organization identity, policy distribution, coordination, and centralized reporting;
- customer-controlled connectors handle authorized local telemetry access and narrowly scoped response;
- desktop is the primary operational console for the first demonstrator;
- mobile initially supports notifications, review, and approval rather than privileged endpoint control.

AI analysis is separated from enforcement. A policy service independently authorizes every action.

## Consequences

Positive:
- Local data access can remain near the customer environment.
- Central management and reporting remain possible.
- The response executor can be isolated behind a narrow local boundary.

Trade-offs:
- Connector lifecycle, updates, identity, and offline behavior add complexity.
- Hybrid deployments require careful network and tenant-boundary design.
- Mobile response capabilities must remain limited until their security model is proven.

## Revisit when

The first telemetry source, customer deployment constraints, data residency needs, and lab prototype are known.
