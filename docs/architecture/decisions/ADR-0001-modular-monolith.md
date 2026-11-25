# ADR-0001: Modular Monolith as Initial Architecture

**Status:** Proposed — pending approval  
**Date:** 2026-11-25

## Context
CEPHAS CRM is a broad enterprise platform. Early delivery needs clear domain boundaries without premature distributed-system complexity.

## Decision
Adopt a modular monolith initially. Organise the backend into domain modules with explicit interfaces, ownership of domain logic and controlled dependencies. Keep deployment topology simple. Design contracts so services can be extracted later when justified by scale, isolation, availability or team ownership.

## Alternatives
- Microservices from day one: rejected initially due to operational overhead, distributed transactions and deployment complexity.
- Unstructured monolith: rejected because it weakens boundaries and creates coupling.

## Consequences
- One primary backend deployment initially, with modular packages and explicit API/service boundaries.
- No cross-module database writes that bypass the owning module's rules.
- Asynchronous jobs/events require defined reliability and tenant-context designs.
- Service extraction requires a separate ADR and evidence-based justification.

## Acceptance checks
- Module ownership and dependency map exists.
- Cross-module access patterns are documented.
- Architecture tests prevent prohibited dependency cycles.
