# ADR-0002: Database-Enforced Tenant and Business-Unit Isolation

**Status:** Proposed — mandatory security decision, pending approval
**Date:** 2026-11-25

## Context
CEPHAS CRM serves multiple organisations, subsidiaries and business units. Application-only filtering is insufficient because a missed predicate can expose another tenant's records.

## Decision
Use PostgreSQL ENABLE and FORCE ROW LEVEL SECURITY for protected tenant/BU data tables; protected authority metadata is separately restricted. Single-BU scope is mandatory initially; no implicit wildcard or tenant-wide access. Every tenant-scoped record must carry tenant and, where applicable, business-unit ownership. The server derives and validates context from authenticated, authorised claims and database membership; a client-supplied tenant identifier is never authority.

Establish authenticated, database-verified transaction-bound context before protected queries and prevent leakage across pooled connections. A mutable session setting is an untrusted carrier, not authority. Require proof against arbitrary SQL under the ordinary runtime role within the defined tenant/BU isolation scope (Gate 0.1.8). Policies fail closed when context is absent, malformed or unauthorised. Apply the same isolation to API requests, jobs, exports, reporting, search, integrations and administrative workflows.

The normal runtime database role must not own protected tables and must not have BYPASSRLS. Schema-owner/migration credentials must be separate and unavailable to application runtime.

## Alternatives
- Application-level filters only: rejected.
- Separate database per tenant: may be offered for selected deployments but does not replace safe shared-deployment boundaries.
- Schema per tenant: not the universal default due to migration and operations overhead.

## Consequences
- RLS policies, indexes and tenant-aware foreign keys are foundational.
- Workers establish and validate tenant context explicitly.
- Cross-tenant support access requires a separate, time-limited, audited privileged workflow.
- Security tests cover direct SQL/API, object-ID substitution, exports, jobs and reporting.

## Acceptance checks
- Missing context cannot read or write tenant data.
- Runtime role cannot bypass RLS or own protected tables.
- Adversarial cross-tenant and cross-BU tests pass.
- Connection-pool tests prove context is transaction-scoped and reset.
