# CEPHAS CRM — Reference Architecture

**Status:** Proposed baseline for Gate 0.1 review

## 1. Logical layers
1. Experience: web app, administration and executive workspaces, customer portal and future mobile clients.
2. API edge: authentication/session validation, request validation, rate limiting, API versioning and correlation IDs.
3. Application services: use cases and orchestration; tenant context is derived and verified server-side.
4. Domain modules: customer, sales, marketing, service, communications, workflow, analytics and AI intelligence.
5. Shared platform: identity, tenancy, authorization, licensing, audit, notifications, configuration and integration registry.
6. Data/event infrastructure: PostgreSQL, transactional outbox, background queue, object storage adapter and optional search.
7. Deployment: customer-controlled Docker installation, private cloud, on-premises or hybrid.

## 2. Proposed technology baseline
Frontend Next.js + TypeScript; backend FastAPI + Python; PostgreSQL; SQLAlchemy + Alembic; Redis + Celery only after tenant-context propagation and isolation tests; Pytest and Playwright; Docker; GitHub Actions. Pin versions and support windows in implementation pull requests.

## 3. Modular boundaries
Each module owns its domain rules and schema namespace/tables. Cross-module interaction uses documented application interfaces or versioned events, not arbitrary database writes. Shared services must not bypass module authorization. Module installation and licence entitlements are explicit and validated server-side.

Initial bounded contexts: Identity & Access; Tenancy & Organisation; Customer & Relationship; Sales; Marketing; Service & Case Management; Communications; Workflow; Analytics; AI Intelligence; Licensing & Entitlements; Audit & Governance; Integrations.

## 4. Tenancy and business-unit isolation
- Every tenant-owned record carries a non-null tenant identifier.
- Business-unit-owned records carry a validated business-unit identifier where required.
- Tenant and business-unit membership/hierarchy are enforced by database constraints and policies.
- PostgreSQL ENABLE and FORCE ROW LEVEL SECURITY are mandatory for protected tenant/BU data tables, with explicit policies and inventory. Protected authority metadata uses separate restricted roles and reviewed interfaces; no direct runtime access.
- Application tenant context is established only after authenticating the principal and resolving authorized membership.
- Use authenticated transaction-bound context verified by the database as proposed in Gate 0.1.5 and 0.1.8. Mutable session settings carry untrusted data, not authority. Never trust browser/API tenant IDs without verification; single BU per transaction initially, no null/wildcard.
- Connection pooling must not leak context between transactions; reset context safely.
- Background jobs, exports, analytics, scheduled tasks and integration workers carry server-created verified tenant execution context and re-authorize at execution time.
- Missing, malformed or expired context fails closed.
- Normal runtime roles must not own protected tables or have BYPASSRLS. Require FORCE ROW LEVEL SECURITY on protected tenant/BU data tables. Shared multi-tenancy is disabled unless the same-role arbitrary SQL isolation proof passes; see Gate 0.1.8 for bounded threat scope.
- Test cross-tenant reads, writes, updates, deletes, joins, aggregates, exports and identifier guessing.

## 5. Identity and authorization
Use OIDC/OAuth2-compatible architecture. Separate authentication from authorization. Apply least privilege, deny by default, scoped roles and explicit privileged-action checks. Support MFA and secure recovery. Service accounts require narrow scopes, rotation and audit. Enforce authorization in backend services and database policies where applicable.

## 6. Data and integration
PostgreSQL is the transactional system of record. Use migrations for schema evolution. External integrations use adapters, scoped credentials, allowlisted callback destinations where applicable, signed webhook verification, replay protection, idempotency and bounded retries. Never store provider secrets in source code or tenant-readable tables.

## 7. AI architecture
AI orchestration is a separate bounded context. It receives only data the initiating principal may access. Provider adapters are configurable per deployment. Prompt injection and untrusted external content are treated as data, never instructions. Tool calls require policy checks; high-impact actions require human confirmation. Record appropriate model/provider, purpose, actor, tenant scope, timestamp and outcome metadata.

## 8. Deployment topology
Separate web/API from workers; keep PostgreSQL and queue on private network segments; inject secrets at runtime from customer-controlled storage; use TLS and secure internal communication; use persistent encrypted volumes and tested backup/restore; provide health checks, structured logs and documented upgrade/rollback. Core CRM and offline licence validation must not require outbound connectivity.

## 9. Architecture decisions requiring ADRs
1. Modular monolith versus independently deployed services initially.
2. Exact tenancy model and RLS policy conventions.
3. Authentication provider and MFA strategy.
4. Object storage and document scanning.
5. Event/outbox and background job model.
6. Search/indexing requirements.
7. AI provider configuration and data egress controls.
8. Offline licence clock rollback and revocation policy.
9. Supported deployment topologies and sizing profiles.

Default recommendation: start with a well-modularised application and shared PostgreSQL deployment; split services only when scale, isolation or operational requirements justify it.
