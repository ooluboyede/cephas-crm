# CEPHAS CRM

**Enterprise Customer Relationship & Intelligence Platform**  
A modular, AI-enabled CRM platform by CEPHAS AI Solutions.

## Product direction
- Market: Universal — organisations and industries worldwide.
- Delivery: Complete modular platform, implemented through controlled engineering gates.
- Deployment: Customer-controlled on-premises, private cloud and hybrid environments.
- Licensing: Annual signed licence with offline public-key validation as standard.
- Data control: Customer-hosted deployments retain customer control of CRM data.
- Online verification: Optional future capability; not required for standard offline validation.

## Architecture principles
1. Database-enforced tenant and business-unit isolation.
2. Server-verified tenant context and fail-closed authorization.
3. Modular bounded contexts with explicit dependencies.
4. API-first integration and versioned contracts.
5. Secure-by-default configuration and auditable privileged actions.
6. Automated tests and successful CI at every engineering gate.
7. Private signing keys are never distributed with customer installations.
8. No production certification claim until release gates and independent review are complete.

## Proposed technology baseline
- Web: Next.js, React and TypeScript.
- API: Python and FastAPI.
- Data: PostgreSQL, SQLAlchemy and versioned migrations.
- Background jobs: Redis and Celery, introduced only with tenant-safe job context.
- Testing: Pytest and Playwright.
- Packaging: Docker.
- CI: GitHub Actions.

Exact versions and support windows must be pinned and reviewed before implementation is locked.

## Initial engineering gates
- Gate 0.1: Product definition, architecture, security and engineering foundation.
- Gate 0.2: Core platform — tenancy, identity, authorization, audit and licence validation.
- Gate 0.3: Customer 360 and relationship management.
- Gate 0.4: Sales and pipeline management.
- Later gates deliver marketing, service, communications, workflow, analytics, AI and industry extensions.

## Project status
Architecture definition is underway. This initial documentation is not a working CRM implementation and does not imply production readiness.

See docs/PRODUCT_REQUIREMENTS.md, docs/architecture/REFERENCE_ARCHITECTURE.md, docs/security/SECURITY_BASELINE.md, docs/licensing/OFFLINE_LICENSING.md and docs/engineering/GATE_0_1_ACCEPTANCE.md.
