# ADR-0007: Customer-Controlled Deployment and Data Plane

**Status:** Proposed — pending approval
**Date:** 2026-11-25

## Context
CEPHAS CRM is licensed software deployed into customer-controlled infrastructure. Customers retain control of CRM records, infrastructure access and backups.

## Decision
Make Docker-based deployment the initial supported packaging baseline. Provide versioned, reproducible images, configuration templates, health checks, upgrade instructions and backup/restore procedures. Support on-premises and private-cloud installations first. Define hybrid patterns where customer policy permits. Kubernetes may be introduced as a separately validated deployment profile, not assumed for every installation.

Separate application, database, cache and worker processes. Inject secrets at deployment time through supported secret-management mechanisms; never bake them into images or commit them. Telemetry and support diagnostics are configurable, data-minimised and disabled or restricted unless authorised by the customer.

## Alternatives
- CEPHAS-hosted SaaS as the only model: rejected as default.
- Manual installation without reproducible packaging: rejected.
- Mandatory Kubernetes: deferred due to complexity for smaller installations.

## Consequences
- Deployment documentation and supported version matrix are release requirements.
- Customer integrations and secrets remain in customer environment.
- Upgrade, rollback, backup and disaster recovery require testing.
- Supply-chain provenance and image vulnerability management are required.

## Acceptance checks
- Clean customer-like environment installs from published artifacts.
- No secrets or customer records are embedded in images.
- Backup/restore and supported upgrade paths are exercised.
- Outbound network dependencies are documented and configurable.
