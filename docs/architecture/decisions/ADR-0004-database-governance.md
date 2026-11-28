# ADR-0004: Database Ownership, Migrations and Data Governance

**Status:** Proposed — pending approval
**Date:** 2026-11-25

## Context
A modular platform requires controlled schema evolution, safe production upgrades and separation between runtime access and database administration.

## Decision
Use PostgreSQL as the primary relational datastore. Manage schema changes through versioned, reviewed migrations. Assign each domain module ownership of its tables and migration responsibility. Cross-module references use documented contracts and constraints; modules do not mutate another module's tables directly.

Separate migration/schema-owner credentials from runtime credentials. Runtime roles receive minimum grants and remain subject to RLS. Migration execution is an explicit deployment step with backup, rollback and compatibility planning.

Define data classification, retention, export, deletion, backup and restore requirements before production certification. Encryption at rest and in transit must be configurable for customer policies.

## Alternatives
- Ad hoc production SQL: rejected.
- Shared unrestricted database superuser for runtime: rejected.
- Different database technology per module: not the initial default.

## Consequences
- Migration review and upgrade tests are release blockers.
- Prefer backward-compatible expand/contract migrations.
- Restore drills and tenant-safe export/deletion tests are required.
- Data ownership and retention rules are documented per domain.

## Acceptance checks
- Clean install and supported upgrade tests pass.
- Runtime credentials cannot perform schema-owner operations.
- Backup/restore and data lifecycle procedures are documented.
