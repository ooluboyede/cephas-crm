# ADR-0008: CI Quality, Security and Release Gates

**Status:** Proposed — pending approval
**Date:** 2026-11-25

## Context
An enterprise CRM requires repeatable evidence that changes preserve correctness, tenant boundaries and software supply-chain integrity.

## Decision
Use required GitHub Actions checks for pull requests and protected release branches. Include formatting/linting, type checks, unit and integration tests, migration validation, API tests, tenant/BU isolation tests, dependency and secret scanning, container scanning when images exist, and reproducible-build checks where practical.

As the product matures, add Playwright end-to-end tests for critical workflows and adversarial security tests. Establish severity thresholds and an exception process with named approvers, expiry dates and compensating controls. No security finding may be silently waived. Production release requires successful required checks, reviewed changes, artifact provenance and documented rollback.

## Alternatives
- Manual testing only: rejected.
- Security scans that never block on agreed critical findings: rejected.
- One slow test suite without fast feedback: rejected; use layered checks.

## Consequences
- CI duration and test reliability must be monitored.
- Flaky tests must be fixed, not routinely ignored.
- Secrets belong in protected GitHub secret facilities, not workflow files.
- Production certification requires evidence beyond a green CI run, including independent security review.

## Acceptance checks
- Required checks are demonstrated on a pull request.
- Critical/high severity handling and exceptions are documented.
- Tenant isolation, migrations and licence validation have automated tests.
- Release evidence is linked to exact commits and artifacts.
