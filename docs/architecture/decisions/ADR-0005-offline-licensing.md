# ADR-0005: Offline Signed Licence Verification

**Status:** Proposed — pending approval
**Date:** 2026-11-25

## Context
CEPHAS CRM must operate in customer-controlled environments, including restricted or offline networks. Customers verify entitlements locally without sending CRM data to CEPHAS.

## Decision
Use a digitally signed licence payload with Ed25519 as the proposed signature scheme, subject to cryptographic library review. The strictly validated payload identifies product CEPHAS_CRM, customer/tenant, edition, enabled modules, deployment binding, validity interval, approved limits, key identifier and schema version.

The CEPHAS signing private key remains in CEPHAS-controlled secure key management. It is never committed to source control, included in builds or installed at customer sites. Product releases contain trusted public verification keys only. Validate signature, schema, product, deployment binding, dates and entitlements server-side before enabling protected capabilities.

Specify canonicalisation and encoding. Key rotation must support trusted overlapping public keys and key identifiers. Online activation/status checks may be optional additions, never a prerequisite for core offline validation.

## Alternatives
- Shared secret embedded in customer software: rejected because it can be extracted and used to forge licences.
- Online-only licensing: rejected because it conflicts with offline deployment.
- Unsigned configuration: rejected.

## Consequences and limitations
- Offline systems cannot receive instantaneous revocation updates. Define signed denylist updates for periodically connected customers, expiry and renewal rules.
- Proposed initial policy: no silent grace. Expired or suspect licence/time/trust state denies protected operations without deleting customer data; separately authorised, audited recovery/export remains subject to tenant isolation. Finalise durable clock rollback detection, recovery and deployment rebinding before implementation.
- Licence validation must not collect customer CRM data.
- Enforcement is server-side, not merely in the UI.

## Acceptance checks
- Tampered, expired, wrong-product, wrong-tenant and wrong-deployment licences fail closed.
- Private keys are absent from repository, artifacts and customer packages.
- Key rotation and old-key retirement tests pass.
- Clock manipulation and offline revocation limitations are documented and tested.
