# ADR-0005: Offline Signed Licence Verification

**Status:** Proposed — pending approval
**Date:** 2026-11-25

## Context
CEPHAS CRM must operate in customer-controlled environments, including restricted or offline networks. Customers verify entitlements locally without sending CRM data to CEPHAS.

## Decision
Proposed production decision: use only the existing CEPHAS Universal Offline Licensing Standard and Central License Issuer v1.0. Ed25519 signs UTF-8 ECMAScript JSON.stringify(payload) in issuer property order. Envelope fields are payload, signature and algorithm; schemaVersion is "1.0". Signed customer code, product code CEPHAS_CRM, tier, deployment ID/environment, issuedAt, expiresAt, gracePeriodDays, modules/features, limits (users, transactions, apiCalls, sites, businessUnits) and keyVersion are authoritative. Tenant/BU mapping is independently authorized locally; issuer does not sign tenant UUID or record-count quota. Do not interpret a valid licence as membership authorization. No experimental canonical-JSON fallback.

The CEPHAS signing private key remains in CEPHAS-controlled secure key management. It is never committed to source control, included in builds or installed at customer sites. Product releases contain trusted public verification keys only. Validate signature, schema, product, deployment binding, dates and entitlements server-side before enabling protected capabilities.

Match the actual compact issuer export and unpadded base64url Ed25519 signature. Provision authenticated SPKI public keys and fingerprint independently. Proposed runtime verifier uses Node crypto to preserve serialization semantics; backend service boundary and exact dependency qualification require approval. Key rotation must support trusted overlapping public keys and key identifiers. Online activation/status checks may be optional additions, never a prerequisite for core offline validation.

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
- Tampered, expired, wrong-product, wrong-customer and wrong-deployment licences fail closed; independently authorized tenant/BU mapping is tested separately.
- Private keys are absent from repository, artifacts and customer packages.
- Key rotation and old-key retirement tests pass.
- Clock manipulation and offline revocation limitations are documented and tested.

## Evidence and status
Gate 0.1.10.2–0.1.10.4 common-format experiments supersede the earlier CRM-specific candidate wire protocol for proposed production use. Legacy tests are regression evidence only. Actual issuer-signed nonproduction artifact, authenticated key provisioning, commercial policy approval, durable revocation/renewal and atomic product enforcement remain outstanding. This ADR remains Proposed.
