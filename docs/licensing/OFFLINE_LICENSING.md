# CEPHAS CRM — Offline Licence Architecture

**Status:** Design specification for Gate 0.1

## 1. Objective
Allow a customer-controlled installation to validate its annual licence locally without depending on a live CEPHAS server. Online verification may be added later as optional capability and must not be a prerequisite for standard offline operation.

## 2. Trust model
- CEPHAS operates a protected signing authority.
- Signing private key is held only in CEPHAS-controlled secure signing infrastructure, preferably an HSM or equivalent managed key vault.
- Customer installations contain only trusted public verification keys.
- Product verifies signature and claims locally.
- A valid signature proves trusted issuance, not that a licence is current or applicable to this installation.

## 3. Licence claims
The sole proposed production format is the existing universal issuer v1.0 envelope {payload, signature, algorithm}. Payload contains schemaVersion, licenseId, customer, product, tier, deployment, issuedAt, expiresAt, gracePeriodDays, limits, modules, features and keyVersion. Product code CEPHAS_CRM; customer code and deployment ID/environment are bound. Quotas are users, transactions, apiCalls, sites and businessUnits. No signed tenant UUID, record limit or separate not-before field exists in v1.0. Local tenant/BU authorization is independently enforced. Do not extend signed claims without central issuer approval.

## 4. Validation sequence
1. Parse using a strict versioned schema.
2. Reject unknown/disallowed algorithms and malformed encodings.
3. Select independently provisioned trusted public key by keyVersion and confirm fingerprint/status.
4. Verify Ed25519 signature over exact UTF-8 JSON.stringify(payload), with no sorted-key or domain-prefix fallback.
5. Verify customer, product, tier, modules/features and deployment/environment; independently enforce local tenant/BU membership.
6. Verify issuedAt and expiresAt, signed grace bounded by approved local policy, protected time and locally available revocation.
7. Enforce limits and feature entitlements server-side.
8. Record minimal tamper-evident validation event without logging sensitive licence material.
9. Fail closed for invalid signatures, unsupported schemas, mismatched product/tenant/deployment or expired licences, with no silent grace in the proposed initial profile; recovery/export is separately authorised and audited, preserves data and never bypasses tenant isolation.

## 5. Cryptographic design
Use issuer-standard Ed25519 with exact ECMAScript serialization. Verify the compact exported artifact, reject duplicate/ambiguous fields and untrusted embedded keys. Test independent issuer-signed fixtures. Node prototype is not an approved production backend. Do not invent cryptographic primitives. Key rotation supports overlapping trusted public keys and documented migration.

## 6. Offline limitations and policy decisions
Offline deployments cannot receive instantaneous revocation updates. Document renewal, explicit no-silent-grace policy, clock rollback detection, backup/restore, deployment re-binding and emergency key rotation. Exact tolerance and protected state remain open. Avoid destructive lockout on transient clock anomalies; define a risk-based auditable policy. Do not rely solely on a resettable local timestamp file for anti-rollback.

## 7. Security requirements
- Signing private keys never enter repository, build artifacts or customer packages.
- No private signing key in frontend code, container images or environment examples.
- Public keys are not secret but must be integrity-protected as part of trusted release.
- Licence verification runs on trusted backend, not only browser code.
- Feature and limit checks are enforced by backend services.
- Tests cover tampering, wrong/unknown key, wrong product/tenant/deployment, expiry/not-before, unsupported schema, boundary times and key rotation.

## 8. Required artefacts before implementation
Licence schema; canonicalization specification; signing/verification library decision; public-key trust-store format; key ceremony and rotation procedure; clock/grace policy; test vectors; threat model; renewal/recovery runbook.

## Protocol reconciliation
The earlier Gate 0.1.7 candidate protocol remains historical experimental evidence, not a supported alternative licence format. Current authoritative source inspection and limitations are documented in Gates 0.1.10.1–0.1.10.4. Commercial policy, genuine fixture, signed renewal ordering, complete revocation, protected state and customer-side enforcement remain pending. No final approval implied.
