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
Signed payload defines licence schema/version and unique ID; product identifier CEPHAS_CRM; customer/organisation and tenant IDs; edition and enabled module IDs; deployment/environment binding policy and deployment ID where used; issue, not-before and expiry times; approved user/seat/record/transaction limits; signing key ID (kid) and algorithm; optional renewal/support metadata. Avoid secrets and unnecessary personal data.

## 4. Validation sequence
1. Parse using a strict versioned schema.
2. Reject unknown/disallowed algorithms and malformed encodings.
3. Select trusted public key by kid.
4. Verify signature over exact canonical payload bytes.
5. Verify product, tenant, edition, modules and deployment binding.
6. Verify not-before and expiry using defined clock policy.
7. Enforce limits and feature entitlements server-side.
8. Record minimal tamper-evident validation event without logging sensitive licence material.
9. Fail closed for invalid signatures, unsupported schemas, mismatched product/tenant/deployment or expired licences, with no silent grace in the proposed initial profile; recovery/export is separately authorised and audited, preserves data and never bypasses tenant isolation.

## 5. Cryptographic design
Use a modern supported digital signature scheme such as Ed25519, subject to library review and platform support. Define deterministic serialization/canonicalization and test cross-language verification. Do not invent cryptographic primitives. Key rotation supports overlapping trusted public keys and documented migration.

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
