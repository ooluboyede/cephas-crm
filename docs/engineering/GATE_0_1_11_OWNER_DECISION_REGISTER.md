# Gate 0.1.11 — Owner and architecture decision register
Status: proposed; no signature or approval inferred from continuation requests. Record named authority, decision, scope, date, rationale and evidence in subsequent reviewed commit. No blanket acceptance.

| ID | Proposed decision | Evidence/condition |
|---|---|---|
| D11-01 | Approve PRD, modular monolith, staged universal customer-hosted market | PRD, ADR-0001, 0006, 0007; review proposed requirements |
| D11-02 | Adopt registry and dedicated tenant/BU roles for narrow shared-deployment row isolation; evaluate separate cluster for strict isolation | ADR-0002, 0004, 0009; no full noninterference claim; resolve C-01 |
| D11-03 | OIDC external IdP with issuer/subject identity, MFA, authorization freshness, no local fallback without separate review | ADR-0003; select supported IdP and review revocation semantics |
| D11-04 | Universal central issuer only, Ed25519 public-only verification, no compulsory network, no experimental envelope fallback | ADR-0005 requires reconciliation with actual issuer; approved tier policies and authentic test fixture |
| D11-05 | Independent customer-controlled recovery authority and audit checkpoint custody, fail closed on missing required evidence | choose protected storage/service and failure/recovery policy; SQLite not final anchor |
| D11-06 | Proposed tier policy for review, not approval | GATE_0_1_10_3_CRM_TIER_POLICY.md; commercial owner confirms limits, null, grace and count/reset policy; independent issuer approval follows real evidence |
| D11-07 | Strict PR governance, no bypass, required CI and named independent reviewer | G01 configuration correction verified; named independent reviewer and actual approvals pending |
| D11-08 | Approve exact dependency/platform and operational profile only after qualifying locked builds | no fabricated compatibility or security scan evidence |

No decision marked accepted. Distinguish owner commercial approval, independent security reviewer acceptance, and production release authority. No Gate 0.2 exception requested or granted. Do not require implementation of entire CRM to review a foundation design, but explicitly distinguish remaining design risks from future implementation deliverables and obtain scoped approval before any implementation gate.

## Gate 0.1.11.1 update
Owner continuation is not formal approval of D11-01–08. D11-07 ruleset configuration verified; review assignment and decision signoff remain pending. ADR-0005 and offline baseline reconciled with actual issuer contract; ADR-0003 initial external IdP profile proposed. All ADR statuses remain Proposed.
