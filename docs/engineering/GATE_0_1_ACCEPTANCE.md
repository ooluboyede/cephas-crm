# CEPHAS CRM — Gate 0.1 Acceptance Plan

**Gate:** 0.1 — Product Architecture and Engineering Foundation  
**Status:** Open; initial documentation baseline initiated

## 1. Purpose
Approve product requirements, reference architecture, security baseline, offline licensing trust model, repository conventions and CI foundation before core application implementation begins.

## 2. Work packages

| ID | Deliverable | Evidence required |
|---|---|---|
| 0.1.1 | Product requirements | Reviewed PRD and scope boundaries |
| 0.1.2 | Repository foundation | Standard directories, README, ignore rules and branch strategy |
| 0.1.3 | Modular architecture | Bounded contexts, dependency rules and architecture decision records |
| 0.1.4 | Tenancy/data architecture | ERD, tenant/BU model, RLS policy inventory and threat cases |
| 0.1.5 | Identity/authorization | Principal, role, permission, session and MFA design |
| 0.1.6 | Offline licensing | Signed payload schema, key trust model, validation sequence and test vectors |
| 0.1.7 | Security threat model | Assets, boundaries, abuse cases, mitigations and verification plan |
| 0.1.8 | API/integration standards | Versioning, errors, auth, idempotency, webhooks and rate-limit conventions |
| 0.1.9 | Deployment blueprint | Container topology, secrets, persistence, backup, restore and upgrade approach |
| 0.1.10 | CI and review | Required checks, successful run and architecture review record |

## 3. Gate acceptance criteria
Gate 0.1 passes only when:
- Product and non-functional requirements are reviewed and approved.
- Module boundaries and dependency constraints are documented.
- Tenant and business-unit isolation is demonstrably database-enforced and fail-closed.
- Identity and authorization design is reviewed.
- Offline licence trust model and key custody are reviewed.
- Security threat model has no unresolved critical design risks.
- API, integration and deployment conventions are documented.
- Repository structure and contribution conventions are established.
- CI runs successfully and required checks are defined.
- Review decisions, open risks, owners and follow-up work are recorded.

A documentation commit alone is not Gate 0.1 completion. No production certification is implied.

## 4. Recommended sequence
1. Complete PRD and architecture review.
2. Record architecture decision records (ADRs).
3. Define tenancy model and policy inventory before domain tables.
4. Define identity and authorization model.
5. Finalise licence schema and cryptographic test vectors.
6. Establish CI and code-quality gates.
7. Approve deployment and operational baseline.
8. Conduct architecture/security review and close critical findings.

## 5. Gate 0.2 entry conditions
Gate 0.2 may begin only after Gate 0.1 is accepted or an explicit documented exception is approved. Gate 0.2 implements organisation/tenant/business-unit management, identity, RBAC, database isolation, audit foundation and offline licence verification.

## 6. Current status
These are proposed design artefacts. Technical decisions requiring ADRs and all implementation evidence remain open until reviewed and verified.
