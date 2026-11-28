# CEPHAS CRM — Gate 0.1.7 closure register and independent review brief
Status: proposed; open blockers; not accepted. Review baseline parent: 04d8366e1ca44c8231dff54f98dd39d8379179be. Reviewer must independently record actual current PR head, base and workflow run before assessment. PR #1 remains draft; no merge or implementation approval.

## C01 — Reconcile original work packages and current iterations
Original GATE_0_1_ACCEPTANCE.md work-package IDs are authoritative and distinct from iteration labels. No criteria waived.
| Original package | Evidence | Disposition |
|---|---|---|
| 0.1.1 PRD | PRODUCT_REQUIREMENTS.md | approval pending |
| 0.1.2 repository | README, CI, ADR register | protection and approval pending |
| 0.1.3 modular architecture | reference architecture, ADR-0001 and assurance | decision approval pending |
| 0.1.4 tenancy | Gate 0.1.5, PLATFORM_BLUEPRINT P01/P02 | disposable DB proof and policy inventory pending |
| 0.1.5 identity | ADR-0003, Gate 0.1.5 | IdP profile, revocation policy pending |
| 0.1.6 licence | OFFLINE_LICENSING, LICENCE_PROTOCOL L01–L04 | trust/recovery schema, clock policy, application vectors pending |
| 0.1.7 threat model | Gate 0.1.4 | independent assessment pending |
| 0.1.8 API/integration | PLATFORM_BLUEPRINT P03 | precise webhook contract pending |
| 0.1.9 deployment | PLATFORM_BLUEPRINT P04/P05 | sizing, anchor, recovery decisions pending |
| 0.1.10 CI and review | Gate 0.1.6, workflow, this brief | review, exact locks and branch enforcement pending |

## C02 — Decision and blocker register
No ADR marked accepted. Proposed owners are roles, not named appointments.
| ID | Decision/blocker | Severity | Proposed owner | Evidence required |
|---|---|---|---|---|
| C-01 | Authenticated context issuer and verifier resist same-role arbitrary SQL, replay, restoration and role escalation | Critical | DB/security | executable disposable real PostgreSQL proof and B01–B07/B09/B10/B13/B14 |
| C-02 | IdP profile, authority administration, MFA mapping and revocation race | High | Identity | precise contract and test plan |
| C-03 | Offline trust bundle/recovery schema, monotonic state, clock policy, key ceremonies and application vectors | High | Licensing/security | approved protocol and independent vectors |
| C-04 | Audit checkpoint anchoring and failure/reconciliation semantics | High | Security/operations | threat-bound design and test plan |
| C-05 | Worker envelope/replay and scoped queue processing | High | Platform | reviewed design before enabling workers |
| C-06 | Exact supported dependency locks and compatibility | High | Release | actual frozen installs and tests; no fabricated lock |
| C-07 | API/webhook precise contract and DR profile | High | Integration/operations | approved contract and recovery targets |
| C-08 | Repository protection and named approvers | High | Engineering governance | ruleset evidence and actual authorised reviewers |
| C-09 | Original Gate 0.1 requires demonstrable isolation before closure | Critical | Engineering authority | authorise disposable proof within Gate 0.1; or explicit limited exception for proof only at Gate 0.2 entry |
No domain feature work, production use or acceptance until critical blockers resolved; any exception requires named authority, rationale, scope, expiry and compensating controls. Do not conflate design review with proof.

## C03 — Independent architecture reviewer brief
Repository: https://github.com/ooluboyede/cephas-crm ; PR: https://github.com/ooluboyede/cephas-crm/pull/1.
Review actual exact SHA, base comparison and CI job steps; identify whether each document exists and whether claims match evidence. Review original acceptance plan, all eight ADRs, security and licensing baselines, iterations 0.1.3–0.1.7 and workflow. Assess conflicting wording (e.g. optional FORCE vs mandatory FORCE, plain session variable vs authenticated context, offline clock grace vs fail closed); require approved reconciliation in ADRs/reference architecture. Assess C-01–C-09, threats TM-01–16 and B01–14; validate trust boundaries, crypto, data model, privilege/role graph, identity, jobs, AI egress, licence limits and rollback, audit anchor, recovery and CI trust. Evaluate whether proposed controls are feasible, not whether they are merely written. No production data or keys. Do not accept based solely on green documentation CI.
Report: exact SHA/base, files reviewed, evidence and limitations, finding IDs/severity/affected lines, threat scenarios, required remediations, acceptance tests, residual risks and explicit decision (Accepted for specified scope / Accept with Conditions / Not Accepted). Distinguish design acceptance, proof authorisation, implementation acceptance and production readiness. Design reviewer cannot certify unimplemented controls. Any approval must specify scope and signoff identity/date; no self-certification by author.

## C04 — Recommended next engineering action
Gate 0.1.8: resolve high-risk design conflicts and specify/seek approval for isolated boundary proof before Gate 0.1 closure. Produce exact licence bundle/recovery schema and disposable application vectors, authority/IdP decision, audit anchor design and lock compatibility evidence. Independent reviewer may assess current proposal as preliminary only; final independent decision on remediated exact commit with proof evidence. No application code, branch rules or real key material added by this iteration.
