# CEPHAS CRM Architecture Decision Register

**Status:** Proposed — pending architecture review and approval
**Gate:** 0.1.2

This register contains decisions required before Gate 0.2. These are proposals, not approved decisions. Each ADR must be reviewed against product requirements, security threats, deployment constraints and implementation evidence.

| ADR | Topic | Proposed direction | Status |
|---|---|---|---|
| 0001 | Application architecture | Modular monolith first; bounded modules and explicit interfaces | Proposed |
| 0002 | Tenant and BU isolation | PostgreSQL RLS, server-verified context, fail closed | Proposed |
| 0003 | Identity and access | OIDC-compatible identity, MFA capability, server-side RBAC | Proposed |
| 0004 | Database governance | Explicit schema ownership, reviewed migrations, least privilege | Proposed |
| 0005 | Offline licensing | Ed25519-signed licence; private key never shipped | Proposed |
| 0006 | AI provider independence | Provider adapters, permission filtering, customer-authorised egress | Proposed |
| 0007 | Deployment | Customer-controlled Docker deployment baseline | Proposed |
| 0008 | CI and security | Required tests, scans and release gates | Proposed |

## Approval rules
1. Review each ADR with engineering and security owners.
2. Record alternatives, trade-offs, consequences and conditions.
3. Mark Accepted only after explicit approval by the designated architecture authority.
4. Supersede rather than silently rewrite an accepted decision.
5. Do not begin Gate 0.2 until all mandatory ADRs are accepted and Gate 0.1 acceptance criteria are satisfied.

## Open cross-cutting questions
- Supported PostgreSQL versions and precise RLS context pattern.
- Identity provider strategy and local identity support in the first release.
- Key rotation, offline revocation, clock rollback and grace-period policy.
- Backup, restore, disaster recovery and customer-managed encryption keys.
- Supported Docker/Compose and Kubernetes profiles.
- Security scanning tools, severity thresholds and exception authority.
