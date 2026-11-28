# Gate 0.1.3 — Architecture assurance
Status: Proposed; implementation not authorised.
Review baseline: 530b5fa67e5bd174b13e05ec9786cd0a411feffb (PR #1).

## Technical decisions proposed for review
| ID | ADR | Decision and required evidence |
|---|---|---|
| A01 | 0001 | Next.js/TypeScript frontend, FastAPI/Python modular backend, SQLAlchemy/Alembic; explicit domain dependency map and import boundary tests. Lock supported versions before implementation. |
| A02 | 0002 | PostgreSQL shared-schema RLS with FORCE ROW LEVEL SECURITY, separate non-owner runtime role, explicit USING and WITH CHECK policies, tenant-aware composite foreign keys. Transaction-local context derived from verified identity and membership. Treat mutable SQL session settings as context transport, not an independent trust boundary against arbitrary SQL execution; prohibit untrusted SQL and review context spoofing threats. Test missing/malformed context, pooling, direct SQL, cross-BU writes and worker replay. |
| A03 | 0003 | OIDC authorization-code flow with PKCE; validate issuer, audience, signature, expiry and nonce where applicable. Prefer customer-hosted identity provider for offline operation; no custom password implementation initially. Require MFA for privileged roles and test membership revocation, session expiry and privilege escalation. |
| A04 | 0004 | Separate migration owner and runtime roles; no runtime DDL, role escalation or unrestricted security-definer functions. Review grants, migration ordering, backup/restore and tenant-aware constraints. |
| A05 | 0005 | Ed25519 public-key verification; strict versioned schema and canonical JSON (RFC 8785 proposed), reject duplicate keys and unknown algorithms, bind product/customer/deployment and enforce entitlements server-side. Define signed trust-bundle rotation, expiry, recovery and clock rollback policy before implementation. Offline revocation is not instantaneous; customer administrators controlling binaries and clocks remain a residual risk. |
| A06 | 0006 | Default-deny AI egress, permission-filtered retrieval, untrusted content treated as data, scoped tools, explicit human approval for consequential actions. Test prompt injection, cross-tenant retrieval, provider failure and audit redaction. |
| A07 | 0007 | Docker Compose initial deployment profile; customer-controlled database, identity and secrets; no mandatory external calls. Define supported OS/runtime versions, image provenance, backup/restore and upgrade/rollback tests. Kubernetes deferred. |
| A08 | 0008 | PR checks for lint, types, tests, migrations, isolation, licensing, secrets and dependency vulnerabilities; image scanning once images exist. Pin third-party actions to reviewed commit SHAs, least-privilege workflow permissions, no untrusted PR secrets. Critical/high findings block release unless formally risk-accepted with expiry and compensating controls. |

## Closure blockers
- Exact supported dependency versions and compatibility matrix not yet verified.
- RLS context trust model, business-unit membership semantics and privileged support path require threat-model review.
- Offline licence clock rollback, trust-bundle update and disaster recovery policies require explicit decisions.
- Identity provider selection, offline deployment and session revocation behaviour require review.
- CI currently validates foundation documents only; it does not validate these security controls.
- Independent architecture/security review and designated approval authority are not yet recorded.

## Acceptance
Review each A01–A08 against the corresponding ADR; record findings, severity, disposition and exact commit. Resolve architecture blockers, update ADRs and reference architecture consistently, and obtain explicit approval. Implementation evidence belongs to later gates; do not claim controls are implemented here. Do not merge or authorise Gate 0.2 solely on documentation CI success.
