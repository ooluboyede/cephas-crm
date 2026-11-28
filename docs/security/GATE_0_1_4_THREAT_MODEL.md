# CEPHAS CRM — Gate 0.1.4 Threat model
Status: Proposed design, not implemented or independently accepted.
Baseline: 6be726dd31e1c028c7deb1f0ae09f587fb06f0c1 (PR #1).
Dependencies: SECURITY_BASELINE.md, ADR-0002, ADR-0003, ADR-0005, ADR-0006, Gate 0.1.3 A01–A08.

## Assets and trust model
Protect CRM personal/commercial records, credentials, memberships, integration tokens, exports, backups, AI context, audit evidence, release artifacts, licences and CEPHAS signing keys. External users, compromised identities, malicious tenants, untrusted content, dependencies and external providers are adversarial. Customer-controlled host/root, database superusers and identity administrators are privileged trust dependencies, not contained by application RLS; document responsibilities and residual risks. CEPHAS signing infrastructure is outside the customer deployment. No mandatory outbound traffic for core offline operation.

## Data flows and boundaries
- Browser -> TLS reverse proxy -> API: authenticate verified issuer/audience/signature/expiry; request identifiers are selectors only. Prefer secure HttpOnly SameSite cookies with CSRF protection where browser sessions are used; do not expose bearer tokens to logs or client bundles.
- API -> identity/membership service -> database: authoritative active membership, explicitly selected tenant and BU, action permission; reject ambiguity. Default to single-BU scope; tenant-wide access requires separately authorised explicit role and enumerated scope, not a null wildcard.
- API -> transaction -> database: context installed and cleared within transaction; no protected queries before verification. Separate runtime, migration, backup and emergency access identities. FORCE RLS and policies on every protected table; USING and WITH CHECK; tenant/BU-aware keys and constraints. Context settings alone cannot withstand arbitrary SQL under the same role. No untrusted SQL, parameterisation, constrained grants and trusted context setter design review required. Do not claim isolation against compromised runtime or superusers. If arbitrary runtime SQL is in scope, require a stronger independently validated binding mechanism or deployment isolation.
- API -> job queue -> worker: service-issued job envelope binds job ID, tenant, BU, actor/service principal and intended operation; integrity/authenticity, expiry and replay/idempotency controls; recheck live membership/entitlements before executing and before publishing results. No raw client context or serialised ambient sessions.
- API -> search/cache/export/object storage: scope all keys, indexes, file paths and access tokens by tenant/BU and permission; recheck access at download; no public links by default; use scoped TTL and quotas.
- API -> AI gateway -> model/tools: local provider preferred, default-deny egress, retrieval authorization before context construction, content untrusted, tool calls independently authorised, consequential changes require scoped expiring approval bound to operation and parameters. No model-direct access to credentials or database.
- Integration ingress/egress: verify signatures over original bytes before processing; tenant binding, timestamp window, durable replay/idempotency and scoped credentials; egress allowlist with SSRF protection.
- CEPHAS offline signing -> customer verifier: private keys never distributed; pinned public trust roots, signed versioned trust bundle and strict entitlement enforcement. Release signing and licence signing separate key purposes.
- Deployment -> backups/audit: customer-managed access and encryption; restore isolation and integrity verified before service; audit events include actor, scope, action, outcome, correlation ID, UTC time; redact secrets and sensitive payloads. Tamper evidence needs independent protected anchor if adversarial DB administrators are in scope.

## Threat register and required acceptance tests
Risk is preliminary inherent risk, not discovered vulnerabilities or measured residual risk. All controls pending. Each test needs exact commit, environment, expected/actual results and retained evidence. Owners below are proposed role assignments.
| ID | Threat / risk | Required control and negative test | Owner |
|---|---|---|---|
| TM-01 | Cross-tenant exposure / Critical | RLS + tenant-aware constraints; two tenants, same logical object IDs; deny list/read/write/delete/upsert/joins/exports as runtime role. | Database |
| TM-02 | Cross-BU access / Critical | Active scoped membership; deny sibling BU operations, null/wildcard and cross-BU FK substitutions. | Identity/DB |
| TM-03 | Impersonation / Critical | OIDC claims verification, PKCE, MFA for privileged roles; reject expired/wrong issuer/audience and invalid signature; test revoked membership. | Identity |
| TM-04 | Privilege escalation / Critical | Default deny; no self-grant, no runtime ownership/BYPASSRLS/role escalation; test direct DB grants and object authorization. | Security |
| TM-05 | Context manipulation / Critical | Trusted server derives context; transaction reset and rollback; reject malformed or missing scope and client selectors; adversarial pool reuse; explicitly assess arbitrary SQL and mutable session settings. | Database |
| TM-06 | Worker leakage / Critical | Authenticated job envelopes and fresh authorization; deny tampered, replayed, expired and revoked jobs; test retries and worker context reuse. | Platform |
| TM-07 | Licence forgery / Critical | Strict canonical payload, signature and scope/time/module validation; reject duplicate fields, algorithm confusion, wrong tenant/deployment/product and disabled module calls. | Licensing |
| TM-08 | Signing compromise / Critical | Separate CEPHAS key custody, key purposes, signed rotation and recovery procedure; test unknown/retired kid, rollback trust bundle, artifact secret scanning; document offline revocation delay. | Security |
| TM-09 | AI disclosure or unsafe actions / Critical | Permission-filtered retrieval, egress deny, constrained tools and human approval; adversarial documents cannot retrieve foreign records or execute unapproved actions. | AI |
| TM-10 | Supply chain compromise / Critical | Locked dependencies, pinned CI actions, build provenance and verified release signatures; reject altered artifact and unapproved high/critical findings. | Release |
| TM-11 | Webhook abuse / High | Signature, timestamp, tenant scope, durable idempotency and egress restrictions; reject forged/stale/duplicate and unapproved destinations. | Integration |
| TM-12 | Audit manipulation / High | Append-only runtime grants, chained integrity and controlled evidence export; test alteration detection and failed access audit; disclose anchor limitations. | Security |
| TM-13 | Backup compromise / High | Encrypted least-privilege backups; restore into isolated environment; verify roles, constraints, trust state and tenant tests before enablement. | Operations |
| TM-14 | Bulk export abuse / High | Separate export permission, quotas, scoped job/download token and audit; test revoked permissions, foreign token and cache keys. | Platform |
| TM-15 | Licence time rollback / High | Proposed fail closed for protected operations on expired or suspect state; no silent grace; preserve customer data and authorised recovery/export; test restored state and clock changes; trusted time/monotonic persistence not yet selected. | Licensing |
| TM-16 | Resource exhaustion / High | Request/upload/job/AI budgets and tenant quotas, bounded retries, backpressure; test saturation without cross-tenant starvation. | Platform |

## Additional security requirements
Uploads are quarantined; validate type/size and scan before processing; sandbox parsers and reject unsafe paths. Secrets are supplied through customer-controlled secret storage and excluded from logging. Break-glass support is disabled by default; if approved, separate identity, explicit tenant approval, time-bound scope, dual approval and audit; no hidden CEPHAS access. Privacy retention/deletion must account for backups and derived AI/search data. Incident procedures include customer ownership, isolation, preservation, rotation, recovery and notification responsibilities.

## Proposed architecture decisions requiring closure
- D01: Specify context setter and database role model, policy coverage inventory, actual membership predicates, pooling mode and adversarial SQL threat scope; build real PostgreSQL tests at Gate 0.2.
- D02: Select supported OIDC provider/profile and revocation latency; fail closed if authoritative membership cannot be checked. Define offline identity availability.
- D03: Specify canonicalisation library and signed trust-bundle schema, key retirement, deployment rebinding and disaster recovery. Define durable rollback protection limitations; customer root can alter code/state. No claim of instant offline revocation or tamper-proof enforcement.
- D04: Define audit anchor and retention responsibility; no mandatory external anchor unless customer authorises and offline profile supports it.
- D05: Define job envelope signing/authentication, replay storage and service principal permissions before enabling workers.
- D06: Pin supported platform versions and tools; define exact CI checks and evidence schema. Existing docs CI does not validate the controls above.

## Gate closure criteria
All threats mapped to ADRs and later implementation tests; review D01–D06 and resolve design blockers; record risk owner, disposition, rationale, evidence and approval at exact commit. Independent architecture/security review and explicit approval required before authorising Gate 0.2. Tests are specifications, not results. Production certification requires implemented controls, adversarial tests and independent implementation review.
