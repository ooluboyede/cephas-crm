# CEPHAS CRM — Security Baseline

**Status:** Initial threat-model baseline; not a security certification

## 1. Security objectives
Protect confidentiality, integrity and availability of customer relationship data; prevent cross-tenant and cross-business-unit access; preserve trustworthy audit evidence; protect licence signing trust; prevent integrations or AI tools from bypassing policy.

## 2. Primary assets
Customer profiles and contacts; commercial opportunities and contracts; support cases and communications; credentials and session tokens; tenant/business-unit configuration; audit records; integration secrets; AI context and outputs; licence files and trusted public keys; backup data.

## 3. Threat actors and trust boundaries
Consider external attackers, malicious/compromised users, compromised tenant administrators, malicious insiders, vulnerable dependencies, compromised providers, prompt-injection content, stolen deployment credentials and operator error. Boundaries include browser/API, tenant, business unit, application/database, application/worker, customer/provider, AI model/tool, deployment host and licence signing infrastructure.

## 4. Mandatory controls
- Deny-by-default authorization and server-verified identity/tenant context.
- PostgreSQL RLS and database constraints for tenant-owned data.
- Secure password/session handling and MFA-capable authentication.
- TLS and encryption at rest with customer-controlled key management where supported.
- Secrets outside source control; least-privilege credentials and rotation.
- Input validation, output encoding, CSRF protections where applicable, safe CORS and security headers.
- Rate limits for authentication, APIs and sensitive operations.
- Append-only or tamper-evident audit design for privileged/sensitive actions.
- Signed integrations/webhooks with timestamp tolerance, replay protection and idempotency.
- Dependency, container and static security scanning in CI.
- Secure backup, restore and key recovery procedures.
- Data export controls, retention and deletion workflows.
- AI prompt-injection defenses, permission-filtered retrieval and human approval for consequential actions.

## 5. High-risk scenarios to test
1. User changes tenant or business-unit IDs in requests.
2. A pooled connection reuses stale tenant context.
3. Worker executes a queued task after membership or permissions are revoked.
4. Reporting, aggregation, search or export bypasses row policies.
5. Runtime database role owns protected tables or has BYPASSRLS.
6. Admin/support reads another tenant's records without approved audited break-glass.
7. Webhook replay, forged signature or duplicate delivery.
8. Secrets leak through logs, exceptions, traces or frontend bundles.
9. Licence altered, expired, copied to unauthorized deployment or validated with untrusted key.
10. AI prompt injection attempts data disclosure or unauthorized tool invocation.
11. Backup/restore mixes tenants or restores insecure permissions.
12. Unsafe file upload compromises a worker.

## 6. Verification
Include positive and negative authorization cases, tenant isolation across all data paths, RLS tests using the real application database role, dependency/container scans, secret scanning, API abuse tests and deployment configuration checks. Independent review is required before production certification.

## 7. Incident readiness
Define security ownership, evidence preservation, customer notification responsibilities, credential/key rotation, containment, recovery and post-incident review before production launch.

## 8. Assurance statement
This document specifies intended controls. It does not prove implementation, testing or independent certification. Each control requires traceable implementation and test evidence.
