# ADR-0003: Identity, Authentication and Authorisation

**Status:** Proposed — pending approval  
**Date:** 2026-11-25

## Context
A universal enterprise CRM must integrate with customer identity systems while providing consistent authentication and fine-grained permissions.

## Decision
Define an identity-provider boundary compatible with OpenID Connect (OIDC). Support enterprise federation as an integration path. Local identity may be supported in the first release only if it meets the same security baseline and does not block federation. Authentication establishes identity; server-side authorisation determines tenant, business-unit, role and resource permissions.

Require MFA capability, secure session lifecycle, modern password hashing for local accounts, rate limiting, account recovery controls and audit events for security-sensitive changes. Design RBAC with permission scopes and resource-level checks; UI visibility is never an enforcement boundary.

## Alternatives
- One fixed external identity provider: rejected as a universal requirement.
- Local-only identity: insufficient for enterprise federation.
- UI-only role checks: rejected.

## Consequences
- Identity adapters and claims mapping must be documented.
- Tenant/BU membership and entitlements are server-verified.
- Privileged actions require step-up controls where risk warrants.
- Service accounts need separate lifecycle and scopes.

## Acceptance checks
- Authentication and authorisation are separately tested.
- MFA and OIDC federation test strategy is defined.
- Tenant/BU claims cannot be self-asserted by an untrusted client.
- Denied access and privileged actions are audited safely.
