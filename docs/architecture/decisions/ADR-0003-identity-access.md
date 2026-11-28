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

## Proposed initial identity profile
Customer-controlled external OIDC provider only; no local password fallback in initial profile. Use authorization code + PKCE S256, exact configured HTTPS issuer and redirect URIs, nonce/state, authenticated discovery and JWKS with bounded cache and approved asymmetric algorithms; reject unknown issuer/audience/azp, invalid signature, expired/future claims or unknown key. No dynamic issuer chosen by token or request, no email-based identity linkage. Use immutable (issuer, subject) mapping, local active membership and permission checks for every protected operation, and fresh context per transaction. Separate browser session cookie (Secure, HttpOnly, SameSite policy, CSRF protection) from service credentials; no browser token controls database identity. Customer IdP assurance mapping and MFA for privileged actions require explicit configuration and tests. Proposed 30-second maximum database context lifetime remains subject to approval; revocation blocks subsequent authorized statements, not already released data. IdP outage denies new authentication; existing-session policy and maximum lifetimes must be approved; no security bypass. Production IdP selection, role provisioning, exact token/session limits and real OIDC tests remain outstanding. No approved architecture decision inferred.
