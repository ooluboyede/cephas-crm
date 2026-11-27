# ADR-0009 — Transaction registry, scope roles and recovery authority
Status: Proposed, experimental evidence only; not architecture approval.
Parent: 35663c9917e5a0bd2276ca4586f5de98042a44aa. Refines ADR-0002 and proposed Gate 0.1.5/0.1.8 context design.

## Decision proposed
Replace the proposed HMAC database capability for the disposable proof with a protected transaction registry and trusted broker, supported by dedicated tenant/BU login roles. No mutable GUC or custom SQL crypto is an authority. Require transaction identity, active membership, exact scope, expiry and restricted runtime privileges. Fresh connection per broker operation; no general SQL exposed. Shared role remains test-only and must not ship. Production OIDC identity, service boundaries, credential custody and scalable role provisioning need separate acceptance.
Recovery state is supplied by an independent trusted operator-managed authority, never learned automatically from the restored CRM database. Prototype uses an append-only SQLite journal outside the PostgreSQL container with compare-and-append, unique epochs and read-only broker access. Before and after protected reads, broker validates its pinned journal record and matching database epoch; epoch advance invalidates old broker. Recovery requires quarantine, authority reconciliation, journal advance, DB epoch update and explicitly configured new broker. No atomic cross-store cutover or rollback protection against a privileged operator restoring both stores is proven. Local journal is not an independent WORM/HSM anchor.

## Alternatives and tradeoffs
HMAC capability: deferred; cryptographic verifier feasibility unproven. Shared login: retained only for tests; increases same-login information channels. Dedicated scope roles: additional SQL isolation but provisioning and credential scaling cost. Separate database/cluster and operational domain: candidate mandatory profile for customers requiring strict noninterference or stronger threat containment. Global LISTEN/NOTIFY, locks, timing, signalling, catalogue and resource channels remain outside demonstrated row-isolation scope; cannot claim full noninterference. No feature release before threat profile review.

## Acceptance
Independent review of exact proof SHA and all tests, production trust boundary design, external durable monotonic authority with protected custody, full restore/failover and quarantine, role lifecycle and OIDC integration. No original Gate 0.1 criterion waived. The proof is not a production implementation or release authorisation.
