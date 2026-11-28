# Disposable offline licence and audit proof
Run from repository root: python3 proof/licence_audit/run.py. Requires Python 3 and OpenSSL with Ed25519 support. Generates only ephemeral test keys. No production data, private CEPHAS keys or network verification. 14 tests required with no skips. See docs/security/GATE_0_1_10_LICENCE_AUDIT_ASSURANCE.md for scope, protocol decisions and blockers. Not production entitlement enforcement or external audit anchoring.

Gate 0.1.10.1 expands the protocol suite to 20 tests and adds an experimental SQLite state store. Earlier 14-test count is historical. See the issuer/state assurance document for compatibility blockers and limits. No company signing keys or live issuer integration.
