# Universal issuer-compatible offline verifier experiment
Run node --test proof/universal_licence/validator.test.mjs. No dependencies or network; Node 22+ candidate. Synthetic keys only. This verifier is separate from the older CRM-specific candidate protocol and does not accept that envelope. See docs/security/GATE_0_1_10_2_UNIVERSAL_VALIDATOR.md for scope and blockers. Expected 14 tests. Do not use for production issuance or customer entitlement enforcement.

Gate 0.1.10.3 adds a test-only persistent common-contract entitlement store and eight Node tests. Run node --test proof/universal_licence/*.test.mjs. Native node:sqlite requires supported Node 22+ (experimental API); no third-party package. See docs/security/GATE_0_1_10_3_PERSISTENT_UNIVERSAL_STATE.md for explicit limitations.

Gate 0.1.10.4 adds conservative renewal with preserved usage/history and six new tests, including two worker-thread contention cases. Existing test databases are disposable; no migration provided. See docs/security/GATE_0_1_10_4_RENEWAL_GOVERNANCE.md.
