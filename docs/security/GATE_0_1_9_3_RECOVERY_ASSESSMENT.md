# Gate 0.1.9.3 — Recovery, cancellation and database assurance
Status: experimental, not accepted. Parent fbc5bea567107c748be518c37c830b251382ae18.
Verified baseline Run #12 45956778143: 26/26 passed, 38.474 seconds, PostgreSQL 18.7, merge SHA 7aebc77ae6850b11c417e9a6f73967c76678055e. New suite 33 tests; separate CI evidence required.

## Implemented experiment
- Actual active PostgreSQL query cancellation, rollback and fresh connection.
- Actual backend termination during broker operation; generic denial and disposal.
- Cleanup-failure denial even after successful read; attempt cleanup of both sessions.
- Broker receives independently supplied expected epoch at trusted construction and checks issuer epoch before issuance and before result release; runtime rechecks scope before commit.
- Real pg_dump/pg_restore of epoch, membership and binding authority data in disposable DB. Demonstrates restored revoked membership may become active again in old DB state, but previously configured broker with newer expected epoch denies the request.
- Foreign scope backend signalling denied; runtime cannot access issuer-only epoch function.

## Important recovery limits
The expected epoch in this experiment lives in trusted process memory; it is not a durable independent rollback anchor. Never adopt the database epoch automatically after startup or restore. Production requires externally protected monotonic deployment/recovery state, authenticated configuration, quarantine of all runtime/issuer paths during restore, authoritative reconciliation of membership and licence/audit floors, credential rotation where required, new epoch and explicit operator approval. Raw direct issuer access remains privileged and can bypass broker epoch check; not a production access path. Full cluster/PITR, concurrent restore, restored external state, failover, cancellation races, crash recovery and availability remain unproven. The test restores selected authority tables, not an entire production backup. Epoch checks do not atomically guarantee revocation at the instant of result delivery; already materialised data cannot be recalled. Separate login mitigates cross-role signalling, not all shared-cluster side channels (including LISTEN/NOTIFY, locks, timing, stats, resource usage and catalog inference). No covert-channel isolation claim. Strict profiles may require separate databases/clusters and separate operational trust domains.

## Reviewer readiness
Do not mark Gate 0.1 accepted. Require exact 33-test logs, assess remaining threat scope, reconcile proposed registry/scoped-login architecture in ADRs and agree production isolation profile. Production OIDC, durable recovery authority, licence and audit protocols, dependency compatibility and branch protection are outstanding. No CRM domain code or real keys. No independent review requested as final acceptance.
