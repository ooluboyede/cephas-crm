# Gate 0.1.9.4 — Durable state and architecture consolidation
Status: experimental; not accepted. Parent 35663c9917e5a0bd2276ca4586f5de98042a44aa.
Verified baseline: Run #13 45965466872, 33/33 passed, 46.861s, PostgreSQL 18.7, merge SHA c6dff38930e9b8bccc18593abe8f8e85f5b3dbcb. New suite expects 39 tests; new CI required.

## Implemented
Separate external SQLite recovery journal with explicit exclusive initialization, transactional compare-and-append, unique epochs, read-only broker access, synchronous durability and no automatic database adoption. Broker pins sequence and epoch and checks state at operation entry and before result release. Tests cover broker reconstruction, unavailable/corrupt journal, stale compare-and-append and epoch reuse, concurrent operator advancement, old broker/database mismatch and recovery change during read. ADR-0009 captures current experimental direction without marking accepted.

## Limits and residuals
SQLite journal is an independent file from the CRM database, NOT an independent protected operational trust domain. Trusted private directory, correct filesystem semantics and operator custody are assumed; no separate OS identities or durable external anti-rollback mechanism demonstrated. File snapshot rollback, deletion/reinitialization by privileged operator, simultaneous rollback of both stores, full cluster restore/PITR, rollback within unchanged epoch, crash/power-loss tests and atomic release/recovery coordination remain unproven. Rechecking state cannot revoke already disclosed data or guarantee no race after final check. Broker startup must use trusted operator state, never copy epoch from an unverified restored DB; synthetic fixture bootstrap is not a production workflow. No production OIDC, licence, audit anchoring, dependency locks beyond proof image, or actual branch protection acceptance. Same database side channels remain explicit risks.

## Decision
Internal assessment remains open. No final independent handoff or Gate 0.2 authorisation. Review evidence should distinguish verified row-isolation experiment from pending production security architecture. Next: validate new exact CI, establish production recovery/identity/audit/licensing design and assess strict isolation profile and repository enforcement. Consolidate outstanding findings rather than treating increased test counts as closure.
