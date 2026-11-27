# Gate 0.1.9.2 — Trusted broker and scope-role proof
Status: experimental, not accepted. Parent 80dc1626fe55a3406963e250ae3eec927798b753.
Verified prior evidence: Run #11 45955998900; 19/19, 35.500 seconds; PostgreSQL 18.7; merge SHA 3444144b411963477063a0adf250c08c1758ad55. New changes need separate evidence.

| Finding | Proposed remediation | Residual |
|---|---|---|
| I07 actor to connection binding | Broker derives tuple from fresh privately held session after synthetic credential authentication; no caller raw tuple or SQL | trusted process and issuer; OIDC/service boundary and same-scope actor misuse not proven |
| I06 shared login query/session exposure | distinct tenant/BU login and explicit DB scope mapping, no broker use of legacy shared role | global PostgreSQL channels, signalling, errors, timing, locks and catalog noninterference not proven |
| I03 session reuse | no reuse in broker proof; dispose on success/failure | cancellation, crash/cleanup and production pool remain open |
| I05 restart/restore | prior restart test passed | full restore/failover and epoch custody still open |

Seven additional tests cover valid authenticated operations across four scopes, credential and operation denial, caller tuple injection, membership revocation, session disposal, scope-role foreign issuance and privilege restrictions. Exact suite 26, no skips. No CRM domain features, production key material or acceptance. Architecture approval, isolation decision for stricter customer threat models, cancellation/restore, licence/audit/identity and dependency compatibility remain open. Do not use green CI to close all C-01–C-09. Next: test cancellation and restore with new connection/epoch, address side channels with documented threat scope, finalise reviewable architecture decision and remaining blockers.
