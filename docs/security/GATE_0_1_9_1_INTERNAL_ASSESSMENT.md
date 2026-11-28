# Gate 0.1.9.1 — Internal assessment and evidence register
Status: not accepted; internal hardening only. Parent c59d2ef72e291b73e1ff7cb41c9265b245244e64.
Baseline Run #10 (45955688115) 12/12 tests passed on PostgreSQL 18.7, 34.337s, merge SHA 00177e6931085c7f5610d89aab778b59792cb460. Source head and merge SHA distinct. New evidence must be collected separately.

| ID | Internal finding | Risk | Remediation/disposition |
|---|---|---|---|
| I01 | Issuer accepts arbitrary tuple without live target validation | High | Check runtime backend identity, DB and low XID; full xid8 verifier; end-to-end trusted broker remains critical blocker |
| I02 | Epoch change permits duplicate live transaction binding | Critical | Exclude epoch from unique key; negative test cross-scope rebind |
| I03 | Pooled session may retain held cursors and prepared state | Critical | Trusted reset proof; production pool and failure/cancellation handling still open |
| I04 | Mutable image tag undermines reproducibility | High | Pin observed image digest; record evidence and reject override |
| I05 | Restart not exercised | High | Actual container restart test; full restore and anti-rollback still open |
| I06 | Shared runtime login can expose SQL/session side channels | High | Test known stats and role grants; inventory other functions/NOTIFY and consider dedicated scope role design |
| I07 | User/actor-to-pinned-connection binding unproven | Critical | No closure; design and implement trusted broker with no caller-supplied tuple |
| I08 | Licence, audit, OIDC and CI locks beyond isolated proof | High | Original blockers remain open |

Independent review not requested as final acceptance. Verify all 19 tests, exact head, merge tree, role grants, image digest and no skipped cases. Do not infer security acceptance from green CI. Proposed internal next step: trusted broker/lease design, shared-login channel threat inventory, full restore/rollback proof and consolidated evidence. No CRM domain feature implementation authorised.
