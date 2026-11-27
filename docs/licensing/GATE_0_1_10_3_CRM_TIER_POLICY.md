# Proposed CRM commercial entitlement policies
Status: DRAFT ONLY; not independently approved, not submitted to issuer, not an offer or product readiness assertion.
Issuer live database observed 2026-11-27: CEPHAS_CRM active, enterprise_ai_platform. Tier defaults: pov 90 days/50 users/250000 transactions; professional 365/100/1000000; enterprise 365/500/10000000; enterprise_unlimited 365/null/null. No CRM policy or commercial review rows. Defaults are not approved contractual ceilings. Issuer POV hard bounds also include 250000 API calls, one site, one business unit and zero grace; expiry follows issuer approval workflow. No commercial pricing decisions made.

## Candidate capability mapping
All 13 registered modules and five common features are listed below. Tier rows are cumulative candidates subject to module implementation and independent approval; licence may grant a subset. No access through UI-only guards.
| Tier | Proposed module scope | Proposed features |
|---|---|---|
| POV | contact_management, account_management, lead_management, opportunity_pipeline | none by default |
| Professional | POV plus sales_automation, customer_service, workflow_automation, reporting_dashboard | api_access |
| Enterprise | Professional plus marketing_automation, ai_customer_intelligence, predictive_analytics, sales_forecasting, integration_gateway | api_access, advanced_analytics, advanced_reporting, external_integrations, multi_site |
| Enterprise Unlimited | Same capability catalogue as Enterprise, contractual scope | same as Enterprise |

## Quota proposal
| Tier | Term days (issuer defaults) | Users | Transactions | API calls | Sites | Business units |
|---|---:|---:|---:|---:|---:|---:|
| POV | 90 | 50 | 250000 | 250000 | 1 | 1 |
| Professional | 365 | 100 | 1000000 | 1000000 | 1 | 1 |
| Enterprise | 365 | 500 | 10000000 | 10000000 | 10 | 10 |
| Enterprise Unlimited | 365 | contract | contract | contract | contract | contract |

API/site/BU production values above are proposed planning ceilings, not issuer defaults. Annual licences use signed term, not hard-coded 365 days. No grace by default; any signed nonzero grace requires explicit approved policy. Null only when explicitly contract-approved for that quota; not an implicit unlimited grant. No separate record quota in current universal format. Do not introduce unrecognized signed fields or daily-reset transactions without central contract approval. Define users as active licensed human identities, sites/BU as active registered units, transactions/API calls as cumulative contract-window events with separately agreed operation definitions and idempotency; migration, renewals, count release and limits on already existing state require approval and atomic implementation. No duplicate charging and no reuse of request IDs for different operations. Draft only; all 18 mappings remain not integrated at product endpoints. No issuer policy approvals, activation or issuance bypass.
