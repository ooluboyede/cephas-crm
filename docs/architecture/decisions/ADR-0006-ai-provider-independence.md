# ADR-0006: Provider-Independent and Permission-Bound AI

**Status:** Proposed — pending approval  
**Date:** 2026-11-25

## Context
AI capabilities may use different model providers or customer-hosted models. CRM data is sensitive and must remain under customer control.

## Decision
Implement AI through provider adapters behind a stable internal interface. Support configurable external and customer-hosted model endpoints where feasible. AI retrieval and tool execution enforce the same tenant, business-unit, role and record permissions as ordinary CRM operations.

Default to no external transmission of customer CRM data. External provider use must be explicitly configured by the customer, disclosed, auditable and governed by data minimisation and contractual controls. Record provider, model, policy outcome and tool actions without unnecessarily logging sensitive prompts or records.

AI may recommend, summarise, classify and draft. Consequential actions—such as changing customer records, issuing refunds or sending external communications—require explicit human approval unless a separately approved policy grants narrowly scoped automation.

## Alternatives
- Hard dependency on one model vendor: rejected.
- Unrestricted AI access to CRM records: rejected.
- Autonomous consequential actions by default: rejected.

## Consequences
- Prompt injection and untrusted document handling need dedicated controls.
- Permission filters apply before content reaches a model.
- Provider-specific features stay outside core domain modules.
- Model/version changes require evaluation and regression testing.

## Acceptance checks
- Permission-denied records never enter model context.
- Default deployment makes no unauthorised outbound AI calls.
- AI tool actions are scoped, audited and approval-gated.
- Provider outage and fallback behaviour is documented.
