# ADR: SaaS entitlement, metering, and billing build-vs-buy boundary

## Status

**Proposed — decision required.** This ADR does not select a billing provider,
set prices, create a subscription, activate a real charge, make a tax/legal
commitment, or claim a billing/usage implementation.

## Date

2026-07-13

## Context

The [G007 entitlement and metering matrix](../saas/ENTITLEMENT_AND_METERING_MATRIX.md)
sets a target boundary: hosted value may be metered, but open local safety
cannot be disabled by entitlement, billing, retention, account, or hosted
failure. The [G006 survey](../saas/CURRENT_STATE_SURVEY.md) does not provide an
accepted hosted usage ledger, billing integration, or evidence-derived usage
path.

## Proposed direction pending ratification

A future server-side entitlement service owns plan/limit/grace state separately
from UI conditionals. Its immutable usage ledger derives governed-workload and
evidence-volume measures from accepted, provenance-labelled evidence records
with reconciliation to source event IDs. It does not charge for local
authorization calls or model tokens. Observed evidence is not metered as a
verified governed action.

A future billing-provider adapter may operate in test mode only until finance,
owner, and legal approvals exist. Billing webhooks require signature
verification, idempotency/replay protection, secret rotation, delivery
evidence, and reconciliation. Entitlement/billing mutations follow the
canonical governed administrative transaction path.

## Decision required

**Accountable owners:** product owner and finance owner; legal, privacy,
security, procurement, and tax stakeholders participate as applicable.

The owners must decide:

1. packaging, price publication, free/grace/suspension behavior, currencies,
   taxes, invoicing, and contractual terms;
2. billing provider, test/live environment controls, data flows, webhook
   identity, reconciliation, and support/refund/dispute process;
3. permitted evidence-derived usage dimensions, aggregation, retention,
   privacy/minimization, and customer-visible reconciliation rules;
4. hosted limits/retention behavior that never weakens local enforcement or
   silently drops required evidence;
5. launch authorization and customer communication process.

## Safe fallback

No real charges, checkout, billing portal, price, or commercial promise is
enabled. A hosted entitlement failure may limit hosted features only through
the approved behavior; it cannot disable local signing, verification,
anti-replay, fail-closed execution, local audit/replay, proof verification, or
required evidence handling.

## Alternatives considered

- Meter local authorization calls or model tokens: rejected; it creates an
  incentive to omit governance/evidence and violates the target business model.
- Enforce plans only in the UI: rejected; server-side rules are required.
- Let payment failure permit ungoverned execution or erase evidence: rejected.

## Consequences and non-goals

This ADR is not a pricing page, revenue claim, payment launch, tax advice, or
commercial agreement. It does not make the local gate a paid feature.

## Evidence required after approval

- server entitlement, immutable usage-ledger, evidence-source reconciliation,
  plan/grace/suspension, and governed-admin event tests;
- billing-adapter test-mode webhook signature, replay, idempotency, rotation,
  failure, and reconciliation tests;
- negative proof that hosted/billing failure cannot weaken or disable local
  safety or silently discard required evidence;
- finance/legal/privacy/security review and test-mode operational runbook.

## Downstream nodes and validation after unblock

Blocked/affected nodes: G502, G503, G606, G704.

After approval, run G502/G503 entitlement and billing test-mode validation and
the relevant G606 operations checks in
[DELIVERY_DAG.yaml](../saas/DELIVERY_DAG.yaml).
