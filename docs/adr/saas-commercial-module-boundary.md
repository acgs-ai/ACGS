# ADR: SaaS commercial-module and licensing boundary

## Status

**Proposed — decision required.** This ADR does not change a license, create a
commercial-only module, make an open-core commitment, publish a price, or offer
a customer contract.

## Date

2026-07-13

## Context

Existing Apache-2.0 code cannot be retroactively represented as an exclusive
paid feature boundary. The [G007 open-core and local-safety contract](../saas/OPEN_CORE_BOUNDARY.md)
requires complete local authorization safety to remain available without a
hosted entitlement or billing dependency. The repository has no owner/counsel
approved commercial-module or licensing decision in this Phase-0 record.

## Proposed direction pending ratification

Keep the local execution/data-plane safety properties open: local policy
evaluation, receipt signing and verification, anti-replay/single-use,
fail-closed execution, local audit/replay, proof-pack/offline verification,
CLI, and conformance tests. Any future hosted commercial value must be
separable operational/service value such as managed fleet, policy, evidence,
retention, collaboration, integrations, support, deployment guidance, or
private deployment assistance. It may not be a hidden bypass, mandatory remote
authorization dependency, or retrospective restriction on already Apache-2.0
code.

A proposed commercial module must have a separately reviewable repository
boundary, dependency direction, data-flow/threat model, entitlement behavior,
license inventory, SBOM/provenance obligations, and customer/support owner.
This is a proposed evaluation rule, not a decision to create such a module.

## Decision required

**Accountable owners:** repository/product owner and legal counsel; security,
procurement, finance, and open-source community stakeholders participate where
applicable.

Before adding a commercial-only module, owners must decide:

1. whether a module is needed at all, its repository/package boundary, and why
   a hosted service or support model is insufficient;
2. license compatibility, copyright/notice obligations, contributor process,
   dependency/SBOM/provenance requirements, and release/distribution plan;
3. entitlement, private/BYOC/on-premise, support, data residency, and security
   boundaries;
4. contractual claims, price/packaging, customer commitments, and launch
   authorization;
5. migration/compatibility behavior for existing Apache-2.0 users and proof
   that no open safety property is gated.

## Safe fallback

Do not add a commercial-only module, license change, price, contract, or
customer commitment. Continue to keep the local safety plane available without
hosted authorization, billing, or entitlement. Do not describe a proposed
boundary as an approved open-core model.

## Alternatives considered

- Make local signing, verification, anti-replay, fail-closed execution, or
  proof verification paid-only: rejected; it weakens the stated open safety
  boundary and cannot retroactively restrict Apache-2.0 code.
- Use a hidden feature flag to make a hosted outage permit local effects:
  rejected; it violates the core receipt-gated invariant.
- Create an unreviewed proprietary fork: rejected pending legal/security/
  community review and a separable value proposition.

## Consequences and non-goals

This ADR is not a legal opinion, license change, commercial offer, private
deployment promise, certification, or revenue claim. It does not resolve
future contributor, trademark, contractual, or jurisdictional questions.

## Evidence required after approval

- owner/counsel-approved ADR and license/dependency inventory;
- separate module/service threat model, data-flow, entitlement, and
  compatibility review;
- tests proving hosted/entitlement/billing failure cannot affect local safety;
- release/SBOM/provenance and support/incident documentation appropriate to the
  approved boundary.

## Downstream nodes and validation after unblock

Blocked/affected nodes: G502, G503, G606, G704.

After approval, validate the affected package/license inventory and run the
entitlement/local-safety regression suite identified in
[DELIVERY_DAG.yaml](../saas/DELIVERY_DAG.yaml).
