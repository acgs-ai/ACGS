# Proposed entitlement and metering matrix

**Status:** Phase-0 target beta contract (G007).

**Not an implementation claim:** This document proposes future product
boundaries. It does not assert a current billing/usage ledger, live charge,
published price, customer subscription, or production entitlement service.

## Current-state boundary

The [G006 survey](CURRENT_STATE_SURVEY.md) is the factual baseline. It found no
managed entitlement catalogue, accepted-evidence usage ledger, billing-provider
integration, checkout, invoice, or live payment workflow. The current local
runtime and proof limits remain governed by [CLAIMS.md](../CLAIMS.md) and
[SECURITY_MODEL.md](../SECURITY_MODEL.md); [ROADMAP.md](../ROADMAP.md) is the
sole roadmap of record.

## Target beta contract

| Offering | Intended value boundary | Local-safety boundary | Evidence needed before it can be offered |
|---|---|---|---|
| Community | Complete local kernel/gateway, verifier, signing, anti-replay, local audit/replay, proof packs, CLI, conformance tests, and basic community control-plane capability. | Never disables local signing, verification, anti-replay, receipt enforcement, or proof verification. | Local conformance and claim-safe capability evidence. |
| Design Partner | A bounded paid real integration, deployment guidance, and a measured review outcome. | The integration must preserve the Community safety surface; no customer result is implied by this proposal. | Explicit owner approval, customer agreement, real integration evidence, and independently reviewed outcome. |
| Managed Team | Hosted evidence retention, limited fleet status, collaboration, basic alerts, and self-service operations. | Hosted limits or outages must not authorize a local side effect or turn the local gate into a remote dependency. | G203-G206 evidence-plane, G401-G404 console, and G501-G503 entitlement evidence. |
| Enterprise | Fleet, policy, approval, evidence operations, identity federation, SIEM/webhooks, longer retention, support, and private-deployment guidance. | A plan change, suspension, entitlement error, or billing outage cannot weaken the local executor. | Implemented authorization, retention, export, identity, and operational evidence with owner-approved terms. |
| Private / Regulated | Enterprise capabilities plus customer-controlled deployment/key/storage options, data-residency planning, evidence-operation runbooks, and audit support. | Does not claim certification, regulatory approval, or replace customer controls. | Owner/counsel decisions, deployment-specific validation, and customer-approved operational scope. |

### Proposed usage dimensions

The target ledger measures active **proven-wired production workloads or
environments**, accepted evidence bytes, retention duration, and premium
operations. It must not charge for local authorization calls or model tokens.
Usage records must be derived from accepted, provenance-labelled evidence and
reconciled to the customer-visible total. Observed evidence must not be metered
as a verified governed action; assurance class and verification result remain
visible in the usage provenance.

### Safety and failure boundaries

Entitlements are a future server-side policy, never only a UI condition. They
may limit hosted retention or optional hosted operations, but they must never
disable local signing, verification, anti-replay, audit/replay, or proof-pack
verification. If a configured high-risk evidence obligation cannot be buffered
within its bounded local spool rule, the path fails closed; required evidence
must not be silently discarded. Billing, subscription, or provider-webhook
failure cannot create allow-by-default behavior or remove the Community safety
surface.

No real charges, published pricing, legal commitments, license changes, or
commercial-only module boundary are authorized by this document. Those require
the G008 commercial-boundary ADR plus explicit owner and counsel review.

## Evidence and next gate

G501-G503 must implement and independently test a server-side entitlement
catalogue, immutable accepted-evidence usage ledger, reconciliation, and
billing-provider adapter in test mode. G203-G206 must first establish accepted
evidence and its assurance provenance. Until those gates pass, this is a target
contract only.
