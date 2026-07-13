# ADR: SaaS independent evidence witness build-vs-buy boundary

## Status

**Proposed — decision required.** This ADR does not assert that current audit
chains, hash manifests, exports, or any managed component are independently
witnessed, immutable, or auditor-verified.

## Date

2026-07-13

## Context

The [G006 survey](../saas/CURRENT_STATE_SURVEY.md) confirms unkeyed hash
manifests and no surveyed signed provenance or independent witness. The target
evidence plane needs a checkpoint/witness relationship so the same service
cannot silently rewrite evidence and its only trust anchor. This complements,
rather than replaces, receipt signatures, tenant isolation, object retention,
and offline proof verification.

## Proposed direction pending ratification

Define a witness-provider interface with authenticated checkpoint submission,
receipt/sequence acknowledgement, independent timestamp/identity evidence,
verification/inclusion or consistency material where supported, retry/failure
classification, and offline-verifier inputs. The target evidence record
distinguishes local chain state, object-sealing state, witness-pending state,
witness-accepted state, and verification failure. It never conflates a
self-hosted hash with an independent checkpoint.

The target must retain enough provenance to detect full self-consistent
rewrites, missing/regressed/conflicting checkpoints, and split-view behavior
within the chosen witness model. This direction is not a vendor selection,
availability promise, or external audit result.

## Decision required

**Accountable owners:** security owner and platform owner; procurement and
privacy/legal participate for third-party/witness data transfer and contract
terms.

The owners must decide:

1. witness model/provider(s), independence criteria, jurisdiction/residency,
   availability, cost, and failure behavior;
2. checkpoint cadence, tenant privacy/minimization, artifact digest format,
   key/identity requirements, and offline verification material;
3. whether multi-witness or transparency-log controls are required for the
   approved threat model;
4. recovery, prolonged outage, disputed checkpoint, revocation, and incident
   process;
5. what claims may be made only after an independent assessment.

## Safe fallback

Until approved and tested, exports describe only their proven local/hash
properties. A missing witness cannot be hidden or represented as independently
anchored evidence. Local executor enforcement remains available without a
remote witness call in the side-effect path.

## Alternatives considered

- Use only a service-local JSONL/hash chain: rejected as an independent-anchor
  substitute because the writer can control both evidence and its sole anchor.
- Call a witness synchronously before every local side effect: rejected because
  it creates a mandatory hosted dependency in the safety-critical hot path.
- Claim witness independence from provider branding alone: rejected.

## Consequences and non-goals

This ADR does not create a transparency service, WORM store, external audit,
legal attestation, availability guarantee, or compliance certification. It does
not select a witness, publish a checkpoint, or establish a retention term.

## Evidence required after approval

- witness-provider conformance, authentication, retry, outage, checkpoint
  sequence, split-view, regression, and conflicting-checkpoint tests;
- signed proof-pack/offline verifier tests covering manifest, receipt-event
  equivalence, source class/provenance, object relation, and witness material;
- privacy/minimization review of checkpoint payloads and operator incident
  runbook.

## Downstream nodes and validation after unblock

Blocked/affected nodes: G302, G303, G603, G703.

After approval, run G302/G303 evidence and offline-verification tests plus
G603 recovery tests from [DELIVERY_DAG.yaml](../saas/DELIVERY_DAG.yaml).
