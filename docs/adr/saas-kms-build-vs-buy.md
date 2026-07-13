# ADR: SaaS signing and KMS build-vs-buy boundary

## Status

**Proposed — decision required.** This ADR defines a future key-management
evaluation boundary. It does not claim a selected KMS/HSM, customer-controlled
key option, managed signing service, key custody model, or production key
rotation exists.

## Date

2026-07-13

## Context

The [G006 survey](../saas/CURRENT_STATE_SURVEY.md) establishes only local
receipt-signing evidence with configuration/profile limits. The target managed
plane requires trusted signing and verification, key IDs, rotation/revocation,
tenant/environment scope, policy/trust distribution, evidence verification,
and clear separation between data-encryption and authorization-signing keys.

## Proposed direction pending ratification

Implement a provider interface for key generation/import/reference, sign,
verify, encrypt/decrypt where appropriate, key-status lookup, rotation,
revocation, audit, and failure classification. The target key hierarchy
separates at least:

- receipt/policy signing and verification trust;
- evidence/export/checkpoint signing where required;
- tenant-scoped data-encryption keys or encryption-context references;
- bootstrap/service/gate credential material.

A target issuer/key record carries algorithm, key ID, scope, validity, trust
epoch, rotation/revocation state, and verification history. Secret key material
is never exposed to browsers, receipts, telemetry, errors, proof packs, or
billing events. This is a design contract, not a selected implementation.

## Decision required

**Accountable owners:** security owner and platform owner; procurement,
privacy/legal, and customer-key stakeholders participate for hosted or
customer-controlled key options.

The owners must decide:

1. provider(s), deployment regions, HSM/KMS requirements, availability model,
   and credential/identity integration;
2. signing algorithms, key hierarchy, tenant/environment binding, rotation,
   compromise/revocation, destruction, recovery, and audit retention rules;
3. whether and how BYOK/customer-controlled keys are supported;
4. separation of duties between platform operators, tenants, providers, and
   witness roles;
5. pricing, contractual, residency, and incident-response implications.

## Safe fallback

No managed signing or key-custody claim is made until approved and tested.
Local open verification/safety must remain available without a hosted KMS
dependency in the side-effect hot path. A provider outage cannot cause an
unsigned or unverified local allow.

## Alternatives considered

- Embed provider-specific calls in receipt/policy code: rejected; it prevents
  key-provider portability and obscures failure semantics.
- Reuse one key for signing, encryption, and credentials: rejected; it
  collapses trust domains and rotation/revocation controls.
- Treat unsigned development mode as a production substitute: rejected.

## Consequences and non-goals

This ADR does not promise HSM use, key residency, BYOK, FIPS validation,
availability, or customer-controlled custody. It does not replace tenant IAM,
PKI, or incident response.

## Evidence required after approval

- provider interface and algorithm/key-ID conformance tests;
- missing/unknown/revoked/compromised/expired key, rotation overlap, signer
  outage, scope mismatch, and cross-tenant negative tests;
- receipt/policy/evidence/export verification across key transitions;
- key-access audit, least-privilege, recovery, and runbook review.

## Downstream nodes and validation after unblock

Blocked/affected nodes: G104, G202, G301, G302, G503, G602, G603.

After approval, execute the relevant canonical receipt/executor, policy,
ingestion/proof, provider failure, and recovery commands in
[DELIVERY_DAG.yaml](../saas/DELIVERY_DAG.yaml).
