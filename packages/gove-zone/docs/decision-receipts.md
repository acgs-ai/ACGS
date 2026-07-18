# Decision Receipts

> Status: `1.0.0rc1` / Beta source metadata, with candidate release
> reconciliation still required. This document describes implemented behavior;
> it is not release, deployment, or certification evidence.

A `DecisionReceipt` is the public proof-of-decision artifact used by the
governed executor. It records every completed governance result, including
`DENY` and `ESCALATE`; only a receipt carrying an executable verdict and
passing the full governed gate may authorize a side effect.

> **No valid Decision Receipt, no side effect.**

## Lifecycle and ordering

For an execution path integrated through the governed kernel:

1. the caller proposes an action and externally authenticated actor context;
2. policy produces `ALLOW`, `DENY`, `TRANSFORM`, or `ESCALATE`, with
   policy failures converted to a fail-closed decision;
3. the audit event is appended before execution;
4. the receipt is issued and bound to that event;
5. the governed executor validates the receipt against caller-supplied expected
   context; and
6. only a valid `ALLOW` or `TRANSFORM` reaches the side effect.

If policy evaluation, audit append, issuance, or gate validation cannot
complete, no side effect runs. Denied and escalated receipts remain audit
evidence; they never authorize execution.

## Implemented schema

The frozen dataclass is implemented in
`src/gove_zone/receipt.py::DecisionReceipt`. Canonical hashing covers every
security-relevant field except the signature value itself; the signature, when
present, signs `receipt_hash`.

| Field group | Fields | Purpose |
|---|---|---|
| Identity and correlation | `receipt_id`, `request_id`, `tenant_id` | Identify the receipt, originating request, and tenant. |
| Proposed context | `actor`, `subject`, `proposed_action`, `declared_goal`, `execution_boundary` | Bind the proposer, action, intent, subject, and allowed execution boundary. |
| Policy evidence | `policy_bundle_id`, `policy_version`, `policy_hash`, `matched_rules`, `constraints` | Identify the policy and evidence that produced the result. |
| Decision | `decision`, `transformations`, `approval_chain_summary` | Record the four-way verdict and any approved transformation or approval summary. |
| Authority separation | `authority`, `validator_id`, `validator_role` | Bind the distinct validator and authority grant; self-validation is rejected. |
| Argument and time binding | `argument_hash`, `timestamp`, `expires_at` | Bind exact proposed arguments and optional expiry. |
| Audit anchors | `previous_audit_hash`, `audit_event_hash` | Tie the receipt to the pre-execution audit chain. |
| Integrity and signing | `receipt_hash`, `signature_algorithm`, `signing_key_id`, `signature` | Detect field changes and optionally authenticate the issuer with Ed25519. |

An unsigned receipt uses `signature_algorithm="none"`, an empty
`signing_key_id`, and `signature="unsigned_local"`. This is implemented
development behavior, not the secure gate default.

## Issuance and signature defaults

Issuance and verification have different defaults:

- `DecisionReceipt.from_record(..., signer=None)` issues an unsigned receipt
  unless the caller explicitly supplies a private-key signer.
- The governed execution surfaces—`execute_with_receipt`,
  `GovernedExecutor`, and `contracts.ReceiptVerifier`—require trusted
  signature verification by default. They do not generate a key, sign a receipt,
  or trust a verifier automatically; missing secure configuration fails closed.
- Bare `DecisionReceipt.verify()` is a low-level primitive. Its
  `require_signature` and expected-context parameters are optional, so it is
  not a complete authorization boundary and should not be used by itself to
  release a side effect.

A receipt that advertises a signature is always verified when presented to the
gate. Missing verifiers, unknown keys, algorithm mismatches, revoked signing
keys, and invalid signatures are hard failures.

## Governed verification

The governed wrappers supply and enforce the expected execution context. The
gate rejects, among other cases:

- missing required fields or a changed `receipt_hash`;
- `DENY`, `ESCALATE`, or an unknown decision;
- actor/self-validation, tenant, boundary, action, argument, policy, validator,
  authority, or audit-anchor mismatch;
- malformed or incorrectly applied transformations;
- an expired receipt, or a missing expiry when the strict profile requires one;
- an unsigned receipt when a signature is required; and
- a signed receipt whose key is unknown, revoked, or fails verification.

These guarantees apply only to paths wired through the governed executor with
trusted expected context. The library cannot intercept a direct call to a raw
tool that an integrator exposes outside the gate.

## Revocation scope

`gove_zone.revocation.RevocationList` is an implemented, operator-supplied
static set of revoked receipt-signing key IDs. When passed to supported live
gates and offline verifiers, a matching signed receipt is rejected before its
signature is trusted, even if the verifier map still contains the key.

The list is off by default and intentionally narrow. The package does not
provide PKI, key custody, automatic distribution or rotation, CRL fetching,
global receipt/nonce revocation, or revocation for every workflow/plan key
population.

## Replay scope

Receipt and replay evidence support two different levels:

- **Audit-only verification** checks chain/event integrity and policy-version
  consistency. Because the audit deliberately stores `argument_hash` rather
  than raw arguments, it cannot re-run policy or claim that the original
  decision was reproduced.
- **Decision re-derivation** requires the opt-in raw-call
  `ReplaySideStore` and the matching original policy bundle.
  `replay_from_side_store` and `replay_bundle` cross-check retained arguments
  against the audit hash before re-running policy. Missing or redacted side
  records degrade honestly to the audit-only level.

External expected event counts or final hashes are also required when detecting
a consistently truncated audit suffix matters.

## Related source documentation

- `governed-execution.md` — end-to-end gate placement.
- `audit-evidence.md` — audit ordering and chain limitations.
- `../SECURITY.md` — threat model, signing, revocation, and deployment duties.
- `../../../docs/DECISION_RECEIPT_SPEC.md` — repository-level public contract.
- `../examples/receipt-gated-execution/demo.py` — runnable signed proof.
