# Decision Receipt specification

This is the public contract for integrators that want to place ACGS / gove-zone before side-effectful execution.

The Decision Receipt is the **vendor-neutral evidence artifact** at the center of ACGS: a single record that binds actor, action, arguments, policy, authority, and audit anchor for one decision. Its fields carry no framework- or model-specific shape (see the schema below and `receipt.py`), so the same record format describes a governed action whether the call came from a hook host, an MCP gateway, a function-call bridge, or a custom executor — and it is the artifact a team keeps regardless of which runtime it later switches to.

> Scope note (fail closed): the *format* is vendor-neutral and implemented today. Making receipts verifiable across multiple independent agent hosts via reference validators is on the [roadmap](ROADMAP.md) ("standard receipt schema for agent runtimes"), not a current cross-host portability guarantee.

Core invariant:

> **No valid Decision Receipt, no side effect.**

## Status

Implemented locally in `packages/gove-zone/src/gove_zone/receipt.py` as
`DecisionReceipt`. Current source metadata is `1.0.0rc1` / Beta, with release
reconciliation still required; this is not a compliance certification.

## Schema

| Field | Required | Binding role |
|---|---:|---|
| `receipt_id` | yes | Unique receipt/event id. |
| `request_id` | yes | Caller correlation id. |
| `tenant_id` | yes | Tenant boundary; cross-tenant reuse fails. |
| `actor` | yes | Principal proposing the action. |
| `subject` | no | Optional resource/person/object label. |
| `proposed_action` | yes | Tool/action name. |
| `declared_goal` | yes | Human-readable intent. |
| `execution_boundary` | yes | Boundary where execution is allowed. |
| `policy_bundle_id` | yes | Stable policy bundle id. |
| `policy_version` | yes | Policy version string. |
| `policy_hash` | yes | Policy content/version hash binding. |
| `decision` | yes | `allow`, `deny`, `transform`, or `escalate`. Only `allow` and approved `transform` can execute. |
| `matched_rules` | yes | Rule ids or policy reasons that fired. |
| `constraints` | yes | Free-form decision constraints. |
| `transformations` | yes | Approved transformed args as `{field, value}` entries. Empty for non-transform. |
| `approval_chain_summary` | yes | Proposer/validator/authority linkage. |
| `timestamp` | yes | ISO-8601 issuance time. |
| `expires_at` | no | ISO-8601 expiry. Empty means no expiry. Bound into hash. |
| `authority` | yes | Authority grant used by validator. |
| `validator_id` | yes | Principal validating the action. Must differ from actor/caller. |
| `validator_role` | yes | Validator role. |
| `argument_hash` | yes | SHA-256 over canonical JSON args. |
| `previous_audit_hash` | yes | Previous hash-chain head. |
| `audit_event_hash` | yes | Audit event hash anchoring this decision. |
| `signature_algorithm` | yes | `none` or `ed25519`. Bound into receipt hash. |
| `signing_key_id` | yes | Key id for signature verification. Bound into receipt hash. |
| `receipt_hash` | yes | SHA-256 over canonical receipt JSON except `receipt_hash` and `signature`. |
| `signature` | yes | `unsigned_local` or signature over `receipt_hash`. |

## Actor binding

The receipt's `actor` is the proposer. The executor must supply `expected_actor` from trusted runtime context. The verifier rejects a receipt issued for a different actor and rejects a receipt where the invoking principal is also the validator.

Evidence: `receipt.py`, `executor.py`, `contracts.py`, `tests/test_maci_role_separation.py`, `tests/test_executor_guard.py`.

## Action binding

`proposed_action` must match the action about to execute. A receipt for `runtime.file.write` cannot authorize `runtime.shell.run`.

Evidence: `tests/test_decision_receipt.py`, `tests/test_executor_guard.py`.

## Argument binding

For `ALLOW`, `DENY`, and `ESCALATE`, the executor hashes the arguments presented at the gate and compares them to `argument_hash`. `DENY` and `ESCALATE` still cannot authorize execution, but malformed or wrongly-bound non-ALLOW receipts are rejected for the first integrity, trust, liveness, or binding failure before the final non-executable decision refusal. For `TRANSFORM`, the executed args must exactly match the approved transformed arguments.

Evidence: `tests/test_argument_binding.py`, `tests/test_executor_guard.py`,
`tests/test_trust_receipt_v2.py`.

## Policy binding

`policy_bundle_id`, `policy_version`, and `policy_hash` bind a receipt to a policy context. The gate can require expected policy id/hash and reject substitutions.

Evidence: `tests/test_policy_bundle_io.py`, `tests/test_tenant_safety.py`.

## Managed control-plane native receipts

The SaaS control-plane worktree has one current canonical native route:
agent creation through `POST /orgs/{org_id}/agents` and its additive `/v1`
alias. That route mints a signed native `DecisionReceipt` for `ALLOW`, `DENY`,
and `ESCALATE` decisions with:

- explicit, distinct receipt issuer and consumption-attestation providers;
- an environment-bound full policy hash;
- project/environment scope carried through the governed event path;
- `DENY` and `ESCALATE` recorded as non-executable native evidence with no
  receipt consumption; and
- `ALLOW` execution, DB mutation, native receipt row, governance event/head,
  outbox row, signed consumption attestation, and signed terminal idempotency
  result inside one rollbackable SQL transaction.

The same route now requires exactly one bounded `Idempotency-Key` and stores a
durable result row for terminal `ALLOW`, `DENY`, and `ESCALATE` decisions. The
row stores digest-only key, request, and response evidence plus receipt/event
references; it does not store the raw transport key or a raw response body.
Replay reconstructs the semantic response from authoritative rows and verifies
the signed result artifact and native evidence chain before returning it. A
same key with a different request digest returns a conflict without a second
mutation, receipt, event, outbox row, or idempotency result. PostgreSQL
serializes this path through a tenant row lock; SQLite coverage is limited to
same-process locking.

This is route-level evidence, not a full control-plane cutover. Twelve legacy
unsigned write aliases remain and still block production posture. Native scope
is hash-bound through the event path, not represented as direct
project/environment columns on the receipt schema. SQL rollback and durable
agent-create replay do not prove external exactly-once delivery, and
export/offline verification requires trusted public keys supplied out of band.
No other mutating route, async export/recovery path, rolling-upgrade path, or
production deployment is claimed by this slice.

Evidence:
`packages/acgs-control-plane/tests/test_native_agent_transaction_route.py`,
`packages/acgs-control-plane/tests/test_agent_create_idempotency.py`,
`packages/acgs-control-plane/tests/test_exports.py`, PR #370 commit
`feaabd96ccb68a076f39cc46fe5a7d906e0a9a5f`, and PR #371 commit
`e0f514f2963987f72827d33ada891abc08677f03`.

## Expiry

`expires_at` is optional for legacy receipts unless a strict profile requires
expiry. Receipt-v2 requires `expires_at`. When set, `expires_at` is bound into
`receipt_hash`; expired or unparseable timestamps fail closed.

For signed receipts and receipt-v2, `timestamp` is also part of the liveness
window. The verifier accepts only:

```text
timestamp - max_clock_skew_seconds <= verification_time <= expires_at
```

The default skew is 300 seconds, and the maximum accepted skew is also 300
seconds. Callers may tighten the bound to any integer from 0 through 300, but
may not widen it beyond the default. A bool, non-integer, negative value, or
value greater than 300 fails closed as `EXPIRY_UNPARSEABLE` before receipt
verification, consumption-ledger burn, or tool execution. A receipt issued
farther in the verifier's future than the accepted skew, or a receipt whose
`expires_at` is before `timestamp`, fails as `RECEIPT_EXPIRED` before any
consumption-ledger burn or side effect. Gate wrappers (`execute_with_receipt`,
`GovernedExecutor`, and `ReceiptVerifier`) thread the same bounded skew, and
callers may override it per verifier or per executor only to tighten it.

The managed control plane's tenant-bootstrap canonical managed-mutation unit of
work pins `DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS`, currently 300 seconds, when it
verifies the receipt before SQL mutation.

Evidence: `tests/test_receipt_expiry.py`,
`tests/test_trust_receipt_v2.py`,
`packages/acgs-control-plane/src/acgs_control_plane/managed_mutations.py`.

## Validator identity and self-validation

The validator is distinct from the actor. `DecisionReceipt.from_record` refuses to mint self-validated receipts, and the gate refuses receipts whose validator is the invoking actor.

Evidence: `receipt.py`, `tests/test_maci_role_separation.py`.

## Signature behavior

Low-level issuance is unsigned unless the caller supplies a signer:
`signature_algorithm="none"`, `signature="unsigned_local"`. Governed execution
gates separately require trusted signature verification by default. They do not
create a key or trust a verifier automatically; without a configured trusted
verifier, the governed path fails before the side effect. Unsigned operation is
an explicit development opt-out, not a production signing claim.

Configured signed issuance uses Ed25519:

- signer signs `receipt_hash` with a private key;
- executor verifies with the trusted public key;
- `require_signature=True` rejects unsigned receipts;
- signed receipts presented without a verifier fail closed;
- receipts signed by a key ID in an operator-supplied `RevocationList` fail
  closed on supported live and offline verification paths; and
- key id and algorithm are bound into `receipt_hash` to prevent downgrade.

The static signing-key revocation list is off by default and deliberately
narrow. It is not PKI, automatic distribution/rotation, per-receipt or nonce
revocation, or coverage for every workflow/plan key population.

Evidence: `signing.py`, `revocation.py`, `tests/test_receipt_signing.py`,
`tests/test_revocation.py`.

## Scoped trust purpose

Receipt-v2 trust is scoped by tenant, project, environment, and purpose. The
default public decision-receipt purpose is `decision-receipt`; callers with a
separate trust domain may pass `trust_purpose` to `DecisionReceipt.verify`,
`execute_with_receipt`, `GovernedExecutor`, or `ReceiptVerifier`. Empty purpose
values fail closed.

A trusted key for one purpose does not verify a receipt for another purpose.
Purpose mismatch, untrusted key, revoked key, expired trust key, or unavailable
scoped trust registry fails closed before any consumption-ledger burn or side
effect. The managed tenant-bootstrap route uses a separate purpose:
`acgs.platform-bootstrap.receipt.v1`.

Evidence: `receipt.py`, `executor.py`, `contracts.py`,
`tests/test_trust_receipt_v2.py`,
`packages/acgs-control-plane/src/acgs_control_plane/tenant_bootstrap.py`,
`packages/acgs-control-plane/tests/integration/test_tenant_bootstrap_vertical.py`.

## Hash behavior

`receipt_hash = sha256(canonical_json(receipt_without_receipt_hash_and_signature))`.

Changing any bound field without reissuing the receipt produces a hash mismatch. Recomputing a hash without a trusted signature is not production-grade proof; signing mode closes that residual only when engaged.

## Validation algorithm

Verifier rejects on the first failure:

1. required fields missing or empty;
2. missing or mismatched `receipt_hash`;
3. unsupported or improperly scoped receipt-v2 fields;
4. signed receipt without a configured verifier or scoped trust registry;
5. invalid signature or scoped trust-key mismatch;
6. receipt-signing key ID present in a supplied static revocation list;
7. unsigned receipt when signature is required;
8. actor mismatch or self-validation;
9. approval-chain summary disagreement;
10. unknown decision;
11. tenant mismatch;
12. execution-boundary mismatch;
13. action mismatch;
14. audit hash mismatch;
15. malformed transformations;
16. transform mismatch or extra/missing transformed args;
17. allow/deny/escalate argument mismatch;
18. policy hash mismatch;
19. policy bundle id mismatch;
20. validator role or authority mismatch when required;
21. invalid skew configuration (`bool`, non-integer, negative, or greater than
    300), missing expiry when required, not-yet-valid issuance beyond bounded
    skew, expired receipt, expiry-before-issuance, or unparseable expiry;
22. fully-bound `deny` or `escalate` decision.

## Invalid receipt cases

- Missing receipt: no side effect.
- Malformed receipt: no side effect.
- `DENY`/`ESCALATE`: no side effect.
- Valid receipt for another tenant/action/actor/args/policy: no side effect.
- Expired receipt: no side effect.
- Bool, non-integer, negative, or greater-than-300 `max_clock_skew_seconds`: no
  verification, ledger burn, or side effect.
- Signed or receipt-v2 receipt issued too far in the verifier's future: no side
  effect.
- Receipt whose expiry predates issuance: no side effect.
- Signed receipt with an unknown, revoked, or invalid key/signature: no side
  effect.
- Unsigned receipt when `require_signature=True`: no side effect.

## Minimal valid receipt example

Illustrative only; use the Python API to mint hashes correctly.

```json
{
  "receipt_id": "ev_abc123",
  "request_id": "req-1",
  "tenant_id": "tenant-A",
  "actor": "agent-1",
  "subject": "",
  "proposed_action": "runtime.file.write",
  "declared_goal": "write approved evidence",
  "execution_boundary": "local-sandbox",
  "policy_bundle_id": "policy-A",
  "policy_version": "policy-A/v1",
  "policy_hash": "policy-hash",
  "decision": "allow",
  "matched_rules": [],
  "constraints": {},
  "transformations": [],
  "approval_chain_summary": {"proposer": "agent-1", "validator_id": "constitutional-council", "authority": "tenant-A/write-grant"},
  "timestamp": "2026-06-06T00:00:00+00:00",
  "expires_at": "",
  "authority": "tenant-A/write-grant",
  "validator_id": "constitutional-council",
  "validator_role": "validator",
  "argument_hash": "sha256-of-canonical-args",
  "previous_audit_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "audit_event_hash": "audit-event-hash",
  "signature_algorithm": "none",
  "signing_key_id": "",
  "receipt_hash": "computed-receipt-hash",
  "signature": "unsigned_local"
}
```

## Invalid example: argument substitution

A receipt issued for:

```json
{"path":"/tmp/safe.txt","content":"ok"}
```

must not authorize:

```json
{"path":"/etc/shadow","content":"pwned"}
```

`execute_with_receipt(..., expected_args=about_to_run_args)` catches this with `argument mismatch`.

## Compatibility guidance for external runtimes

- Treat the receipt as a narrow authorization for one actor/action/argument/policy context.
- Store receipts with audit anchors; do not store only model text.
- Always verify at the executor boundary, not only in a planner or prompt.
- Pass `expected_actor`, `expected_action`, `expected_args`, tenant, boundary, and policy expectations from runtime context.
- Configure explicit signed issuance plus the matching trusted verifier for
  production-adjacent pilots; do not promote unsigned local mode as production
  security.
- Keep direct tool implementations private behind the gate.
