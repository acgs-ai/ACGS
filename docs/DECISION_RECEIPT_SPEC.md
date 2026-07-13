# Decision Receipt specification

This is the public contract for integrators that want to place ACGS / gove-zone before side-effectful execution.

The Decision Receipt is the **vendor-neutral evidence artifact** at the center of ACGS: a single record that binds actor, action, arguments, policy, authority, and audit anchor for one decision. Its fields carry no framework- or model-specific shape (see the schema below and `receipt.py`), so the same record format describes a governed action whether the call came from a hook host, an MCP gateway, a function-call bridge, or a custom executor — and it is the artifact a team keeps regardless of which runtime it later switches to.

> Scope note (fail closed): the *format* is vendor-neutral and implemented today. Making receipts verifiable across multiple independent agent hosts via reference validators is on the [roadmap](ROADMAP.md) ("standard receipt schema for agent runtimes"), not a current cross-host portability guarantee.

Core invariant:

> **No valid Decision Receipt, no side effect.**

## Status

Implemented locally in `packages/gove-zone/src/gove_zone/receipt.py` as `DecisionReceipt`. This is alpha (`0.1.0.dev0`) and not a compliance certification.

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
| `action_tier` | no | Policy-routing tier: `explore` or `commit`. `commit` is the strict default; unknown/missing coerces to `commit`. Bound into `receipt_hash`. Legacy receipts without it default to `commit`. |
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

For `ALLOW`, the executor hashes the arguments about to run and compares them to `argument_hash`. For `TRANSFORM`, the executed args must exactly match the approved transformed arguments.

Evidence: `tests/test_argument_binding.py`, `tests/test_executor_guard.py`.

## Policy binding

`policy_bundle_id`, `policy_version`, and `policy_hash` bind a receipt to a policy context. The gate can require expected policy id/hash and reject substitutions.

Evidence: `tests/test_policy_bundle_io.py`, `tests/test_tenant_safety.py`.

## Action tier

`action_tier` separates information-gathering (`explore`) actions from goal-executing (`commit`) actions. It is a *policy-routing* dimension — it changes which rules match, never whether the receipt gate applies. Every tier still requires a valid receipt, `expected_actor`, and an audit append; `DENY`/`ESCALATE` stay non-executable for all tiers.

The declared tier travels as untrusted input on the call (`state["action_tier"]`). A tool-tier registry is authoritative: the effective tier is `min(declared, registered)` with `commit` as the strict top value, so a tool the registry marks commit-only can never be evaluated under `explore` regardless of what the caller declares. No registry, or an unregistered tool, means `commit`. The registry is content-addressed and folds into the policy version/hash.

`action_tier` is bound into `receipt_hash`, so a post-issuance tier swap fails verification. `from_dict` defaults a missing field to `commit` (legacy compatibility). The verifier rejects unknown tier strings, and — when a registry is supplied at the gate — refuses an `explore` receipt for a commit-only tool as a belt-and-suspenders check against the policy-side evaluation. The registry is manual/declarative in v1: it is not semantic detection of whether a tool has side effects; operators must register side-effecting tools as `commit` (which is already the default).

Evidence: `decision.py` (`ActionTier`), `tier.py` (`ToolTierRegistry`), `policy.py` (rule `tiers` criterion), `receipt.py`, `tests/test_action_tiering.py`.

## Expiry

`expires_at` is optional. When set, it is bound into `receipt_hash`; expired or unparseable timestamps fail closed.

Evidence: `tests/test_receipt_expiry.py`.

## Validator identity and self-validation

The validator is distinct from the actor. `DecisionReceipt.from_record` refuses to mint self-validated receipts, and the gate refuses receipts whose validator is the invoking actor.

Evidence: `receipt.py`, `tests/test_maci_role_separation.py`.

## Signature behavior

Default local mode is unsigned: `signature_algorithm="none"`, `signature="unsigned_local"`. This is for development/local proof. It is not a production signing claim.

Opt-in signing uses Ed25519:

- signer signs `receipt_hash` with a private key;
- executor verifies with the trusted public key;
- `require_signature=True` rejects unsigned receipts;
- signed receipts presented without a verifier fail closed;
- key id and algorithm are bound into `receipt_hash` to prevent downgrade.

Evidence: `signing.py`, `tests/test_receipt_signing.py`.

## Hash behavior

`receipt_hash = sha256(canonical_json(receipt_without_receipt_hash_and_signature))`.

Changing any bound field without reissuing the receipt produces a hash mismatch. Recomputing a hash without a trusted signature is not production-grade proof; signing mode closes that residual only when engaged.

## Validation algorithm

Verifier rejects on the first failure:

1. required fields missing or empty;
2. missing or mismatched `receipt_hash`;
3. signed receipt without a configured verifier;
4. invalid signature;
5. unsigned receipt when signature is required;
6. actor mismatch or self-validation;
7. approval-chain summary disagreement;
8. unknown decision;
9. `deny` or `escalate` decision;
10. tenant mismatch;
11. execution-boundary mismatch;
12. action mismatch;
13. audit hash mismatch;
14. malformed transformations;
15. transform mismatch or extra/missing transformed args;
16. allow argument mismatch;
17. policy hash mismatch;
18. policy bundle id mismatch;
19. validator role or authority mismatch when required;
20. expired or unparseable expiry.

## Invalid receipt cases

- Missing receipt: no side effect.
- Malformed receipt: no side effect.
- `DENY`/`ESCALATE`: no side effect.
- Valid receipt for another tenant/action/actor/args/policy: no side effect.
- Expired receipt: no side effect.
- Signed receipt with unknown key or bad signature: no side effect.
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
- Use signing mode for production-adjacent pilots; do not promote unsigned local mode as production security.
- Keep direct tool implementations private behind the gate.
