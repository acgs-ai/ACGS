# Security model and threat table

Core invariant:

> **No valid Decision Receipt, no side effect.**

Status: alpha/local proof. This document is a threat model, not a certification claim.

## Threat table

| Threat | Risk | Current protection | Test coverage / demo | Remaining limitation | Roadmap item |
|---|---|---|---|---|---|
| Missing receipt | Executor runs a side effect with no authorization evidence. | `execute_with_receipt`, `GovernedExecutor`, and `ReceiptVerifier` reject `None`. | `test_executor_refuses_no_receipt`, `gove-zone proofpack`, `examples/tamper_demo`. | Direct tool paths outside the gate can bypass ACGS. | Integration hardening and gateway conformance tests. |
| Malformed receipt | Bad or incomplete evidence is accepted. | Required-field checks fail closed. | `test_executor_refuses_malformed_receipt`, `test_verification_rejects_missing_fields`. | External runtimes must not catch-and-ignore validation errors. | Standard error contracts for adapters. |
| Expired receipt | Old authorization is replayed after its valid period. | `expires_at` is hash-bound and compared as a timezone-aware timestamp. | `test_receipt_expiry.py`. | Expiry is optional; no global revocation list. | Secure profile with expiries and revocation. |
| Tampered receipt | Actor/action/policy/expiry/authority fields are edited. | `receipt_hash` recomputation detects edits; signing verifies hash when engaged. | `test_verification_rejects_altered_fields`, `test_receipt_signing.py`, demo output. | Unsigned hashes are recomputable under host compromise. | Signed receipts on by default for secure profile. |
| Mismatched actor | Receipt issued for one actor is used by another. | Gate requires `expected_actor` from runtime context and checks receipt actor. | `test_maci_role_separation.py`, executor tests. | Actor authentication is integrator-owned. | Identity binding adapters and production auth profile. |
| Mismatched action | Receipt for one tool authorizes another. | `expected_action` check. | `test_decision_receipt.py`, `test_executor_guard.py`. | None inside gate; bypass risk remains outside gate. | Gateway coverage for all tool entrypoints. |
| Argument substitution | Receipt for safe args is reused for dangerous args. | `argument_hash` and exact transform checks. | `test_argument_binding.py`, `test_executor_guard.py`. | Raw args are not stored in audit by default; strong replay needs side-store. | Proof packs with side-store or redaction policy. |
| Self-validation | Agent validates its own authority. | `Validator` role, `DecisionReceipt.from_record` guard, gate actor-anchor check. | `test_maci_role_separation.py`. | Opaque string identity; no built-in IAM. | Integrator identity and signed validator profile. |
| Replay attempt | Old receipt is reused across time/run/context. | Expiry, actor/action/args/tenant/boundary/policy binding; opt-in single-use `ReceiptConsumptionLedger` burns the receipt's audit anchor before execution; workflow ledger for workflow paths. | `test_receipt_expiry.py`, `test_receipt_consumption.py`, workflow tests, replay tests. | The consumption ledger is opt-in (off by default); no global nonce/revocation registry in the local kernel. | Default-on single-use profile; global revocation registry. |
| Audit-chain tampering | Evidence is edited after the fact. | Hash-chained JSONL with `previous_hash` and `event_hash`; malformed tail fails closed before append. | `test_audit_chain.py`, `test_audit_chain_corruption.py`, tamper demo. | Local JSONL is not WORM/off-host durable. | WORM/SIEM/exportable proof packs. |
| Consumption-ledger tampering | The single-use record is edited (line deleted/reordered/altered/truncated) to un-burn a receipt and re-enable exactly one replay. | Each ledger entry is hash-chained (`previous_hash`/`entry_hash`, mirroring the audit chain), so interior delete/reorder/content-edit is detectable; `verify_ledger()` / `gove-zone verify-ledger` reports it; `seal()` baselines a pre-chaining legacy ledger. Tail truncation is caught by a persisted high-water-mark — opt-in `ReceiptConsumptionLedger(path, checkpoint=True)` advances a `<ledger>.hwm` sidecar that `verify_ledger()` auto-consults. Forged/orphan burns (a `consumed_key` anchoring no real decision) are caught by `reconcile(audit_store)` / `verify-ledger --audit PATH`. (Replay-blocking itself never depends on the chain — it keys on `consumed_key` — so tampering is exposed by the report, not by a silent execution.) | The `.hwm` sidecar and the ledger share storage: an attacker who rewrites both consistently is not stopped (place the sidecar on append-only/off-host storage to raise the bar). `reconcile` trusts the audit chain's `iter_events()` — verify it separately with `verify_chain()`. No global revocation registry. | WORM / off-host placement of the audit chain + HWM sidecar; signed checkpoints. |
| Unsigned dev mode misuse | Local unsigned receipts are marketed as production signing. | Docs and `CLAIM_BOUNDARY` identify unsigned local proof; signing mode exists. | `test_receipt_signing.py`, `docs/CLAIMS.md`. | Operator can still deploy unsigned mode if they choose. | Secure profile with signing required by default. |
| Policy-bundle substitution | Receipt is evaluated under one policy but executed under another. | Policy bundle id/hash checks; canonical `RuleSetPolicy` export. | `test_policy_bundle_io.py`, `test_tenant_safety.py`. | No active/stale/revoked lifecycle registry. | Signed policy bundles and versioned policy registry. |
| MCP/tool-gateway misuse | MCP connects tools but execution happens before governance. | `integration.py` normalizes MCP/function-call shapes; examples show gateway placement. | `test_integration_hook.py`, `test_integration_gaps.py`, `examples/mcp_tool_gate`. | Adapter shape support is local; production MCP server enforcement must be wired by integrator. | MCP adapter conformance suite. |
| Executor bypass | A caller invokes the raw tool instead of the governed executor. | Architecture docs require direct tools behind gate; tests prove gated paths only. | Integration guide, examples. | Kernel cannot stop code paths it is not wired into. | Gateway wrappers, static checks, deployment profile. |
| Policy evaluation failure | Policy exception accidentally allows execution. | Kernel synthesizes DENY and audits it. | `test_fail_closed.py`. | Hanging policies need configured watchdog. | Secure defaults for `policy_timeout`. |
| Policy timeout/hang | Executor waits forever or eventually allows after stale evaluation. | Optional `policy_timeout` converts timeout to DENY. | `test_fail_closed_gaps.py`. | Timeout is configurable, not globally required. | Secure profile defaults. |
| Audit append failure | Side effect runs without durable evidence. | Kernel raises `AuditError` before execution. | `test_fail_closed.py`, `test_audit_chain_corruption.py`. | Local disk availability and durability are operator concerns. | Durable/off-host audit sink. |

## Deployment hardening — defaults that matter

The kernel ships safe-by-inspection but **dev-permissive by default**. Two defaults
must be changed for a production posture; both are accepted limitations of the local
alpha, not bugs:

- **Signing is off by default.** `require_signature` defaults to `False`
  (`executor.py`, `contracts.py`). In that mode verification checks only the local
  SHA-256 `receipt_hash`, which is recomputable under host compromise (see the
  *Tampered receipt* and *Unsigned dev mode misuse* rows). **Production MUST set
  `require_signature=True` with a trusted verifier** (`signing.py`,
  `test_receipt_signing.py`). Unsigned mode is dev-only proof and must not be
  described as production signing.
- **Anti-replay is opt-in, off by default.** `DecisionReceipt.verify` is
  stateless, so a valid `ALLOW` receipt can be replayed until its `expires_at`
  *unless* the gate carries a single-use ledger. Passing a
  `ReceiptConsumptionLedger` (`consumption.py`) makes the receipt single-use: its
  audit anchor is burned before the side effect, and a replay raises
  `ReceiptAlreadyUsedError` (`test_receipt_consumption.py`). The ledger is now
  hash-chained, so the freshness record is itself tamper-evident (see the
  *Consumption-ledger tampering* row) — but it must be enabled per gate and there
  is still no global nonce/revocation registry. `replay.py` is
  *deterministic/audit* replay, not anti-replay enforcement. Mitigations today:
  enable the consumption ledger, set a short `expires_at`, use the workflow ledger
  for workflow paths, and retain side-store proof packs for strong replay. A
  default-on single-use profile and a global revocation registry are roadmap.

Also operator-tunable and off/optional by default: `expires_at` (no global
revocation list) and `policy_timeout` (hang → DENY only when configured). Set both
for a hardened deployment.

## Security-sensitive files

- `packages/gove-zone/src/gove_zone/receipt.py`
- `packages/gove-zone/src/gove_zone/executor.py`
- `packages/gove-zone/src/gove_zone/kernel.py`
- `packages/gove-zone/src/gove_zone/audit.py`
- `packages/gove-zone/src/gove_zone/consumption.py`
- `packages/gove-zone/src/gove_zone/replay.py`
- `packages/gove-zone/src/gove_zone/signing.py`
- `packages/gove-zone/src/gove_zone/policy.py`
- `packages/gove-zone/src/gove_zone/tenant.py`
- `packages/gove-zone/src/gove_zone/integration.py`
- `.claude/hooks/acgs-emit-receipt.py`
- `.claude/settings.json`

## Required security review behavior

Any change to receipt, policy, audit, signing, replay, executor, hook, or adapter code must include:

- negative-path test proving the side effect did not run;
- wiring proof at the dispatcher/gateway boundary;
- claim updates in `docs/CLAIMS.md` if behavior changed;
- explicit note whether unsigned mode or signing mode semantics changed.
