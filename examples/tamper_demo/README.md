# Tamper demo

Shows receipt tampering, argument substitution, and audit-chain tampering failures.

Run:

```bash
uv run --package gove-zone python examples/tamper_demo/demo.py
```

Expected output: JSON with `status: "pass"` and:

- `valid_receipt_executed: true`
- `tampered_receipt_blocked: true`
- `tampered_receipt_audited: true`
- `argument_mismatch_blocked: true`
- `argument_mismatch_audited: true`
- `audit_chain_valid_before_tamper: true`
- `audit_chain_valid_after_tamper: false`
- `side_effect_count: 1`

Failure cases, each asserted independently:

- **Receipt field tampering**: `proposed_action` is rewritten to `runtime.shell.run`. The gate
  raises `ReceiptValidationError` and the last audit event is a `DENY` whose matched rules are
  exactly `receipt.execution.receipt_invalid`.
- **Argument substitution**: the untampered receipt is replayed against different arguments.
  This is a separate attempt with its own audited `DENY` for
  `receipt.execution.receipt_invalid`, captured immediately after the call.
- **Audit-chain tampering**: after both attempts, the persisted JSONL is edited on disk (the
  first event's `decision` is flipped to `deny`). Verification runs through the *same* strict
  audit object that wrote the chain — `fixture.audit.verify_checkpointed_chain()` — so the local
  chain is checked against the signed external checkpoint that is actually bound to these
  events. It reports `valid: false`. Re-opening the file as a fresh uncheckpointed store would
  only prove local hash-linking, not that the chain still matches its trusted checkpoint.

Across all three, the side-effect counter stays at `1`: only the one valid receipt ever executed.

What is proven: a valid Decision Receipt is narrow; tampering with receipt fields, arguments, or
replay evidence does not silently authorize a side effect, and each rejection is recorded on the
audit chain with its own reason.

## How the gate is configured

The demo builds the strict receipt-gate fixture (`build_strict_receipt_gate_fixture`) in a
temporary directory, and every `execute_with_receipt` call runs under it with no opt-outs:

- `require_signature=True` with `verifier=fixture.signer` — the receipt is signed at issuance
  and its signature is verified at the gate.
- The receipt binds to a real audit chain: the policy `DecisionRecord` is appended to
  `fixture.audit` first, and the receipt carries that event's `event_hash` and `previous_hash`.
  The audit store is a chain-hash store with a signed external checkpoint anchor.
- `consumption_store=fixture.consumption_store` — anchored schema-v4 single-use consumption.
- `rejection_audit=fixture.audit` — denials are recorded on the same strict chain.
- `lifecycle_signer=fixture.lifecycle_signer` (a key distinct from the receipt signer) with
  `lifecycle_authority_id="fixture-lifecycle-validator"`.
- `expected_adapter_artifact_digest=adapter_artifact_digest(side.run)` — the gate refuses to run
  an adapter whose code identity does not match the digest.
- The first call additionally pins `expected_audit_hash`, `expected_policy_hash`, and
  `expected_policy_bundle_id`.

This example is local-only. It proves executor placement and failure behavior with a strict,
fully-wired gate. The keys, audit chain, checkpoint anchor, and consumption anchor are
ephemeral and generated in-process for this run: they are not production key custody, not
off-host durability, and not evidence of a deployment. The tamper is performed by this demo on
its own temporary file. The example does not prove production deployment, compliance
certification, or live framework integration.
