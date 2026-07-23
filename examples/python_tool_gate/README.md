# Python tool gate example

Shows a plain Python side-effect function protected by a Decision Receipt gate.

Run:

```bash
uv run --package gove-zone python examples/python_tool_gate/demo.py
```

Expected output: JSON with `status: "pass"`, `valid_receipt_executed: true`, `missing_receipt_blocked: true`, `missing_receipt_audited: true`, and `side_effect_count: 1`.

Failure case: the same function is called with `receipt=None`; the governed executor raises `ReceiptValidationError`, the side effect counter does not increment, and the last audit event is a `DENY` whose matched rules are exactly `receipt.execution.receipt_required`.

What is proven: a normal Python function can remain unchanged while the wrapper enforces **No valid Decision Receipt, no side effect.**

## How the gate is configured

The demo builds the strict receipt-gate fixture (`build_strict_receipt_gate_fixture`) in a
temporary directory, and both `execute_with_receipt` calls run under it with no opt-outs:

- `require_signature=True` with `verifier=fixture.signer` — the receipt is signed at issuance
  and its signature is verified at the gate.
- The receipt binds to a real audit chain: the policy `DecisionRecord` is appended to
  `fixture.audit` first, and the receipt carries that event's `event_hash` and `previous_hash`.
  The audit store is a chain-hash store with a signed external checkpoint anchor.
- `consumption_store=fixture.consumption_store` — anchored schema-v4 single-use consumption.
- `rejection_audit=fixture.audit` — denials are recorded on the same strict chain.
- `lifecycle_signer=fixture.lifecycle_signer` (a key distinct from the receipt signer) with
  `lifecycle_authority_id="fixture-lifecycle-validator"`.
- `expected_adapter_artifact_digest=adapter_artifact_digest(side_effect.write_file)` — the gate
  refuses to run an adapter whose code identity does not match the digest.

This example is local-only. It proves executor placement and failure behavior with a strict,
fully-wired gate. The keys, audit chain, checkpoint anchor, and consumption anchor are
ephemeral and generated in-process for this run: they are not production key custody, not
off-host durability, and not evidence of a deployment. The example does not prove production
deployment, compliance certification, or live framework integration.
