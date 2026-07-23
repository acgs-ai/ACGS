# MCP tool gate example

Shows where ACGS belongs in front of an MCP `tools/call` implementation.

Run:

```bash
uv run --package gove-zone python examples/mcp_tool_gate/demo.py
```

Expected output: JSON with `status: "pass"`, `normalized_tool: "runtime.file.write"`, `valid_receipt_executed: true`, `missing_receipt_blocked: true`, `missing_receipt_audited: true`, and `side_effect_count: 1`.

Failure case: the gateway invokes the side-effectful MCP tool with `receipt=None`; the governed executor raises `ReceiptValidationError`, the tool call counter does not increment, and the last audit event is a `DENY` whose matched rules are exactly `receipt.execution.receipt_required`.

What is proven: MCP can remain the transport while ACGS governs whether the tool implementation may run.

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
- `expected_adapter_artifact_digest=adapter_artifact_digest(tool.run)` — the gate refuses to run
  an adapter whose code identity does not match the digest.

The MCP payload is normalized by `tool_call_from_hook_payload`, so the receipt, the gate, and the
audit record all bind the same normalized action name (`runtime.file.write`), not the raw
transport-level tool string.

This example is local-only. It proves executor placement and failure behavior with a strict,
fully-wired gate. The keys, audit chain, checkpoint anchor, and consumption anchor are
ephemeral and generated in-process for this run: they are not production key custody, not
off-host durability, and not evidence of a deployment. The example does not prove production
deployment, compliance certification, or live framework integration.
