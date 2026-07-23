# Agent framework gate example

Shows an OpenAI Agents-style or LangGraph-style tool wrapper: the agent/framework may request a tool call, but the wrapper enforces the receipt gate.

Run:

```bash
uv run --package gove-zone python examples/agent_framework_gate/demo.py
```

Expected output: JSON with `status: "pass"`, `valid_receipt_executed: true`, `argument_substitution_blocked: true`, `argument_substitution_audited: true`, and `side_effect_count: 1`.

Failure case: a receipt issued for one set of arguments is reused with different arguments. The receipt is verified before consumption is reserved, so the executor raises `ReceiptValidationError`, the mailer counter does not increment, and the last audit event is a `DENY` whose matched rules are exactly `receipt.execution.receipt_invalid`.

What is proven: orchestration can stay in the agent framework while side-effect authorization stays in ACGS.

## How the gate is configured

The demo builds the strict receipt-gate fixture (`build_strict_receipt_gate_fixture`) in a
temporary directory and constructs a `GovernedExecutor` with every strict trust root pinned at
construction — they are immutable afterwards, so a caller cannot override them per-call:

- `require_signature=True` with `verifier=fixture.signer` — the receipt is signed at issuance
  and its signature is verified at the gate.
- The receipt binds to a real audit chain: the policy `DecisionRecord` is appended to
  `fixture.audit` first, and the receipt carries that event's `event_hash` and `previous_hash`.
  The audit store is a chain-hash store with a signed external checkpoint anchor.
- `consumption_store=fixture.consumption_store` — anchored schema-v4 single-use consumption.
- `rejection_audit=fixture.audit` — denials are recorded on the same strict chain.
- `lifecycle_signer=fixture.lifecycle_signer` (a key distinct from the receipt signer) with
  `lifecycle_authority_id="fixture-lifecycle-validator"`.
- `expected_actor` is pinned to the wrapper's caller identity, not read from the receipt.
- `register_tool(action, fn, adapter_artifact_digest=adapter_artifact_digest(fn))` pins the
  adapter's code identity at registration; the gate refuses to run an adapter whose digest does
  not match.

This example is local-only. It proves executor placement and failure behavior with a strict,
fully-wired gate. The keys, audit chain, checkpoint anchor, and consumption anchor are
ephemeral and generated in-process for this run: they are not production key custody, not
off-host durability, and not evidence of a deployment. The example does not prove production
deployment, compliance certification, or live framework integration.
