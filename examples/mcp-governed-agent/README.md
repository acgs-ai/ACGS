# MCP-governed agent

An agent's MCP `tools/call` traffic intercepted by the ACGS MCP Governance
Gateway (`mcp_gateway` package in `packages/gove-zone`):

```
Agent
 ↓
MCP request
 ↓
ACGS policy check
 ↓
Decision Receipt
 ↓
Tool execution
```

The gateway is a reuse-only assembly over the sealed gove-zone kernel: every
decision goes through `Kernel.evaluate_and_record`, and every execution is
authorised by a `DecisionReceipt` verified inside `execute_with_receipt`. The
receipt binds the tool name, the canonical argument hash, the invoking
principal, and an optional expiry — so a receipt cannot be replayed across
tools, arguments, identities, or time.

Local-only: no network, no MCP SDK. The demo runs in the explicit unsigned dev
profile (`GovernanceProfile.dev()`); production deployments pass
`GovernanceProfile.production(...)` with a signer/verifier instead.

Run:

```bash
PYTHONPATH=packages/gove-zone/src python examples/mcp-governed-agent/demo.py
```

Expected output: a single JSON line with `"status": "pass"` and one check per
scenario:

- `allowed_tool_executed_with_receipt` — the allowed call executed and the MCP
  result carries the receipt metadata (`receipt_hash`, `argument_hash`,
  `expires_at`, `audit_event_hash`).
- `denied_tool_blocked_without_execution` — the denied tool returned a
  structured `isError` result and never ran.
- `modified_arguments_blocked` — a receipt minted for `customer_id: c-42`
  refused execution with `customer_id: c-999`.
- `expired_receipt_blocked` — a receipt past its `expires_at` refused
  execution.
- `replayed_receipt_blocked` — with a `ReceiptConsumptionLedger` configured,
  the first execution burned the receipt and the replay was refused.
- `side_effects_observed` — exactly two side effects total: the allowed read
  and the single-use read; every other scenario terminated before the tool.

Failure case: any scenario where a side effect happens without a valid,
matching, unexpired receipt flips `status` to `fail` and the script exits
non-zero. The deny, tamper, and expiry paths all terminate before the tool
callable is reached.

What is proven: MCP tool calls only execute through a policy decision plus a
receipt whose tool-name, argument-hash, identity, expiry, and single-use
bindings all verify at the execution gate — and denials, tampered arguments,
expired receipts, and replayed receipts are refused fail-closed. No valid
Decision Receipt, no side effect.

What is NOT proven here: transport authentication of the calling agent (the
demo passes `actor` in-process; see `docs/SECURITY_MODEL.md`) and
signed-receipt verification (dev profile is explicitly unsigned; the signed
`GovernanceProfile.production_strict` posture is exercised in the package
tests).
