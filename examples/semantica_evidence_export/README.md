# Semantica evidence export example

Shows a **one-way** projection of an ACGS Decision Receipt into a
Semantica-shaped record. Semantica is the case file. ACGS is the lock on
the door.

**The Semantica MCP server is not a PEP and never gates a side effect.**

Run:

```bash
uv run --package gove-zone python examples/semantica_evidence_export/demo.py
```

Expected output: JSON with `status: "pass"`, `valid_receipt_executed: true`, `missing_receipt_blocked: true`, `side_effect_count: 1`, `verdicts_exported: 4`, `semantica_is_not_a_gate: true`, and `fabricated_confidence: false`.

Failure case: the same function is called with `receipt=None`; the governed executor raises `ReceiptValidationError` and the side effect counter does not increment. A missing Semantica install does **not** fail the demo — export is skipped and the ACGS decision is unchanged.

What is proven: a Decision Receipt can be exported as a downstream graph-shaped record without becoming an authorization, and **No valid Decision Receipt, no side effect** still holds when the export sink is absent.

## Product boundary

- Data flows **receipt → record only**. Nothing Semantica stores is read back into a gate, policy evaluation, or verification path.
- ACGS does not emit `confidence` or free-text `reasoning`. The lazy emit path uses documented placeholders (`ACGS_NO_REASONING_FIELD`, `0.0`) if Semantica is installed. Those placeholders are not ACGS evidence.
- `receipt_hash` remains the only integrity anchor. A Semantica node id is not evidence.

## How the gate is configured

This example is local-only and unsigned (`require_signature=False`), matching
`examples/python_tool_gate`. It proves executor placement and the mapping
boundary. It does not prove production key custody, signed-mode closure, or
live Semantica service integration.

DENY / TRANSFORM / ESCALATE receipts are minted with `DecisionReceipt.from_record`
and exported; they are not passed to `execute_with_receipt`, because denied and
escalated receipts cannot authorize execution.

The example does not prove production deployment, compliance certification, or
that Semantica enforces anything.

## Compose with MCP

```
agent → tool call
          │
          ▼
   ACGS gate  (validate_action / execute_with_receipt)
          │  ALLOW + valid receipt ──► side effect runs
          │  DENY / ESCALATE / missing receipt ──► refused
          ▼
   Semantica record_decision   ← observation only, after the fact, best-effort
```

Semantica ships two MCP entrypoints: `python -m mcp` (`mcp/` package, 17 tools) and
`semantica-mcp` / `python -m semantica.mcp_server` (12 tools). This example assumes
neither is running. If you compose them later, call the ACGS gate first. A Semantica
write failure must skip export and leave the ACGS decision unchanged.

`add_causal_relationship` on Semantica silently no-ops when a node is missing or is
not a decision. Do not treat graph linkage as proof that two receipts are related.

See also: [Decision Receipt spec](../../docs/DECISION_RECEIPT_SPEC.md),
[claim ledger](../../docs/CLAIMS.md), [integration matrix](../../docs/INTEGRATION_MATRIX.md).
