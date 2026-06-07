# MCP tool gate example

Shows where ACGS belongs in front of an MCP `tools/call` implementation.

Run:

```bash
uv run --package gove-zone python examples/mcp_tool_gate/demo.py
```

Expected output: JSON with `status: "pass"`, a normalized tool name of `runtime.file.write`, `valid_receipt_executed: true`, and `missing_receipt_blocked: true`.

Failure case: the gateway tries to invoke the side-effectful MCP tool without a receipt; execution is blocked.

What is proven: MCP can remain the transport while ACGS governs whether the tool implementation may run.

This example is local-only. It proves executor placement and failure behavior; it does not prove production deployment, compliance certification, or live framework integration.
