# Agent framework gate example

Shows an OpenAI Agents-style or LangGraph-style tool wrapper: the agent/framework may request a tool call, but the wrapper enforces the receipt gate.

Run:

```bash
uv run --package gove-zone python examples/agent_framework_gate/demo.py
```

Expected output: JSON with `status: "pass"`, `valid_receipt_executed: true`, and `argument_substitution_blocked: true`.

Failure case: a receipt issued for one set of arguments is reused with different arguments; the executor rejects the call and the side effect does not run.

What is proven: orchestration can stay in the agent framework while side-effect authorization stays in ACGS.

This example is local-only. It proves executor placement and failure behavior; it does not prove production deployment, compliance certification, or live framework integration.
