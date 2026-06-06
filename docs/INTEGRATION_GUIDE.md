# Integration guide

> **Core invariant: No valid Decision Receipt, no side effect.**


ACGS / gove-zone belongs immediately before side effects.

The model may request an action, but the executor must enforce the receipt gate.

## Put the gate before

- filesystem writes;
- API calls;
- database changes;
- payments;
- deployments;
- email/send actions;
- MCP tools;
- CI/CD side effects;
- agent-framework tool execution.

## Integration rule

Never treat planner approval as execution approval. The executor must verify:

- actor;
- action;
- arguments;
- tenant;
- execution boundary;
- policy bundle/hash;
- audit anchor;
- expiry;
- signature when required;
- decision is `allow` or approved `transform`.

## Plain Python function wrapper

Runnable example:

```bash
uv run --package gove-zone python examples/python_tool_gate/demo.py
```

Pattern:

```python
result = execute_with_receipt(
    tool_fn=write_file,
    args={"path": "safe.txt", "content": "ok"},
    receipt=receipt,
    expected_tenant_id="tenant-A",
    expected_execution_boundary="local-sandbox",
    expected_action="runtime.file.write",
    expected_actor="agent-1",
)
```

## MCP tool gateway

Runnable example:

```bash
uv run --package gove-zone python examples/mcp_tool_gate/demo.py
```

MCP connects tools; ACGS governs whether `tools/call` may reach the implementation.

Gateway placement:

```text
MCP client -> gateway receives tools/call -> ACGS governance/receipt -> executor verifies -> actual tool implementation
```

## OpenAI Agents-style tool wrapper

Runnable generic example:

```bash
uv run --package gove-zone python examples/agent_framework_gate/demo.py
```

Pattern:

```python
def governed_tool_call(action, args, receipt):
    return executor.execute(action, args, receipt)
```

The model output can contain a function/tool call. The bridge must not call the raw Python function directly; it must call the governed wrapper.

## LangGraph-style node/tool wrapper

Use the same boundary at the graph node that performs the side effect:

```python
def deploy_node(state):
    args = state["deploy_args"]
    receipt = state.get("decision_receipt")
    return governed_executor.execute("ci.deploy", args, receipt)
```

The graph can decide when to request governance, but the side-effect node enforces the gate.

## Generic HTTP API gate

A side-effect API should require a receipt alongside the action request:

```text
POST /deploy
{
  "action": "ci.deploy",
  "args": {"environment": "staging", "version": "1.2.3"},
  "decision_receipt": {...}
}
```

Server-side order:

1. authenticate caller;
2. map caller to `expected_actor`;
3. verify receipt with expected tenant/boundary/action/args/policy;
4. run side effect only if verification succeeds;
5. return denial without executing otherwise.

## CI deployment gate

Runnable example:

```bash
uv run --package gove-zone python examples/ci_deploy_gate/demo.py
```

CI should gate before deploy/apply/publish:

```text
workflow job -> request governance -> receipt -> deploy step verifies -> deploy or fail closed
```

## What not to do

- Do not let agents pass `--force` or a policy override to raw tools.
- Do not trust a receipt without checking args and actor from runtime context.
- Do not accept unsigned receipts in production-adjacent paths unless the risk is explicitly accepted and documented.
- Do not describe hook observe mode as enforcement.
- Do not put the gate only in a planner; put it where the side effect would happen.
