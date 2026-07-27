# Integration guide

> **Core invariant: No valid Decision Receipt, no side effect.**


ACGS belongs immediately before side effects.

The model may request an action, but the executor must enforce the receipt gate.

For which runtimes are shipped-and-tested versus illustrative patterns versus roadmap, see [`INTEGRATION_MATRIX.md`](INTEGRATION_MATRIX.md). The placement is the same for all of them; only the proof depth differs.

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

### Your first receipt (self-contained, copy-paste)

This minimal snippet mints a Decision Receipt and proves the invariant in both
directions: the allowed path executes the side effect, the missing-receipt path
fails closed. Run it verbatim with
`uv run --extra crypto --package gove-zone python <file>.py`:

```python
from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ReceiptValidationError,
    Validator,
    execute_with_receipt,
    sha256_json,
)

TENANT, BOUNDARY = "tenant-A", "local-sandbox"
ACTION, ACTOR = "runtime.file.write", "agent-1"
ARGS = {"path": "safe.txt", "content": "ok"}


def write_file(**kwargs) -> str:
    return "SIDE EFFECT EXECUTED"


# 1. Mint a Decision Receipt for an ALLOW decision over this exact call.
record = DecisionRecord(
    decision=Decision.ALLOW,
    tool=ACTION,
    argument_hash=sha256_json(ARGS),
    policy_version="example-policy/v1",
    event_id="ev_first_receipt",
    actor=ACTOR,
    reason="example allow",
)
receipt = DecisionReceipt.from_record(
    record=record,
    audit_hash="audit_hash_first_receipt",
    previous_audit_hash="0" * 64,
    tenant_id=TENANT,
    execution_boundary=BOUNDARY,
    policy_bundle_id="example-policy",
    policy_hash="example-policy/v1",
    request_id="req-first-receipt",
    validator=Validator("constitutional-council"),
    authority="tenant-A/write-grant",
)

# 2. Allowed path: the receipt verifies, so the side effect runs.
result = execute_with_receipt(
    require_signature=False,  # dev-mode: local unsigned demo (prod signs receipts)
    tool_fn=write_file,
    args=ARGS,
    receipt=receipt,
    expected_tenant_id=TENANT,
    expected_execution_boundary=BOUNDARY,
    expected_action=ACTION,
    expected_actor=ACTOR,
)
assert result == "SIDE EFFECT EXECUTED"

# 3. Missing-receipt path: no valid receipt -> no side effect (fail closed).
missing_blocked = False
try:
    execute_with_receipt(
        require_signature=False,
        tool_fn=write_file,
        args=ARGS,
        receipt=None,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=ACTOR,
    )
except ReceiptValidationError:
    missing_blocked = True
assert missing_blocked

print("OK: allowed path executed; missing-receipt path blocked.")
```

The same end-to-end thread, including denied / tampered / cross-tenant paths,
runs as `examples/python_tool_gate/demo.py` (above).

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

> Illustrative placement pattern using the generic framework gate. A tested, OpenAI-Agents-named conformance adapter is on the [roadmap](ROADMAP.md), not shipped — see [`INTEGRATION_MATRIX.md`](INTEGRATION_MATRIX.md).

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

> Illustrative placement pattern, not a tested adapter. LangGraph conformance tests are on the [roadmap](ROADMAP.md) — see [`INTEGRATION_MATRIX.md`](INTEGRATION_MATRIX.md).

Use the same boundary at the graph node that performs the side effect:

```python
def deploy_node(state):
    args = state["deploy_args"]
    receipt = state.get("decision_receipt")
    return governed_executor.execute("ci.deploy", args, receipt)
```

The graph can decide when to request governance, but the side-effect node enforces the gate.

## Generic HTTP API gate

> Illustrative placement pattern; no shipped server example yet (see [`INTEGRATION_MATRIX.md`](INTEGRATION_MATRIX.md)).

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

## Contributing an adapter or policy bundle

To teach ACGS a new framework's tool-call shape, or to contribute a reviewed policy bundle, follow the step-by-step runbooks:

- [`runbooks/add-a-runtime-adapter.md`](runbooks/add-a-runtime-adapter.md) — extend the normalizer, keep batches fail-closed (`runtime.malformed_batch`), and add the gate-level tests a parser-only unit test cannot replace.
- [`runbooks/add-a-policy-bundle.md`](runbooks/add-a-policy-bundle.md) — `RuleSetPolicy` bundle shape (`deny`/`escalate` plus exemptions) and its fixture and gate tests.
