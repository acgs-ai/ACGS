# Agent-framework wrapper — governing LangGraph / OpenAI Agents tool calls

A runnable example showing the **same** gove-zone governance gate wrapping two
different agent-framework tool-call shapes, **without importing the real SDKs**:

- **(a) LangGraph-style tool node** — a pre-execution intercept inside a
  `state -> state` node that gates a proposed tool call *before* the node runs
  its side effect.
- **(b) OpenAI Agents `@function_tool`-style wrapper** — a decorator/closure that
  gates the wrapped tool function on every invocation.

Both route through gove-zone's **real** side-effect gate
(`execute_with_receipt` via `GovernedExecutor`) under the **production profile**:
signed Decision Receipts are required, and the gate verifies an Ed25519 signature
against a public key before any side effect runs. A small reusable
`GovernedToolGate.govern(tool_fn, action, args, ...)` wrapper carries the gate
and runs the *exact* callable the framework would otherwise run; the two
framework adapters are thin wrappers around it, each passing its own tool
function. On DENY the wrapped function is never called.

## How to run

From the monorepo root:

```bash
uv run --package gove-zone python \
    packages/gove-zone/examples/agent-framework-wrapper/demo.py
```

Or directly, with gove-zone importable:

```bash
python packages/gove-zone/examples/agent-framework-wrapper/demo.py
```

It writes only to a fresh tempdir and exits `0` if every invariant holds (it
exits non-zero on any violation). `main() -> int` is exposed so a test can call
it.

## What to look for

- **Production profile leads.** The gate is built from
  `GovernanceProfile.production(signer=..., verifier=...)`. A production gate with
  **no** verifier fails closed loud (`ProductionProfileError`) — the demo asserts
  this; there is no silent downgrade to unsigned.
- **An ALLOWED call** runs the side effect (file written, result returned)
  through both adapters.
- **A DENIED call** is blocked by the policy at the gate; the demo asserts the
  underlying tool function **never ran** (`tool.ran is False`). The deny path is
  the point.
- **Tamper-evident audit chain** — every decision is anchored and
  `verify_chain()` confirms integrity.

## Why no SDK import

Hard rule: the demo runs with **only gove-zone installed** — no `langgraph`, no
`openai-agents`. Each framework's *call shape* is modelled with a tiny in-file
stub plus a representative payload, then governed with gove-zone's real API. This
shows the integration **pattern**, not a vendored SDK.

## Lineage note

The eval-MVP adapters under `acgs_governance_eval_mvp/governance/adapters/*` wrap
an **older** kernel. This example uses **gove-zone proper** (`gove_zone.*`), the
current kernel.

## Honest scope

This is **local Alpha proof** of the wrapping invariant — *"no valid signed
Decision Receipt, no side effect."* It is **NOT** a production, compliance, or
regulator-ready certification. The Ed25519 keypair is generated in-process purely
so the example is self-contained; a real deployment supplies a private signer at
issuance and distributes only the public verifier to the gate. See
`../../SECURITY.md` and `../receipt-gated-execution/` for the underlying
invariant proven end to end.
