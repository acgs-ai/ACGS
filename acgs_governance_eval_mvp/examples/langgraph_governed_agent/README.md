# Receipt-Gated LangGraph Governed Agent

**What it proves.** A LangGraph-style agent that calls a side-effecting tool
(`contract.redline`) through the ACGS governance adapter **fails closed**: when
governance denies the call, the tool executor is *provably never invoked* and the
graph routes to a remediation node; when governance permits the call, the
executor runs exactly once on the validated input and a tamper-evident
`DecisionRecord` "receipt" is persisted to the chain-hash audit store. The proof
is exercised through the graph's own dispatch (`MiniGraph.invoke`) — not by
calling the adapter directly — so it certifies the wiring, not just the gate.

The deny-path guarantee is structural: the executor is handed only to
`govern_langgraph_tool_call(...)` → `adapter.guard(...)`, which raises **before**
running the executor on a deny. A spy executor's call-list therefore stays empty.

## Run

```bash
cd acgs_governance_eval_mvp
uv run --package acgs-governance-eval-mvp python examples/langgraph_governed_agent/demo.py
```

It prints a BLOCKED scenario (with reason codes), then an ALLOWED scenario (with
the executor result and persisted receipt `event_hash`), verifies the audit
chain, prints a `PASS` banner, and exits 0. Local-only, no network.

The graph-level wiring test lives at
`tests/test_langgraph_graph_wiring.py` (deny + allow, asserting the spy stays
empty on deny).

## Honest scope

There is **no real `langgraph` dependency** here, by design. The package's
`governance/adapters/AGENTS.md` mandates that adapters target only the SDK's
tool-node callback contract, not the SDK itself. `governed_graph.py` mirrors that
node-dispatch + conditional-edge contract (a governance denial —
`PermissionError`/`GovernanceDeniedError` — routes to remediation) so the
fail-closed behaviour can be exercised hermetically. The
governance decision path it drives is the real one.
