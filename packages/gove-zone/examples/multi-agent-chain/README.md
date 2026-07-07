# Multi-agent governance chain

A worked example of the governance DAG (`gove_zone.dag`): typed tracking of a
multi-agent chain —

```
Agent A ──authority delegation──▶ Agent B
Agent B ──approval──▶ Decision ──approval──▶ Decision Receipt
Decision Receipt ──execution──▶ Tool Call ──execution──▶ Side Effect (evidence)
```

Nodes: `agent`, `decision`, `receipt`, `tool_call`, `side_effect`.
Edges: `authority_delegation`, `approval`, `dependency`, `execution`.

What the demo proves, fail-closed:

1. A well-formed chain replays offline: `verify_dag_replay` re-verifies every
   receipt with the graph's action/actor bindings folded in.
2. Delegation cycles are rejected (Kahn topological sort).
3. Authority inheritance is narrowing-only — an agent can never re-delegate
   more than it holds.
4. An agent acting outside its delegated scope is rejected.
5. A tampered receipt fails replay exactly as at the executor gate.
6. An ungoverned tool call (no gating receipt edge) fails replay.
7. A side effect with no evidence reference fails replay.

Run from the monorepo root:

```bash
uv run --package gove-zone python packages/gove-zone/examples/multi-agent-chain/demo.py
```

Honest scope: the DAG is structural governance *tracking* plus offline replay
verification. It does not by itself stop an ungoverned executor — the receipt
gates in `gove_zone.executor` remain the enforcement point, and unsigned
replay proves internal consistency, not unforgeability (pass a verifier and
`require_signature=True` for the signed posture).
