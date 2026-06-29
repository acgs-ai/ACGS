# Wave 2 (Prove) — Receipt-Gated LangGraph Governed Graph

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Prove the ACGS LangGraph adapter fails closed in an actual graph dispatch
path — the tool executor never runs on deny and the graph routes to remediation —
turning the stack-map's `partial` LangGraph row into an honest, evidence-backed
`exists`.

**Architecture:** A minimal, self-contained graph runner mirrors LangGraph's
node-dispatch + conditional-edge contract (a node that raises routes to a
remediation node). The governed tool-node calls the existing
`govern_langgraph_tool_call(...)` adapter. **No real `langgraph` dependency** — the
package's own `adapters/AGENTS.md` mandates that adapters depend only on the SDK's
callback contract, not the SDK. The "receipt" is the persisted `DecisionRecord`
in the `ChainHashAuditStore`.

**Tech Stack:** Python 3.10+, eval-MVP `governance.*` package, pytest. All work lands
inside `acgs_governance_eval_mvp/` (one subproject scope, one gate).

## Global Constraints (verbatim)

- **No real `langgraph` dep** — mirror the tool-node callback contract only
  (`acgs_governance_eval_mvp/governance/adapters/AGENTS.md`).
- ruff line-length **120** for this package; ignore `B008,RUF012,UP028` (its pyproject).
- mypy strict applies to `governance/` + `governed_mcp_v0/` only — examples/tests are not mypy-gated, but keep them clean.
- The wiring test MUST drive the graph dispatch, NOT call `govern_langgraph_tool_call` directly (handler-wiring rule — the existing `test_langgraph_adapter_blocks_denied` is the anti-pattern this fixes).
- Fail-closed is sacred: on deny the side-effect executor must be provably un-called.
- Permitted path requires `policy_citations: ["CONTRACT-AUTHORITY-001"]` (see `test_reference_adapters.py`).
- Demo is local-only, no network, exits 0.
- Explicit-path `git add` only; commit from the worktree on `agent/wave2-prove`.

## Files

- Create: `acgs_governance_eval_mvp/examples/langgraph_governed_agent/governed_graph.py` — reusable mini-graph + governed-node builder.
- Create: `acgs_governance_eval_mvp/examples/langgraph_governed_agent/demo.py` — runnable; deny + allow scenarios, prints receipt, verifies chain, exit 0.
- Create: `acgs_governance_eval_mvp/examples/langgraph_governed_agent/README.md` — what it proves + honest claim + run command.
- Create: `acgs_governance_eval_mvp/tests/test_langgraph_graph_wiring.py` — graph-level wiring test (deny + allow).

## Interfaces (governed_graph.py — later tasks/tests rely on these exact names)

```python
class ToolExecuted:                       # spy-friendly sentinel for the side effect
    calls: list[dict]                     # appended once per real execution

def build_governed_graph(
    adapter,                              # GovernedToolAdapter (with audit_store)
    tool_executor,                        # Callable[[dict], Any] — the side effect
    *, node_name: str = "redline-node",
    tool_name: str = "contract.redline",
) -> "MiniGraph": ...

class MiniGraph:
    def invoke(self, state: dict) -> dict: ...
    # returns final state with keys:
    #   "terminal": "done" | "remediation"
    #   "result":   executor return value (only when terminal == "done")
    #   "denial":   {"reason_codes": [...], "event_hash": str} (only on remediation)
```

State input contract for `invoke`: `{"principal": {...}, "tool_args": {...}}`.

---

### Task 1: Graph runner + governed node (`governed_graph.py`)

**Files:** Create `acgs_governance_eval_mvp/examples/langgraph_governed_agent/governed_graph.py`

- [ ] **Step 1: Write the failing test** (this is also the start of Task 4's file; create `tests/test_langgraph_graph_wiring.py`)

```python
from __future__ import annotations
import sys
from pathlib import Path

import pytest
from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore

EX = Path(__file__).resolve().parent.parent / "examples" / "langgraph_governed_agent"
if str(EX) not in sys.path:
    sys.path.insert(0, str(EX))
from governed_graph import build_governed_graph  # noqa: E402

PRINCIPAL = {"id": "agent-legal-1", "role": "LegalOps"}
BASE_ARGS = {"contract_id": "supplier-123", "fields": ["price", "term"], "resource": "contracts/supplier-123"}


def _adapter(tmp_path, roles_bundle, policy_bundle):
    return GovernedToolAdapter(
        roles_bundle=roles_bundle, policy_bundle=policy_bundle,
        audit_store=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )


def test_graph_denies_without_citations_executor_never_runs(tmp_path, roles_bundle, policy_bundle):
    adapter = _adapter(tmp_path, roles_bundle, policy_bundle)
    ran = []
    graph = build_governed_graph(adapter, lambda ti: ran.append(ti) or {"ok": True})
    final = graph.invoke({"principal": PRINCIPAL, "tool_args": BASE_ARGS})
    assert final["terminal"] == "remediation"          # routed to remediation
    assert ran == []                                    # FAIL-CLOSED: side effect never ran
    assert final["denial"]["reason_codes"]              # carries why


def test_graph_allows_with_citations_executes_and_persists_receipt(tmp_path, roles_bundle, policy_bundle):
    adapter = _adapter(tmp_path, roles_bundle, policy_bundle)
    ran = []
    graph = build_governed_graph(adapter, lambda ti: ran.append(ti) or {"ok": True})
    args = {**BASE_ARGS, "policy_citations": ["CONTRACT-AUTHORITY-001"]}
    final = graph.invoke({"principal": PRINCIPAL, "tool_args": args})
    assert final["terminal"] == "done"
    assert ran and ran[0] == args                       # executed with validated input
    assert final["result"] == {"ok": True}
```

- [ ] **Step 2: Run to verify it fails** — `cd acgs_governance_eval_mvp && uv run --package acgs-governance-eval-mvp python -m pytest tests/test_langgraph_graph_wiring.py -q` → FAIL (`ModuleNotFoundError: governed_graph`).

- [ ] **Step 3: Implement `governed_graph.py`** — a `MiniGraph` whose `invoke` dispatches: `govern` node calls `govern_langgraph_tool_call(node_name, tool_name, tool_args, principal, adapter, tool_executor)`; catch `PermissionError` (→ `GovernanceDeniedError`), extract `err.decision.reason_codes` + `event_hash`, route to `remediation` (sets `terminal="remediation"`, `denial=...`, does NOT call executor again); on success set `terminal="done"`, `result=<return>`. The executor is invoked ONLY inside the adapter's `guard` (via the adapter), so deny provably never executes it. Conditional edge = the try/except, mirroring "exception becomes the node's error → route to remediation."

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `git add acgs_governance_eval_mvp/examples/langgraph_governed_agent/governed_graph.py acgs_governance_eval_mvp/tests/test_langgraph_graph_wiring.py` then commit `feat(eval-mvp): receipt-gated LangGraph graph-wiring test + mini-graph runner`.

### Task 2: Runnable demo + README

**Files:** Create `demo.py` + `README.md` under the example dir.

- [ ] **Step 1:** Write `demo.py`: build adapter with a tempdir `ChainHashAuditStore`, load bundles via `governance.policy_loader.load_roles("governance/roles.json")` + `load_policy_bundle("governance/policies/2026-05")` (run from package root), build the graph with a real side-effect executor that prints, run the **deny** scenario (assert/print the executor never ran, show reason_codes), run the **allow** scenario (print the result + the persisted receipt `event_hash`), then verify the audit chain. Print a clear PASS banner; `sys.exit(0)`.
- [ ] **Step 2:** Run it: `cd acgs_governance_eval_mvp && uv run --package acgs-governance-eval-mvp python examples/langgraph_governed_agent/demo.py` → exit 0, shows BLOCKED then ALLOWED+receipt.
- [ ] **Step 3:** Write `README.md`: one-paragraph "what it proves" (fail-closed wiring against the LangGraph tool-node contract), the run command, and the honest scope line: *no real `langgraph` dependency — this exercises the callback contract the adapter targets, by design.*
- [ ] **Step 4: Commit** the two files.

### Task 3: Verify full package gate (regression)

- [ ] Run the whole eval-MVP suite + ruff to prove no regression:
  `cd acgs_governance_eval_mvp && uv run --package acgs-governance-eval-mvp python -m pytest tests -q` and `uvx ruff@0.8 check examples/langgraph_governed_agent tests/test_langgraph_graph_wiring.py`. Capture literal output. Both green before claiming done.

## Self-Review checklist

- Deny path: executor spy list empty (provably un-called) — the core fail-closed proof.
- Allow path: executor called once with the **validated** `effective_tool_input`, receipt persisted, chain verifies.
- Test drives `graph.invoke`, never the adapter directly.
- No `import langgraph` anywhere.
- Follow-up (separate, after #182 merges): update the `AGENT_STACK_GOVERNANCE.md` LangGraph maturity row `partial → exists` citing this demo + test (do NOT edit that doc here — it's on PR #182).
