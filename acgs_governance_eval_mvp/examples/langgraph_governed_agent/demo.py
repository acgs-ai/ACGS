#!/usr/bin/env python3
"""Runnable proof: the governed LangGraph graph fails closed.

Runs two scenarios through ``MiniGraph.invoke`` (the same dispatch path a real
LangGraph deployment would use):

  1. BLOCKED — a redline tool call without the required policy citation is
     denied; the side-effect executor is *provably never invoked* (its spy
     call-list stays empty) and the graph routes to remediation.
  2. ALLOWED — the same call *with* ``policy_citations`` is permitted; the
     executor runs once with the validated input, and a tamper-evident
     ``DecisionRecord`` receipt is persisted to the chain-hash audit store.

Finally it verifies the audit chain end-to-end. Local-only, no network. Exits 0
on success (and prints a PASS banner); any broken invariant raises and exits
non-zero.

Run from the package root:
    uv run --package acgs-governance-eval-mvp python examples/langgraph_governed_agent/demo.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Make `governance` (package root) and `governed_graph` (this dir) importable
# whether run via `uv run --package` or directly from the package root.
PKG_ROOT = Path(__file__).resolve().parents[2]
if str(PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(PKG_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from governance.adapters.tools import GovernedToolAdapter  # noqa: E402
from governance.audit import ChainHashAuditStore  # noqa: E402
from governance.policy_loader import load_policy_bundle, load_roles  # noqa: E402
from governed_graph import ToolExecuted, build_governed_graph  # noqa: E402

PRINCIPAL = {"id": "agent-legal-1", "role": "LegalOps"}
BASE_ARGS = {
    "contract_id": "supplier-123",
    "fields": ["price", "term"],
    "resource": "contracts/supplier-123",
}


class PrintingRedline(ToolExecuted):
    """Real side-effect executor that prints when (and only when) it runs."""

    def __call__(self, tool_input: dict) -> dict:
        print(f"   [SIDE EFFECT] redlining {tool_input.get('contract_id')} fields={tool_input.get('fields')}")
        return super().__call__(tool_input)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        store = ChainHashAuditStore(Path(tmp) / "audit.jsonl")
        adapter = GovernedToolAdapter(
            roles_bundle=load_roles(PKG_ROOT / "governance" / "roles.json"),
            policy_bundle=load_policy_bundle(PKG_ROOT / "governance" / "policies" / "2026-05"),
            audit_store=store,
        )
        executor = PrintingRedline()
        graph = build_governed_graph(adapter, executor)

        print("=" * 68)
        print("Scenario 1 — DENY (no policy citation): executor must NOT run")
        print("=" * 68)
        denied = graph.invoke({"principal": PRINCIPAL, "tool_args": BASE_ARGS})
        assert denied["terminal"] == "remediation", "deny must route to remediation"
        assert executor.calls == [], "FAIL-CLOSED VIOLATION: executor ran on a denied call"
        print(f"   BLOCKED -> terminal={denied['terminal']!r}")
        print(f"   reason_codes : {denied['denial']['reason_codes']}")
        print(f"   denial receipt event_hash : {denied['denial']['event_hash']}")
        print("   side effect executed? NO (spy call-list is empty) — fail-closed proven\n")

        print("=" * 68)
        print("Scenario 2 — ALLOW (with CONTRACT-AUTHORITY-001): executor runs once")
        print("=" * 68)
        allowed_args = {**BASE_ARGS, "policy_citations": ["CONTRACT-AUTHORITY-001"]}
        allowed = graph.invoke({"principal": PRINCIPAL, "tool_args": allowed_args})
        assert allowed["terminal"] == "done", "allow must terminate done"
        assert len(executor.calls) == 1, "executor must run exactly once on allow"
        print(f"   ALLOWED -> terminal={allowed['terminal']!r}")
        print(f"   executor result : {allowed['result']}")
        print(f"   persisted receipt event_hash : {store.last_hash()}\n")

        print("=" * 68)
        print("Audit chain verification")
        print("=" * 68)
        report = store.verify_chain()
        assert report["valid"], f"audit chain failed verification: {report['failures']}"
        print(f"   chain valid : {report['valid']}  (events checked: {report['checked']})\n")

        print("PASS — governed LangGraph graph fails closed; receipt chain verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
