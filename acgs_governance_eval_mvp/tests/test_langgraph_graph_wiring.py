from __future__ import annotations

import sys
from pathlib import Path

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
    # Receipt persisted: the allow DecisionRecord is in the audit chain and it
    # verifies — the test name claims persistence, so the body must prove it.
    report = adapter.audit_store.verify_chain()
    assert report["valid"] and report["checked"] >= 1   # receipt persisted + chain intact
