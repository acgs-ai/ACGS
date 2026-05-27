"""T017 — seed traces into the store, query by correlation_id, assert order.

Verifies the JSONL append + SQLite index + chain integrity (`intact` on a
clean trace) round-trip end-to-end. No bus involved — pure store/query.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_bus_analyzer.store import TraceStore


def _event(correlation_id: str, source_agent: str, suffix: str = "") -> dict[str, Any]:
    return {
        "event_id": f"00000000-0000-0000-0000-0000000000{suffix:>02}",
        "correlation_id": correlation_id,
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": source_agent,
        "target_handler_declared": "policy.evaluate",
        "target_handler_resolved": None,
        "payload_ref": f"sha256:{suffix:0>64}",
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": "608508a9bd224290",
        "status": "completed",
    }


def test_three_traces_listed_and_queried(tmp_path: Path) -> None:
    store = TraceStore(tmp_path)
    for cid in ("trace-a", "trace-b", "trace-c"):
        for i in range(3):
            store.append(_event(cid, "claude:worker-03", suffix=str(i)))

    lst = store.list_traces()
    assert {item.correlation_id for item in lst.items} == {"trace-a", "trace-b", "trace-c"}
    for item in lst.items:
        assert item.event_count == 3
        assert item.worst_event_status == "completed"

    single = store.get_trace("trace-b")
    assert single is not None
    assert [ev.causal_index for ev in single.events] == [0, 1, 2]
    assert single.integrity_status == "intact"


def test_get_trace_unknown_returns_none(tmp_path: Path) -> None:
    store = TraceStore(tmp_path)
    assert store.get_trace("nope") is None


def test_policy_violation_bubbles_to_worst_status(tmp_path: Path) -> None:
    store = TraceStore(tmp_path)
    store.append(_event("trace-x", "claude:worker-03", suffix="0"))
    violation = _event("trace-x", "acgs:handler/policy-evaluator", suffix="1")
    violation["kind"] = "decision"
    violation["decision"] = "deny"
    violation["flagged_rule"] = "rule.no-pii"
    violation["status"] = "policy-violation"
    store.append(violation)

    item = store.list_traces().items[0]
    assert item.correlation_id == "trace-x"
    assert item.worst_event_status == "policy-violation"
