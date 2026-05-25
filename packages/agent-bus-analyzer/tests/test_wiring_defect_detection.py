"""T034 — pure-function unit tests for compute_findings + static_declared_handlers.

All tests are hermetic: no filesystem access beyond tmp_path for the AST scan.
"""

from __future__ import annotations

import textwrap
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_bus_analyzer.models import (
    HandlerDescriptor,
    HandlerRegistrySnapshot,
    WiringDefectSummary,
)
from agent_bus_analyzer.wiring import compute_findings, static_declared_handlers

# ---- helpers ---------------------------------------------------------------


def _make_snapshot(*handler_names: str) -> HandlerRegistrySnapshot:
    now = datetime.now(UTC)
    handlers = {
        name: HandlerDescriptor(
            name=name,
            declared_in_source=False,
            registered_in_runtime=True,
            last_seen_at=None,
        )
        for name in handler_names
    }
    return HandlerRegistrySnapshot(
        snapshot_id=str(uuid.uuid4()),
        sampled_at=now,
        handlers=handlers,
        source="enhanced_agent_bus",
    )


def _dispatch_event(handler: str, *, seconds_ago: float = 5.0) -> dict:
    ts = datetime.now(UTC) - timedelta(seconds=seconds_ago)
    return {
        "event_id": str(uuid.uuid4()),
        "correlation_id": "corr-1",
        "recorded_at": ts.isoformat(),
        "source_agent": "test-agent",
        "target_handler_declared": handler,
        "kind": "dispatch",
        "status": "completed",
    }


# ---- compute_findings tests ------------------------------------------------


def test_no_events_no_registry_yields_empty() -> None:
    snap = _make_snapshot()
    result = compute_findings(snap, [], window_seconds=60)
    assert isinstance(result, WiringDefectSummary)
    assert result.findings == []
    assert result.kind == "wiring-defect-summary"


def test_unwired_dispatch_detected() -> None:
    """Dispatch to handler not in registry → unwired_dispatch finding."""
    snap = _make_snapshot()  # empty registry
    events = [_dispatch_event("unknown.handler")]
    result = compute_findings(snap, events, window_seconds=60)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.kind == "unwired_dispatch"
    assert f.handler_name == "unknown.handler"
    assert len(f.example_event_ids) == 1


def test_declared_but_unrouted_detected() -> None:
    """Handler in registry but no dispatches → declared_but_unrouted."""
    snap = _make_snapshot("policy.evaluate")
    result = compute_findings(snap, [], window_seconds=60)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.kind == "declared_but_unrouted"
    assert f.handler_name == "policy.evaluate"
    assert f.example_event_ids == []


def test_matched_handler_no_findings() -> None:
    """Handler in registry AND dispatched in window → no findings."""
    snap = _make_snapshot("policy.evaluate")
    events = [_dispatch_event("policy.evaluate")]
    result = compute_findings(snap, events, window_seconds=60)
    assert result.findings == []


def test_dedup_on_kind_handler_name() -> None:
    """Multiple dispatch events to the same unknown handler → one finding."""
    snap = _make_snapshot()
    events = [_dispatch_event("ghost") for _ in range(3)]
    result = compute_findings(snap, events, window_seconds=60)
    unwired = [f for f in result.findings if f.kind == "unwired_dispatch"]
    assert len(unwired) == 1
    assert len(unwired[0].example_event_ids) <= 5


def test_example_event_ids_capped_at_5() -> None:
    snap = _make_snapshot()
    events = [_dispatch_event("ghost") for _ in range(10)]
    result = compute_findings(snap, events, window_seconds=60)
    assert len(result.findings[0].example_event_ids) <= 5


def test_events_outside_window_ignored() -> None:
    """Events older than window_seconds are excluded."""
    snap = _make_snapshot()
    old_event = _dispatch_event("ghost", seconds_ago=120.0)
    result = compute_findings(snap, [old_event], window_seconds=60)
    assert result.findings == []


def test_non_dispatch_events_ignored() -> None:
    """response / decision events don't trigger unwired_dispatch."""
    snap = _make_snapshot()
    response_event = {
        "event_id": str(uuid.uuid4()),
        "correlation_id": "corr-1",
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": "test",
        "target_handler_declared": "ghost",
        "kind": "response",
        "status": "completed",
    }
    result = compute_findings(snap, [response_event], window_seconds=60)
    # ghost is not in the registry, but it's a response event — no unwired_dispatch
    unwired = [f for f in result.findings if f.kind == "unwired_dispatch"]
    assert unwired == []


def test_idempotent_on_same_inputs() -> None:
    snap = _make_snapshot("h1")
    events = [_dispatch_event("h2")]
    r1 = compute_findings(snap, events)
    r2 = compute_findings(snap, events)
    # finding_ids differ (UUID), but kinds and handler names match
    kinds_1 = {(f.kind, f.handler_name) for f in r1.findings}
    kinds_2 = {(f.kind, f.handler_name) for f in r2.findings}
    assert kinds_1 == kinds_2


# ---- static_declared_handlers tests ----------------------------------------


def test_scan_finds_bus_handler_decorator(tmp_path: Path) -> None:
    src = tmp_path / "handler.py"
    src.write_text(
        textwrap.dedent("""\
        class Bus:
            pass

        bus = Bus()

        @bus.handler("policy.evaluate")
        def policy_evaluate(msg):
            pass
        """)
    )
    result = static_declared_handlers([tmp_path])
    assert "policy.evaluate" in result


def test_scan_finds_kernel_tool_decorator(tmp_path: Path) -> None:
    src = tmp_path / "tools.py"
    src.write_text(
        textwrap.dedent("""\
        @kernel.tool("audit.log")
        def audit_log(record):
            pass
        """)
    )
    result = static_declared_handlers([tmp_path])
    assert "audit.log" in result


def test_scan_bare_decorator_uses_function_name(tmp_path: Path) -> None:
    src = tmp_path / "bare.py"
    src.write_text(
        textwrap.dedent("""\
        @bus.handler
        def my_handler(msg):
            pass
        """)
    )
    result = static_declared_handlers([tmp_path])
    assert "my_handler" in result


def test_scan_no_arg_decorator_uses_function_name(tmp_path: Path) -> None:
    src = tmp_path / "noarg.py"
    src.write_text(
        textwrap.dedent("""\
        @kernel.tool()
        def my_tool(x):
            pass
        """)
    )
    result = static_declared_handlers([tmp_path])
    assert "my_tool" in result


def test_scan_skips_submodule_root(tmp_path: Path) -> None:
    """A root containing .git is refused — submodule boundary."""
    submodule = tmp_path / "submodule"
    submodule.mkdir()
    (submodule / ".git").mkdir()  # simulate submodule marker
    src = submodule / "handler.py"
    src.write_text(
        textwrap.dedent("""\
        @bus.handler("secret.handler")
        def secret_handler(msg):
            pass
        """)
    )
    result = static_declared_handlers([submodule])
    assert "secret.handler" not in result


def test_scan_skips_unparseable_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(\n")  # SyntaxError
    good = tmp_path / "good.py"
    good.write_text(
        textwrap.dedent("""\
        @bus.handler("good.handler")
        def good_handler(msg):
            pass
        """)
    )
    result = static_declared_handlers([tmp_path])
    assert "good.handler" in result


def test_scan_nonexistent_root_is_skipped() -> None:
    result = static_declared_handlers([Path("/nonexistent/path/xyz")])
    assert isinstance(result, set)
