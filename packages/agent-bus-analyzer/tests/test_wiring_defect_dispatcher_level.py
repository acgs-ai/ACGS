"""T035 — DISPATCHER-LEVEL wiring defect detection test.

Constitution Principle III: this test exercises the dispatcher path, not
direct observer function calls.

Strategy: we use the real ``LocalEventBus`` (same pattern as T016 /
test_bus_dispatch_capture.py). The bus is available in this environment
(``python -c "import enhanced_agent_bus"`` passes). We publish a dispatch
message to a handler NOT in the injected registry snapshot, run
``get_wiring_defects(store, snapshot=snap)``, and assert that an
``unwired_dispatch`` finding appears.

If ``enhanced_agent_bus`` is unavailable (CI without the checkout), the
test skips cleanly via ``pytest.importorskip``.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest

pytest.importorskip(
    "enhanced_agent_bus",
    reason="dispatcher integration requires optional enhanced-agent-bus checkout",
)
from enhanced_agent_bus.core_models import AgentMessage, MessageType
from enhanced_agent_bus.local_bus import LocalEventBus

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.models import HandlerDescriptor, HandlerRegistrySnapshot
from agent_bus_analyzer.observer import Observer
from agent_bus_analyzer.query import get_wiring_defects
from agent_bus_analyzer.store import TraceStore


def _make_empty_snapshot() -> HandlerRegistrySnapshot:
    """An empty registry — every dispatched handler is unwired."""
    return HandlerRegistrySnapshot(
        snapshot_id=str(uuid.uuid4()),
        sampled_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        handlers={},
        source="enhanced_agent_bus",
    )


def _make_snapshot_with(*handler_names: str) -> HandlerRegistrySnapshot:
    from datetime import UTC, datetime

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
        sampled_at=datetime.now(UTC),
        handlers=handlers,
        source="enhanced_agent_bus",
    )


@pytest.mark.asyncio
async def test_dispatcher_unwired_dispatch_finding(tmp_path: Path) -> None:
    """Publish to an unknown handler → unwired_dispatch finding via dispatcher path."""
    bus = LocalEventBus()
    await bus.start()
    try:
        queue = CaptureQueue(capacity=100)
        observer = Observer(queue=queue, constitutional_hash="608508a9bd224290")
        await observer.attach(bus)

        store = TraceStore(tmp_path / "store")
        writer = asyncio.create_task(store.writer_loop(queue, drain_on_idle=False))

        # Publish through the real bus dispatcher.
        msg = AgentMessage(
            from_agent="test-agent",
            to_agent="not.registered.handler",
            message_type=MessageType.COMMAND,
        )
        await bus.send_message(msg)

        # Allow bus consumer + writer to land the event.
        await asyncio.sleep(0.3)

        # Verify the event landed in the store (confirms dispatcher path active).
        traces = store.list_traces()
        assert traces.items, "no traces from dispatcher publish — wiring broken"

        # Now run wiring defect detection with an empty registry snapshot.
        snap = _make_empty_snapshot()
        summary = get_wiring_defects(store, window_seconds=60, snapshot=snap)

        unwired = [f for f in summary.findings if f.kind == "unwired_dispatch"]
        assert unwired, (
            "expected unwired_dispatch finding for 'not.registered.handler' "
            f"but got findings: {summary.findings}"
        )
        assert any(f.handler_name == "not.registered.handler" for f in unwired)

        writer.cancel()
        try:
            await writer
        except asyncio.CancelledError:
            pass
    finally:
        await bus.stop()


@pytest.mark.asyncio
async def test_dispatcher_no_finding_when_handler_registered(tmp_path: Path) -> None:
    """Publish to a known handler → no unwired_dispatch finding."""
    bus = LocalEventBus()
    await bus.start()
    try:
        queue = CaptureQueue(capacity=100)
        observer = Observer(queue=queue, constitutional_hash="608508a9bd224290")
        await observer.attach(bus)

        store = TraceStore(tmp_path / "store")
        writer = asyncio.create_task(store.writer_loop(queue, drain_on_idle=False))

        msg = AgentMessage(
            from_agent="test-agent",
            to_agent="policy.evaluate",
            message_type=MessageType.COMMAND,
        )
        await bus.send_message(msg)

        await asyncio.sleep(0.3)

        # Registry knows about policy.evaluate.
        snap = _make_snapshot_with("policy.evaluate")
        summary = get_wiring_defects(store, window_seconds=60, snapshot=snap)

        unwired = [f for f in summary.findings if f.kind == "unwired_dispatch"]
        assert not unwired, f"unexpected unwired_dispatch findings: {unwired}"

        writer.cancel()
        try:
            await writer
        except asyncio.CancelledError:
            pass
    finally:
        await bus.stop()
