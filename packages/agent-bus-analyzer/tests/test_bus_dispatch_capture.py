"""T016 — DISPATCHER-LEVEL: real LocalEventBus → real subscribe → analyzer store.

This is the Constitution Principle III load-bearing test. We do NOT call
``Observer.on_bus_event`` directly. We boot a real ``LocalEventBus``,
attach the observer via ``await observer.attach(bus)``, publish through
``bus.send_message()``, and assert the analyzer's store contains the
event. If the wiring breaks, this test breaks — not the unit tests.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip(
    "enhanced_agent_bus",
    reason="dispatcher integration requires optional enhanced-agent-bus checkout",
)
from enhanced_agent_bus.core_models import AgentMessage, MessageType
from enhanced_agent_bus.local_bus import LocalEventBus

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.observer import Observer
from agent_bus_analyzer.store import TraceStore


@pytest.mark.asyncio
async def test_bus_publish_lands_in_analyzer_store(tmp_path: Path) -> None:
    bus = LocalEventBus()
    await bus.start()
    try:
        queue = CaptureQueue(capacity=100)
        observer = Observer(queue=queue, constitutional_hash="608508a9bd224290")
        await observer.attach(bus)

        store = TraceStore(tmp_path / "store")
        writer = asyncio.create_task(store.writer_loop(queue, drain_on_idle=False))

        msg = AgentMessage(
            from_agent="claude:worker-03",
            to_agent="policy.evaluate",
            message_type=MessageType.COMMAND,
        )
        await bus.send_message(msg)

        # Give the bus consumer and our writer a moment to land the event.
        await asyncio.sleep(0.3)

        traces = store.list_traces()
        assert traces.items, "no traces persisted from a real bus publish"
        single = store.get_trace(traces.items[0].correlation_id)
        assert single is not None
        assert single.events, "trace had no events"
        ev = single.events[0]
        assert ev.source_agent == "claude:worker-03"
        assert ev.target_handler_declared == "policy.evaluate"
        assert ev.kind == "dispatch"
        assert ev.constitutional_hash == "608508a9bd224290"

        writer.cancel()
        try:
            await writer
        except asyncio.CancelledError:
            pass
    finally:
        await bus.stop()
