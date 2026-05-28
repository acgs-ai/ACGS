"""T062 — capture latency benchmark (SC-005: observer overhead ≤ 5 %).

Measures end-to-end ``LocalEventBus.send_message`` latency with and without the
analyzer observer attached.  This matches SC-005's "bus dispatch latency"
wording and avoids the false denominator from comparing the observer hot path
against an unrealistically tiny no-op coroutine.

Median over ≥ 1 000 events dampens GC / context-switch noise.

Run with ``-m benchmark`` to include, or ``-m 'not benchmark'`` to skip.
"""

from __future__ import annotations

import asyncio
import statistics
import time

import pytest

pytest.importorskip(
    "enhanced_agent_bus",
    reason="latency benchmark requires optional enhanced-agent-bus checkout",
)
from enhanced_agent_bus.core_models import AgentMessage, MessageType
from enhanced_agent_bus.local_bus import LocalEventBus

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.observer import Observer

_SAMPLE_SIZE = 1_000
_SC005_OVERHEAD_THRESHOLD = 0.05  # 5 %
_CONST_HASH = "a1b2c3d4e5f60718"


def _make_msg(i: int) -> AgentMessage:
    return AgentMessage(
        from_agent="bench-sender",
        to_agent="bench-handler",
        message_type=MessageType.COMMAND,
        content={"index": i},
        conversation_id=f"bench-trace-{i // 10:05d}",
        message_id=f"bench-msg-{i:06d}",
        metadata={"constitutional_hash": _CONST_HASH},
    )


async def _run_bus_samples(n: int, *, attach_observer: bool) -> list[float]:
    """Measure LocalEventBus send latency with optional observer attached."""
    bus = LocalEventBus()
    await bus.start()
    samples: list[float] = []
    try:
        if attach_observer:
            queue: CaptureQueue = CaptureQueue(capacity=n + 100)
            observer = Observer(queue=queue, constitutional_hash=_CONST_HASH)
            await observer.attach(bus)

        for i in range(n):
            msg = _make_msg(i)
            t0 = time.perf_counter()
            await bus.send_message(msg)
            samples.append(time.perf_counter() - t0)
        return samples
    finally:
        await bus.stop()


@pytest.mark.benchmark
def test_observer_overhead_within_sc005() -> None:
    """SC-005: observer per-event overhead must be ≤ 5 % over the no-op baseline.

    Uses median over 1 000 bus sends to dampen noise. The comparison is:
        overhead_ratio = (observed_bus_median - baseline_bus_median) / baseline_bus_median
    and must be ≤ 0.05.

    If this flakes on heavily-loaded CI, increase _SAMPLE_SIZE or run with
    ``-m 'not benchmark'`` to skip — do not delete the test.
    """
    baseline_samples = asyncio.run(_run_bus_samples(_SAMPLE_SIZE, attach_observer=False))
    observed_samples = asyncio.run(_run_bus_samples(_SAMPLE_SIZE, attach_observer=True))

    baseline = statistics.median(baseline_samples)
    observed = statistics.median(observed_samples)

    overhead_ratio = (observed - baseline) / max(baseline, 1e-9)

    print(
        f"\nSC-005 latency: baseline={baseline * 1e6:.2f} µs/event  "
        f"observer={observed * 1e6:.2f} µs/event  "
        f"overhead={overhead_ratio:.1%}  threshold={_SC005_OVERHEAD_THRESHOLD:.0%}"
    )

    assert overhead_ratio <= _SC005_OVERHEAD_THRESHOLD, (
        f"SC-005 FAIL: observer overhead {overhead_ratio:.1%} "
        f"> {_SC005_OVERHEAD_THRESHOLD:.0%} threshold "
        f"(baseline={baseline * 1e6:.2f} µs, observer={observed * 1e6:.2f} µs)"
    )
