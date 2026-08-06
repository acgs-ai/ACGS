"""T062 — capture latency benchmark (SC-005: observer overhead ≤ 5 %).

Measures end-to-end ``LocalEventBus.send_message`` latency with and without the
analyzer observer attached.  This matches SC-005's "bus dispatch latency"
wording and avoids the false denominator from comparing the observer hot path
against an unrealistically tiny no-op coroutine.

Median overhead across five paired runs of ≥ 1 000 events dampens GC /
context-switch noise and transient ordering effects.

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
_PAIR_COUNT = 5
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


def _median_paired_overhead_ratio(pairs: list[tuple[float, float]]) -> float:
    """Return the median observer overhead across baseline/observer pairs."""
    return statistics.median(
        (observed - baseline) / max(baseline, 1e-9) for baseline, observed in pairs
    )


def test_median_paired_overhead_rejects_sustained_regression() -> None:
    pairs = [(1.0, 1.06)] * _PAIR_COUNT

    overhead_ratio = _median_paired_overhead_ratio(pairs)

    assert overhead_ratio == pytest.approx(0.06)
    assert overhead_ratio > _SC005_OVERHEAD_THRESHOLD


def test_median_paired_overhead_ignores_single_transient() -> None:
    pairs = [(1.0, 1.01)] * 4 + [(1.0, 1.226)]

    overhead_ratio = _median_paired_overhead_ratio(pairs)

    assert overhead_ratio == pytest.approx(0.01)
    assert overhead_ratio <= _SC005_OVERHEAD_THRESHOLD


@pytest.mark.benchmark
def test_observer_overhead_within_sc005() -> None:
    """SC-005: observer per-event overhead must be ≤ 5 % over the no-op baseline.

    Runs five baseline/observer pairs, alternating measurement order, and uses
    the median paired overhead ratio. Each run uses the median of 1 000 sends.
    """
    pairs: list[tuple[float, float]] = []
    for pair_index in range(_PAIR_COUNT):
        if pair_index % 2 == 0:
            baseline_samples = asyncio.run(_run_bus_samples(_SAMPLE_SIZE, attach_observer=False))
            observed_samples = asyncio.run(_run_bus_samples(_SAMPLE_SIZE, attach_observer=True))
        else:
            observed_samples = asyncio.run(_run_bus_samples(_SAMPLE_SIZE, attach_observer=True))
            baseline_samples = asyncio.run(_run_bus_samples(_SAMPLE_SIZE, attach_observer=False))

        baseline = statistics.median(baseline_samples)
        observed = statistics.median(observed_samples)
        pairs.append((baseline, observed))
        pair_overhead = (observed - baseline) / max(baseline, 1e-9)
        print(
            f"\nSC-005 pair {pair_index + 1}/{_PAIR_COUNT}: "
            f"baseline={baseline * 1e6:.2f} µs/event  "
            f"observer={observed * 1e6:.2f} µs/event  "
            f"overhead={pair_overhead:.1%}"
        )

    overhead_ratio = _median_paired_overhead_ratio(pairs)

    print(
        f"\nSC-005 median paired overhead={overhead_ratio:.1%}  "
        f"threshold={_SC005_OVERHEAD_THRESHOLD:.0%}"
    )

    assert overhead_ratio <= _SC005_OVERHEAD_THRESHOLD, (
        f"SC-005 FAIL: median paired observer overhead {overhead_ratio:.1%} "
        f"> {_SC005_OVERHEAD_THRESHOLD:.0%} threshold"
    )
