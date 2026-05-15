"""Unit tests for CaptureQueue drop + gap semantics."""

from __future__ import annotations

import pytest

from agent_bus_analyzer.capture import CaptureQueue


def test_try_put_succeeds_until_capacity() -> None:
    q = CaptureQueue(capacity=2)
    assert q.try_put({"id": 1}) is True
    assert q.try_put({"id": 2}) is True
    assert q.try_put({"id": 3}) is False
    assert q.gap_open() is True
    assert q.qsize() == 2


def test_close_gap_returns_window_and_counts_drops() -> None:
    q = CaptureQueue(capacity=1)
    q.try_put({"id": 1})  # ok
    assert q.try_put({"id": 2}) is False  # drop -> gap opens
    assert q.try_put({"id": 3}) is False  # drop -> gap extends
    window = q.close_gap()
    assert window is not None
    started, ended, count = window
    assert count == 2
    assert ended >= started


def test_close_gap_resets_state() -> None:
    q = CaptureQueue(capacity=1)
    q.try_put({"id": 1})
    q.try_put({"id": 2})  # drop
    q.close_gap()
    assert q.gap_open() is False
    assert q.close_gap() is None


def test_negative_capacity_rejected() -> None:
    with pytest.raises(ValueError):
        CaptureQueue(capacity=0)
    with pytest.raises(ValueError):
        CaptureQueue(capacity=-1)


async def test_get_awaits_until_event_arrives() -> None:
    q = CaptureQueue(capacity=4)
    q.try_put({"id": 1})
    event = await q.get()
    assert event == {"id": 1}
