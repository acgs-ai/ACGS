"""Bounded in-process capture queue with ingest-gap window tracking.

Producer-consumer between the observer callback (hot path) and the writer
task (cold path). When the queue is full, the producer drops the event
and opens an ingest-gap window. The writer emits a single
``ingest-gap`` marker covering the dropped window on resumption.

Drop, not block: FR-013 forbids blocking the bus. The upstream is the
production path; the analyzer is the observer.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any


class CaptureQueue:
    """Bounded ``asyncio.Queue`` wrapper that records dropped-event windows."""

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError(f"capacity must be positive, got {capacity}")
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=capacity)
        self._capacity = capacity
        self._gap_start: datetime | None = None
        self._dropped_in_gap: int = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    def qsize(self) -> int:
        return self._queue.qsize()

    def gap_open(self) -> bool:
        return self._gap_start is not None

    def try_put(self, event: dict[str, Any]) -> bool:
        """Non-blocking enqueue.

        Returns ``True`` on success, ``False`` on drop. On drop the gap
        window is opened (if not already open) and the dropped-count is
        incremented. The caller MUST NOT retry — retrying would risk
        back-pressuring the upstream bus.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._record_drop()
            return False
        return True

    def _record_drop(self) -> None:
        if self._gap_start is None:
            self._gap_start = datetime.now(UTC)
        self._dropped_in_gap += 1

    def close_gap(self) -> tuple[datetime, datetime, int] | None:
        """Close the current gap window, if open.

        Returns ``(gap_started_at, gap_ended_at, dropped_count)`` or
        ``None`` if no gap was open. Calling on a closed gap is a no-op
        that returns ``None``.
        """
        if self._gap_start is None:
            return None
        start = self._gap_start
        end = datetime.now(UTC)
        count = self._dropped_in_gap
        self._gap_start = None
        self._dropped_in_gap = 0
        return start, end, count

    async def get(self) -> dict[str, Any]:
        """Await the next event. Blocks until one is available."""
        return await self._queue.get()
