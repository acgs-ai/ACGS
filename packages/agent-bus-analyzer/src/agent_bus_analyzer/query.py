"""Public query API consumed by the console.

Thin wrapper over ``TraceStore``. The store owns integrity verification;
this layer just shapes the response into the schemas the console expects
(``trace-query.schema.json``).
"""

from __future__ import annotations

from agent_bus_analyzer.models import SingleTrace, TraceList
from agent_bus_analyzer.store import TraceStore


def list_traces(store: TraceStore, *, limit: int = 50) -> TraceList:
    return store.list_traces(limit=limit)


def get_trace(store: TraceStore, correlation_id: str) -> SingleTrace | None:
    return store.get_trace(correlation_id)
