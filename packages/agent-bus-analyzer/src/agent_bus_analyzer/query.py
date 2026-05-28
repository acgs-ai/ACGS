"""Public query API consumed by the console.

Thin wrapper over ``TraceStore``. The store owns integrity verification;
this layer just shapes the response into the schemas the console expects
(``trace-query.schema.json``).

US2 addition: ``get_wiring_defects`` samples the handler registry and
recent store events, then calls ``wiring.compute_findings``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agent_bus_analyzer.models import (
    Expired,
    RetentionPolicy,
    SingleTrace,
    TraceList,
    WiringDefectSummary,
)
from agent_bus_analyzer.store import TraceStore
from agent_bus_analyzer.wiring import compute_findings, sample_registry

if TYPE_CHECKING:
    from agent_bus_analyzer.models import HandlerRegistrySnapshot


def list_traces(store: TraceStore, *, limit: int = 50) -> TraceList:
    return store.list_traces(limit=limit)


def get_trace(store: TraceStore, correlation_id: str) -> SingleTrace | None:
    return store.get_trace(correlation_id)


def get_trace_or_expired(store: TraceStore, correlation_id: str) -> SingleTrace | Expired | None:
    """Return a live trace, an expired sidecar, or None (never existed).

    Checks for an expired sidecar at
    ``{store_dir}/expired/{correlation_id}.json`` before returning None.
    The sidecar must be a JSON object with ``max_age_days`` (int) and
    ``purged_at`` (ISO-8601 string) fields matching ``RetentionPolicy``.
    """
    live = store.get_trace(correlation_id)
    if live is not None:
        return live

    expired_path = store.store_dir / "expired" / f"{correlation_id}.json"
    if expired_path.exists():
        try:
            data = json.loads(expired_path.read_text(encoding="utf-8"))
            retention = RetentionPolicy(
                max_age_days=int(data["max_age_days"]),
                purged_at=data["purged_at"],
            )
            return Expired(
                correlation_id=correlation_id,
                retention_policy=retention,
            )
        except (KeyError, ValueError, json.JSONDecodeError):
            return None

    return None


def _read_recent_events(store: TraceStore, window_seconds: float) -> list[dict[str, Any]]:
    """Scan all trace JSONL files and return events within the time window.

    Uses the public ``store.store_dir`` attribute (read-only access). We
    iterate files directly rather than calling ``store.list_traces()`` to
    avoid triggering full hash-chain verification on every defect poll.
    """
    cutoff_ts = datetime.now(UTC).timestamp() - window_seconds
    events: list[dict[str, Any]] = []
    traces_dir = store.store_dir / "traces"
    if not traces_dir.exists():
        return events
    for jsonl_path in traces_dir.glob("*.jsonl"):
        try:
            with jsonl_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    clean = line.strip()
                    if not clean:
                        continue
                    try:
                        ev = json.loads(clean)
                    except json.JSONDecodeError:
                        continue
                    recorded_raw = ev.get("recorded_at")
                    if recorded_raw is None:
                        continue
                    try:
                        recorded_dt = datetime.fromisoformat(str(recorded_raw))
                        if recorded_dt.timestamp() >= cutoff_ts:
                            events.append(ev)
                    except (ValueError, TypeError):
                        continue
        except OSError:
            continue
    return events


def get_wiring_defects(
    store: TraceStore,
    *,
    window_seconds: int = 60,
    snapshot: HandlerRegistrySnapshot | None = None,
    bus: Any = None,
    gove_zone_kernel: Any = None,
) -> WiringDefectSummary:
    """Return a WiringDefectSummary for the current observation window.

    Parameters
    ----------
    store:
        The live TraceStore — used to read recent events (read-only).
    window_seconds:
        How far back (in seconds) to scan for recent dispatch events.
    snapshot:
        Injected HandlerRegistrySnapshot for testability. When None,
        ``sample_registry(bus, gove_zone_kernel)`` is called.
    bus:
        Optional live bus object for runtime sampling. Ignored when
        ``snapshot`` is provided.
    gove_zone_kernel:
        Optional live gove-zone kernel object. Ignored when ``snapshot``
        is provided.
    """
    if snapshot is None:
        snapshot = sample_registry(bus, gove_zone_kernel)
    recent_events = _read_recent_events(store, float(window_seconds))
    return compute_findings(snapshot, recent_events, window_seconds=float(window_seconds))
