"""Opt-in raw-arguments side-store for true decision re-derivation.

The audit chain stores only ``argument_hash`` — never raw arguments. That
hash-only property is a privacy and chain-size guarantee (see
:mod:`gove_zone.audit`). To re-run a policy against the original call during
replay, the raw :class:`~gove_zone.tool.ToolCall` must be retained somewhere.
This side-store is that retention: a separate, off-by-default JSONL file keyed
by ``event_id``.

It is deliberately **not** a hash chain — it is a lookup table. Integrity is
not self-contained; it comes from cross-checking each record's raw args against
the tamper-evident audit chain at replay time (see
:func:`gove_zone.replay.replay_from_side_store`). The store is independently
deletable/prunable so operators can drop raw-args retention without touching the
audit chain.

A ``redact`` predicate marks sensitive calls as non-persistable: those events
are written as a tombstone (``{event_id, redacted: true}``) with no raw args, so
replay can fall back to event-only verification honestly rather than claiming a
re-derivation it cannot perform.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from gove_zone.decision import DecisionRecord
from gove_zone.tool import ToolCall


class ReplaySideStore:
    """Append-only JSONL lookup table of raw ``ToolCall`` data keyed by event id.

    Usage::

        store = ReplaySideStore("/var/log/gove-zone/replay.jsonl")
        store.append(call, record)
        side_record = store.get(record.event_id)

    Pass ``redact`` to exclude sensitive calls from raw persistence; matching
    calls are stored as tombstones.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        redact: Callable[[ToolCall], bool] | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._redact = redact

    def append(self, call: ToolCall, record: DecisionRecord) -> dict[str, Any]:
        """Persist one record for ``record.event_id`` and return the written entry.

        When ``redact(call)`` is truthy the entry is a tombstone carrying no raw
        args; otherwise it carries the raw call (args, state, path, actor, goal,
        tool) plus the recorded ``argument_hash``, ``policy_version``, and
        ``decision`` for convenient cross-referencing against the audit chain.
        """
        entry: dict[str, Any]
        if self._redact is not None and self._redact(call):
            entry = {"event_id": record.event_id, "redacted": True}
        else:
            entry = {
                "event_id": record.event_id,
                "tool": call.name,
                "actor": call.actor,
                "goal": call.goal,
                "path": list(call.path),
                "args": dict(call.args),
                "state": dict(call.state),
                "argument_hash": record.argument_hash,
                "policy_version": record.policy_version,
                "decision": record.decision.value,
            }
        line = (
            json.dumps(
                entry,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def get(self, event_id: str) -> dict[str, Any] | None:
        """Return the last record stored for ``event_id``, or ``None``."""
        found: dict[str, Any] | None = None
        for entry in self.iter_records():
            if entry.get("event_id") == event_id:
                found = entry
        return found

    def iter_records(self) -> Iterable[dict[str, Any]]:
        """Yield every persisted record dict in write order.

        Malformed or non-object lines are skipped rather than raised. This store
        is a non-authoritative lookup table — integrity comes from the audit
        chain cross-check at replay time, not from the side-store itself. A
        corrupt line therefore must not break lookups of other events; a missing
        or unparseable target record simply surfaces as ``get() -> None``, which
        :func:`gove_zone.replay.replay_from_side_store` callers treat as an
        honest event-only fallback rather than a claimed re-derivation.
        """
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                clean = line.strip()
                if not clean:
                    continue
                try:
                    entry = json.loads(clean)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    yield entry
