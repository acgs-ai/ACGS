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
from gove_zone.path_capability import (
    AttestedDirectory,
    is_proc_fd_path,
    require_attested_directory,
    validate_direct_file_path,
)
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
        _attested_directory: AttestedDirectory | None = None,
        _attested_relative: str | None = None,
    ) -> None:
        self.path = Path(path)
        self._attested_directory = _attested_directory
        self._attested_relative = _attested_relative
        if _attested_directory is None:
            self.path = validate_direct_file_path(
                self.path,
                error_type=ValueError,
                create_parent=True,
            )
        else:
            require_attested_directory(_attested_directory, error_type=ValueError)
            _attested_directory.checkpoint()
        self._redact = redact

    @classmethod
    def from_attested(
        cls,
        directory: AttestedDirectory,
        relative: str,
        *,
        redact: Callable[[ToolCall], bool] | None = None,
    ) -> ReplaySideStore:
        """Borrow *directory* and bind this store to one relative side-store file."""
        require_attested_directory(directory, error_type=ValueError)
        directory.checkpoint()
        directory.proc_path(relative)
        return cls(
            directory.display_path / relative,
            redact=redact,
            _attested_directory=directory,
            _attested_relative=relative,
        )

    def _storage_path(self) -> Path:
        directory = self._attested_directory
        relative = self._attested_relative
        if directory is None or relative is None:
            return validate_direct_file_path(
                self.path,
                error_type=ValueError,
                create_parent=False,
            )
        require_attested_directory(directory, error_type=ValueError)
        directory.checkpoint()
        return directory.proc_path(relative)

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
        with self._storage_path().open("a", encoding="utf-8") as fh:
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
        storage_path = self._storage_path()
        if not storage_path.exists():
            return
        with self._storage_path().open("r", encoding="utf-8") as fh:
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


def _is_proc_descriptor_alias(path: Path) -> bool:
    if is_proc_fd_path(path):
        return True
    parts = Path(os.path.abspath(os.fspath(path))).parts
    return (
        len(parts) >= 5
        and parts[:2] == ("/", "proc")
        and (parts[2].isdecimal() or parts[2] == "thread-self")
        and parts[3] == "fd"
        and parts[4].isdecimal()
    )
