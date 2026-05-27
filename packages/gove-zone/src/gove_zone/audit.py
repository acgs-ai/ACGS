"""Append-only JSONL audit store with hash chaining.

Ported from ``acgs_governance_eval_mvp/governance/audit/jsonl_chain.py``.
Process-safe via ``fcntl.flock`` (Unix-only — Windows support is deferred).

Chain rules:

- ``previous_hash`` of event N links to ``event_hash`` of event N-1.
- The first event's ``previous_hash`` is :data:`GENESIS_HASH` (64 zeros).
- ``event_hash`` is ``sha256(canonical_json(payload))`` where ``payload`` is
  the full event dict minus ``event_hash`` itself.

Concurrent writers are serialized through an exclusive lock on a sidecar
``.lock`` file so two appends never produce sibling events that share a
``previous_hash``.
"""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from gove_zone.decision import DecisionRecord, sha256_json
from gove_zone.errors import AuditError

GENESIS_HASH = "0" * 64


class AuditChainError(AuditError):
    """Raised when the persisted audit chain tail is corrupt or unreadable."""


class ChainHashAuditStore:
    """Append-only JSONL audit store with cryptographic chain hashing.

    Usage::

        store = ChainHashAuditStore("/var/log/gove-zone/audit.jsonl")
        store.append(decision_record)
        result = store.verify_chain()
        assert result["valid"]
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str | None = None

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        """Append *decision* and return the persisted event dict.

        Serializes read-then-write under an exclusive ``fcntl.flock`` so
        concurrent callers never produce sibling events pointing at the same
        ``previous_hash``. Writes are fsync'd before the lock is released.
        """
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                # Always re-read while holding the lock. This instance may
                # have appended earlier, then another store/process may have
                # advanced the chain before this append.
                previous_hash = self._read_last_hash_from_disk()
                payload = decision.to_dict()
                payload["previous_hash"] = previous_hash
                payload.pop("event_hash", None)
                payload["event_hash"] = sha256_json(payload)

                line = (
                    json.dumps(
                        payload,
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
                self._last_hash = str(payload["event_hash"])
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        return payload

    def last_hash(self) -> str:
        """Return the event_hash of the most recent event, or genesis."""
        self._last_hash = self._read_last_hash_from_disk()
        return self._last_hash

    def _read_last_hash_from_disk(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        try:
            size = self.path.stat().st_size
        except OSError as exc:
            raise AuditChainError(f"could not stat audit chain {self.path}: {exc}") from exc
        if size == 0:
            return GENESIS_HASH

        last_line: str | None = None
        try:
            with self.path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                # Tail-read in chunks until the newline preceding the final
                # record, so we never load the whole file.
                chunk = 4096
                buf = b""
                pos = size
                while pos > 0:
                    read = min(chunk, pos)
                    pos -= read
                    fh.seek(pos)
                    buf = fh.read(read) + buf
                    stripped = buf.rstrip(b"\n")
                    nl = stripped.rfind(b"\n")
                    if nl != -1:
                        last_line = stripped[nl + 1 :].decode("utf-8")
                        break
                    if pos == 0:
                        last_line = stripped.decode("utf-8")
                        break
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditChainError(f"could not read audit chain tail from {self.path}: {exc}") from exc

        if not last_line:
            raise AuditChainError(f"audit chain tail is blank in non-empty file {self.path}")
        try:
            event = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise AuditChainError(f"audit chain tail is not valid JSON in {self.path}: {exc}") from exc
        if not isinstance(event, dict):
            raise AuditChainError(f"audit chain tail is not a JSON object in {self.path}")
        event_hash = event.get("event_hash")
        if not isinstance(event_hash, str):
            raise AuditChainError(f"audit chain tail has invalid event_hash in {self.path}")
        return event_hash

    def iter_events(self) -> Iterable[dict[str, Any]]:
        """Yield every persisted event dict in chain order."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                clean = line.strip()
                if clean:
                    yield json.loads(clean)

    def query(
        self,
        *,
        where: Callable[[dict[str, Any]], bool] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Filter events by an arbitrary predicate.

        Domain-specific filters (by tool, rule_id, tenant, etc.) compose on
        top of this — the kernel ships only the generic predicate hook.
        """
        out: list[dict[str, Any]] = []
        for event in self.iter_events():
            if where is not None and not where(event):
                continue
            out.append(event)
            if len(out) >= limit:
                break
        return out

    def verify_chain(self) -> dict[str, Any]:
        """Re-walk the chain and report integrity.

        Returns a dict with:
            ``valid`` (bool): True iff every event hash matches and every
              ``previous_hash`` matches the prior ``event_hash``.
            ``checked`` (int): number of events walked.
            ``failures`` (list): per-failure detail dicts.
            ``last_hash`` (str): final ``event_hash`` walked, or genesis.
        """
        previous = GENESIS_HASH
        checked = 0
        failures: list[dict[str, Any]] = []

        for event in self.iter_events():
            checked += 1
            expected_previous = event.get("previous_hash")
            if expected_previous != previous:
                failures.append(
                    {
                        "event_id": event.get("event_id"),
                        "type": "previous_hash_mismatch",
                        "expected": previous,
                        "actual": expected_previous,
                    }
                )

            claimed_hash = event.get("event_hash")
            payload = dict(event)
            payload.pop("event_hash", None)
            recomputed = sha256_json(payload)
            if claimed_hash != recomputed:
                failures.append(
                    {
                        "event_id": event.get("event_id"),
                        "type": "event_hash_mismatch",
                        "expected": recomputed,
                        "actual": claimed_hash,
                    }
                )

            previous = str(claimed_hash)

        return {
            "valid": len(failures) == 0,
            "checked": checked,
            "failures": failures,
            "last_hash": previous,
        }
