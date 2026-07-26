"""Append-only JSONL audit store with hash chaining.

Ported from ``acgs_governance_eval_mvp/governance/audit/jsonl_chain.py``.
Process-safe via a standard-library file lock: ``fcntl.flock`` on POSIX and
``msvcrt.locking`` on Windows. Importing the package requires neither; the lock
primitive is resolved lazily at append time. A host exposing neither primitive
fails closed at append rather than writing without serialization. Both paths
are exercised by ``test_concurrent_appends_preserve_chain_integrity``, which
launches writers in separate OS processes so the POSIX ``fcntl`` branch runs
on the Linux/macOS CI legs and the Windows ``msvcrt`` branch runs on the
Windows CI leg.

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

import json
import os
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, Protocol

# Re-exported for backward compatibility: the lock implementation lives in
# ``gove_zone._locking`` and ``from gove_zone.audit import _exclusive_file_lock``
# must keep working.
from gove_zone._fsprobe import (
    filesystem_is_lock_safe as filesystem_is_lock_safe,
)
from gove_zone._fsprobe import (
    unsafe_fs_override_enabled,
)
from gove_zone._locking import _exclusive_file_lock as _exclusive_file_lock
from gove_zone.decision import DecisionRecord, sha256_json
from gove_zone.errors import AuditError, UnsafeAuditFilesystemError

GENESIS_HASH = "0" * 64


class AuditChainError(AuditError):
    """Raised when the persisted audit chain tail is corrupt or unreadable."""


class AuditAppender(Protocol):
    """Structural audit sink accepted by the kernel.

    The kernel only depends on append semantics: a decision record is persisted
    and the sink returns the complete appended event mapping, including the
    append-produced hash fields.
    """

    def append(self, decision: DecisionRecord) -> Mapping[str, Any]:
        """Append *decision* and return the complete persisted event mapping."""


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
        # Fail-closed startup probe (G1.6): refuse to back the audit chain with a
        # filesystem whose cross-process locking is unreliable (NFS without a
        # lock manager), unless the operator explicitly opts in. Runs BEFORE any
        # directory/file is created so a refusal leaves no side effects.
        if not unsafe_fs_override_enabled() and not filesystem_is_lock_safe(self.path):
            raise UnsafeAuditFilesystemError(
                f"audit path {str(self.path)!r} resolves to a network filesystem "
                "whose fcntl.flock locking is not a reliable cross-process mutex "
                "(NFS without a running lock manager), so the append-only chain "
                "guarantee cannot be honored — refusing to start. If this export "
                "runs lockd and locking is reliable, set "
                "GOVE_ZONE_ALLOW_UNSAFE_FS=1 to override."
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str | None = None
        # File size observed immediately after this instance's own last
        # append (while still holding the lock). Lets the next append skip
        # the tail re-read when nothing else has written in between; any
        # size change falls back to the authoritative tail read.
        self._last_size: int | None = None

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        """Append *decision* and return the persisted event dict.

        Serializes read-then-write under an exclusive platform file lock so
        concurrent callers never produce sibling events pointing at the same
        ``previous_hash``. Writes are fsync'd before the lock is released.
        """
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
            previous_hash = self._previous_hash_locked()
            payload = decision.to_dict()
            payload["previous_hash"] = previous_hash
            payload.pop("event_hash", None)
            payload["event_hash"] = sha256_json(payload)

            data = (
                json.dumps(
                    payload,
                    sort_keys=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            with self.path.open("ab") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
                self._last_size = fh.tell()
            self._last_hash = str(payload["event_hash"])
        return payload

    def append_many(self, decisions: Iterable[DecisionRecord]) -> list[dict[str, Any]]:
        """Append a batch of decisions under ONE lock acquisition and ONE fsync.

        Chain semantics are identical to calling :meth:`append` in a loop —
        every event's ``previous_hash`` still links to the prior event's
        ``event_hash`` — but the whole batch is serialized, written, and
        fsync'd as a single storage transaction.

        Durability trade-off (explicit): a crash between the batched write and
        its single fsync can lose up to the entire batch, whereas per-event
        :meth:`append` bounds the loss to the newest event. Whatever survives
        is always a valid *prefix* of the chain — the chain rules themselves
        are never weakened, and no event is ever readable before it is
        hash-linked. Callers needing per-event durability must keep using
        :meth:`append`.

        Returns the persisted event dicts in append order; an empty batch
        writes nothing and returns ``[]``.
        """
        records = list(decisions)
        if not records:
            return []
        payloads: list[dict[str, Any]] = []
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
            previous_hash = self._previous_hash_locked()
            chunks: list[bytes] = []
            for decision in records:
                payload = decision.to_dict()
                payload["previous_hash"] = previous_hash
                payload.pop("event_hash", None)
                payload["event_hash"] = sha256_json(payload)
                chunks.append(
                    (
                        json.dumps(
                            payload,
                            sort_keys=True,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8")
                )
                previous_hash = str(payload["event_hash"])
                payloads.append(payload)
            with self.path.open("ab") as fh:
                fh.write(b"".join(chunks))
                fh.flush()
                os.fsync(fh.fileno())
                self._last_size = fh.tell()
            self._last_hash = previous_hash
        return payloads

    def _previous_hash_locked(self) -> str:
        """Return the chain tail hash. MUST be called while holding the lock.

        Fast path: when this instance performed the most recent append and
        the file size (stat, under the same lock) is unchanged since, reuse
        the cached tail hash instead of re-reading the file tail. Any other
        observation — different size, missing file, stat error, no prior
        append by this instance — falls back to the authoritative tail read,
        so cross-process interleaving behaves exactly as before.
        """
        if self._last_hash is not None and self._last_size is not None:
            try:
                if self.path.stat().st_size == self._last_size:
                    return self._last_hash
            except OSError:
                pass  # deleted/unreadable → authoritative read (genesis or raise)
        return self._read_last_hash_from_disk()

    def last_hash(self) -> str:
        """Return the event_hash of the most recent event, or genesis."""
        self._last_hash = self._read_last_hash_from_disk()
        # The (_last_hash, _last_size) pair is only trusted as an append
        # fast-path when both were captured together under the append lock.
        self._last_size = None
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
            raise AuditChainError(
                f"could not read audit chain tail from {self.path}: {exc}"
            ) from exc

        if not last_line:
            raise AuditChainError(f"audit chain tail is blank in non-empty file {self.path}")
        try:
            event = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise AuditChainError(
                f"audit chain tail is not valid JSON in {self.path}: {exc}"
            ) from exc
        if not isinstance(event, dict):
            raise AuditChainError(f"audit chain tail is not a JSON object in {self.path}")
        event_hash = event.get("event_hash")
        if not isinstance(event_hash, str):
            raise AuditChainError(f"audit chain tail has invalid event_hash in {self.path}")
        return event_hash

    def iter_events(self) -> Iterable[dict[str, Any]]:
        """Yield every persisted event dict in chain order.

        Raises :class:`AuditChainError` on any malformed line so callers
        such as :meth:`verify_chain` surface the same exception type as
        :meth:`append` instead of leaking a raw ``json.JSONDecodeError``.
        """
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                clean = line.strip()
                if not clean:
                    continue
                try:
                    event = json.loads(clean)
                except json.JSONDecodeError as exc:
                    raise AuditChainError(
                        f"audit chain line {line_number} in {self.path} is not valid JSON: {exc}"
                    ) from exc
                if not isinstance(event, dict):
                    raise AuditChainError(
                        f"audit chain line {line_number} in {self.path} is not a JSON object"
                    )
                yield event

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

    def verify_chain(
        self,
        *,
        expected_count: int | None = None,
        expected_last_hash: str | None = None,
    ) -> dict[str, Any]:
        """Re-walk the chain and report integrity.

        Returns a dict with:
            ``valid`` (bool): True iff every event hash matches, every
              ``previous_hash`` matches the prior ``event_hash``, and any
              supplied external anchor (``expected_count`` / ``expected_last_hash``)
              matches.
            ``checked`` (int): number of events walked.
            ``failures`` (list): per-failure detail dicts.
            ``last_hash`` (str): final ``event_hash`` walked, or genesis.

        **Truncation/rollback detection.** Internal hash-chaining proves the
        persisted events are mutually consistent, but a *prefix* of the chain is
        itself internally consistent: silently deleting whole trailing events
        yields a shorter chain that still re-walks cleanly. Internal walking
        alone therefore cannot detect rollback. Supply an out-of-band anchor to
        close that gap:

        - ``expected_count``: the number of events the chain must contain. A
          ``checked`` below it is reported as a ``length_mismatch`` failure
          (the tail was truncated; a larger ``checked`` means unexpected growth).
        - ``expected_last_hash``: the ``event_hash`` the chain must end on,
          recorded out-of-band after the last trusted append. A mismatch is a
          ``last_hash_mismatch`` failure.

        Persist whichever anchor you can (event count and/or last hash) in a
        store the audit writer cannot rewrite, and pass it here on verification.
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

        if expected_count is not None and checked != expected_count:
            failures.append(
                {
                    "event_id": None,
                    "type": "length_mismatch",
                    "expected": expected_count,
                    "actual": checked,
                }
            )

        if expected_last_hash is not None and previous != expected_last_hash:
            failures.append(
                {
                    "event_id": None,
                    "type": "last_hash_mismatch",
                    "expected": expected_last_hash,
                    "actual": previous,
                }
            )

        return {
            "valid": len(failures) == 0,
            "checked": checked,
            "failures": failures,
            "last_hash": previous,
        }
