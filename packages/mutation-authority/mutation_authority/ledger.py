"""Append-only, hash-chained audit ledger (mutation_ledger.jsonl).

Every event embeds the hash of the previous event, so any retroactive
edit, deletion, or reordering breaks the chain. The genesis event binds
the ledger to the governance-root manifest hash and to a baseline
snapshot of the governed resources, which makes the ledger the single
source of truth for "what is the authorized state of resource X".
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import hash_obj

GENESIS_PREV = "0" * 64

EVENT_GENESIS = "GENESIS"
EVENT_DECISION = "DECISION"
EVENT_COMMIT = "COMMIT"


class LedgerIntegrityError(Exception):
    """The audit chain does not verify. Fail closed."""


@dataclass(frozen=True)
class LedgerEvent:
    seq: int
    type: str
    timestamp: int
    payload: dict[str, Any]
    prev_event_hash: str
    event_hash: str

    def body(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "type": self.type,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "prev_event_hash": self.prev_event_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "event_hash": self.event_hash}


class AuditLedger:
    """`anchor_path` is a head checkpoint stored OUTSIDE the governed tree
    (same privilege tier as the keystore). It pins the expected event count
    and head hash, which makes tail truncation, full rewrite, and
    delete-and-regenerate attacks on the JSONL file detectable — internal
    hash-chain consistency alone cannot prove completeness.
    """

    def __init__(
        self,
        path: Path,
        anchor_path: Path | None = None,
        *,
        allow_unanchored: bool = False,
    ):
        if anchor_path is None and not allow_unanchored:
            raise LedgerIntegrityError(
                "AuditLedger requires an out-of-tree anchor_path: without it, "
                "tail truncation and delete-and-regenerate attacks are "
                "undetectable and consumed receipts become replayable. Pass "
                "allow_unanchored=True only for insecure development use."
            )
        self.path = path
        self.anchor_path = anchor_path
        # Reentrancy state for _write_lock/transaction: an RLock serializes
        # threads sharing this instance, and the depth counter lets a
        # transaction() holder append without re-flocking the sidecar (a
        # second flock on a fresh fd would deadlock against our own lock).
        self._tx_guard = threading.RLock()
        self._tx_depth = 0
        # File descriptor pinned to the ledger for the duration of a locked
        # transaction, plus the thread that owns it. Every read and write
        # inside the transaction goes through this ONE descriptor, so the
        # object that was verified is byte-for-byte the object appended to —
        # reopening by pathname between verify and append would let a
        # symlink/rename swap redirect the append to an unverified file.
        self._pinned_fd: int | None = None
        # Parent directory descriptor retained alongside the pinned ledger
        # fd: pinning proves the fd cannot be redirected, but not that it
        # still NAMES self.path — a writer to the ledger directory could
        # rename the ledger away mid-transaction and install a regular copy
        # at the configured path, detaching the whole transaction. The
        # directory entry is revalidated against this descriptor before any
        # append is accepted.
        self._pinned_parent_fd: int | None = None
        self._tx_owner: int | None = None

    # -- construction -----------------------------------------------------

    @classmethod
    def initialize(
        cls,
        path: Path,
        root_manifest_hash: str,
        baseline: dict[str, str],
        timestamp: int,
        anchor_path: Path | None = None,
        *,
        allow_unanchored: bool = False,
    ) -> AuditLedger:
        if path.exists():
            raise LedgerIntegrityError(f"ledger already exists: {path}")
        if anchor_path is not None and anchor_path.exists():
            raise LedgerIntegrityError(
                f"ledger anchor already exists: {anchor_path} "
                "(refusing to regenerate history for an existing chain)"
            )
        ledger = cls(path, anchor_path=anchor_path, allow_unanchored=allow_unanchored)
        ledger._append(
            EVENT_GENESIS,
            {"root_manifest_hash": root_manifest_hash, "baseline": baseline},
            timestamp,
        )
        return ledger

    # -- append -----------------------------------------------------------

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        """Exclusive cross-process lock serializing EVERY ledger writer over
        the whole tail-read → append → anchor-replace → rollback sequence.

        Two concurrent writers that both snapshot the same tail would emit
        events with the same seq and predecessor hash, race the shared anchor
        temporary file, and — if one anchor replacement failed — its
        exception-path truncation to the stale prior size could delete the
        other writer's already-fsynced event, leaving an ACCEPTED effect
        unrecorded. The lock lives in a sidecar file (never the ledger itself,
        so locking cannot create or truncate it) and releases on close (and on
        process death).

        Reentrant: a caller already inside transaction() (which holds this
        same lock) may append without deadlocking on a second flock of the
        sidecar. The RLock additionally serializes threads that share this
        ledger instance, since flock cannot arbitrate between them."""
        with self._tx_guard:
            if self._tx_depth:
                self._tx_depth += 1
                try:
                    yield
                finally:
                    self._tx_depth -= 1
                return
            lock_fd = self._acquire_write_lock_fd()
            try:
                self._pin_ledger_fd()
                self._tx_depth = 1
                self._tx_owner = threading.get_ident()
                try:
                    yield
                finally:
                    self._tx_depth = 0
                    self._tx_owner = None
                    if self._pinned_fd is not None:
                        os.close(self._pinned_fd)
                        self._pinned_fd = None
                    if self._pinned_parent_fd is not None:
                        os.close(self._pinned_parent_fd)
                        self._pinned_parent_fd = None
            finally:
                os.close(lock_fd)

    def _acquire_write_lock_fd(self) -> int:
        """flock a verified regular sidecar lock file and return its fd.

        The sidecar must be opened without following symlinks and its
        directory entry re-verified AFTER the flock is granted: a plain
        `open("a")` would follow an attacker-planted symlink (two writers
        could then flock different inodes and both believe they hold the
        exclusive lock), and an unlink-and-recreate between open and flock
        detaches the locked inode from the entry the next writer opens."""
        lock_name = self.path.name + ".lock"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for _ in range(64):
                try:
                    fd = os.open(
                        lock_name,
                        os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW,
                        0o644,
                        dir_fd=parent_fd,
                    )
                except OSError as exc:
                    raise LedgerIntegrityError(
                        f"ledger lock is not a verified regular file: {exc}"
                    ) from exc
                acquired = False
                try:
                    pinned = os.fstat(fd)
                    if not stat.S_ISREG(pinned.st_mode):
                        raise LedgerIntegrityError("ledger lock is not a verified regular file")
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    try:
                        named = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue  # entry vanished after our open; retry
                    if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino):
                        continue  # entry replaced after our open; retry
                    acquired = True
                    return fd
                finally:
                    if not acquired:
                        os.close(fd)
            raise LedgerIntegrityError(
                "ledger lock file kept changing while acquiring the write lock"
            )
        finally:
            os.close(parent_fd)

    def _pin_ledger_fd(self) -> None:
        """Open and identity-check the ledger ONCE per locked transaction.

        The open is anchored to the parent directory fd and refuses to follow
        a symlink (O_NOFOLLOW) or accept a non-regular file, so a swapped-in
        link cannot redirect subsequent verified reads or appends to a file
        outside the governed store. The parent descriptor is RETAINED for the
        transaction so the directory entry can be revalidated at accept time
        (see _revalidate_pinned_entry). A missing ledger is legal only for
        the genesis append, which creates it exclusively in _append_locked.
        """
        parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                fd = os.open(self.path.name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                self._pinned_fd = None
                self._pinned_parent_fd = parent_fd
                parent_fd = -1  # retained for genesis create + revalidation
                return
            except OSError as exc:
                raise LedgerIntegrityError(f"ledger is not a verified regular file: {exc}") from exc
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise LedgerIntegrityError("ledger is not a verified regular file")
            self._pinned_fd = fd
            self._pinned_parent_fd = parent_fd
            parent_fd = -1  # ownership transferred to the transaction
        finally:
            if parent_fd != -1:
                os.close(parent_fd)

    def _revalidate_pinned_entry(self) -> None:
        """Prove the pinned descriptor still names self.path before accepting.

        Pinning the fd defeats symlink/rename swaps of the object being
        written, but not detachment: after a rename-away plus a regular-file
        copy installed at the configured path, the transaction would commit
        to a detached chain while the configured ledger silently misses the
        event. Re-stat the directory entry through the retained parent
        descriptor and require the same (st_dev, st_ino) as the pinned fd."""
        if self._pinned_fd is None or self._pinned_parent_fd is None:
            raise LedgerIntegrityError("ledger transaction lost its pinned descriptors")
        try:
            named = os.stat(self.path.name, dir_fd=self._pinned_parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise LedgerIntegrityError(
                f"ledger directory entry vanished mid-transaction: {exc}"
            ) from exc
        pinned = os.fstat(self._pinned_fd)
        if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise LedgerIntegrityError(
                "ledger was renamed or replaced mid-transaction — the pinned "
                "descriptor no longer names the configured ledger path"
            )

    def _read_raw(self) -> bytes:
        """Raw ledger bytes: through the pinned fd inside a transaction the
        calling thread owns (so verify and append see the same object), by
        pathname otherwise (plain reads outside any write sequence)."""
        if self._tx_depth and self._tx_owner == threading.get_ident():
            if self._pinned_fd is None:
                return b""
            size = os.fstat(self._pinned_fd).st_size
            return os.pread(self._pinned_fd, size, 0)
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return b""

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Exclusive cross-process ledger transaction for a read-check-append
        sequence that spans more than one call (e.g. DecisionEngine.decide's
        open-receipt conflict check followed by the ALLOW append). Holding
        this lock guarantees no other writer can append between the caller's
        reads of ledger state and its own append."""
        with self._write_lock():
            yield

    def append(self, event_type: str, payload: dict[str, Any], timestamp: int) -> LedgerEvent:
        if event_type not in (EVENT_DECISION, EVENT_COMMIT):
            raise ValueError(f"unsupported event type: {event_type}")
        return self._append(event_type, payload, timestamp)

    def _append(self, event_type: str, payload: dict[str, Any], timestamp: int) -> LedgerEvent:
        with self._write_lock():
            return self._append_locked(event_type, payload, timestamp)

    def _append_locked(
        self, event_type: str, payload: dict[str, Any], timestamp: int
    ) -> LedgerEvent:
        events = list(self.events())
        prev_hash = events[-1].event_hash if events else GENESIS_PREV
        body = {
            "seq": len(events),
            "type": event_type,
            "timestamp": timestamp,
            "payload": payload,
            "prev_event_hash": prev_hash,
        }
        event = LedgerEvent(**body, event_hash=hash_obj(body))
        if self._pinned_fd is None:
            # Genesis append: the ledger does not exist yet. Create it
            # exclusively (O_EXCL) and without following links (O_NOFOLLOW),
            # relative to the RETAINED parent descriptor, so a pre-planted
            # symlink at the ledger path cannot redirect the new chain
            # outside the governed store.
            if self._pinned_parent_fd is None:
                raise LedgerIntegrityError("ledger transaction lost its pinned descriptors")
            try:
                self._pinned_fd = os.open(
                    self.path.name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o644,
                    dir_fd=self._pinned_parent_fd,
                )
            except OSError as exc:
                raise LedgerIntegrityError(f"cannot create ledger: {exc}") from exc
        fd = self._pinned_fd
        prior_size = os.fstat(fd).st_size
        # Append through the SAME pinned descriptor the tail read used —
        # reopening by pathname here would reintroduce the verify/append
        # swap window this transaction exists to close.
        data = (json.dumps(event.to_dict(), sort_keys=True) + "\n").encode("utf-8")
        os.lseek(fd, 0, os.SEEK_END)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
        try:
            # Before ACCEPTING (advancing the anchor), prove the pinned
            # descriptor still names the configured ledger path: a rename
            # after _pin_ledger_fd would otherwise commit this event to a
            # detached chain while the file at self.path misses it.
            self._revalidate_pinned_entry()
            self._write_anchor(count=len(events) + 1, head_hash=event.event_hash)
        except Exception:
            # The ledger and its anchor must move together: an appended event
            # without an advanced anchor would make every subsequent verify
            # fail (or worse, mask a truncation). Roll the append back and
            # surface the failure instead of leaving the two out of sync.
            os.ftruncate(fd, prior_size)
            os.fsync(fd)
            raise
        return event

    def rollback_last(self, event: LedgerEvent) -> None:
        """Remove an exact just-appended head event and rewind its anchor.

        This is only for an effect transaction whose post-append filesystem
        identity check failed. Refuse if anything else has advanced the chain.
        """
        with self._write_lock():
            events = list(self.events())
            if not events or events[-1].event_hash != event.event_hash:
                raise LedgerIntegrityError("cannot roll back ledger: appended event is not head")
            if self._pinned_fd is None:
                raise LedgerIntegrityError("cannot roll back ledger: ledger file missing")
            lines = self._read_raw().splitlines(keepends=True)
            if len(lines) != len(events):
                raise LedgerIntegrityError("cannot roll back ledger: event framing changed")
            prior_size = sum(len(line) for line in lines[:-1])
            os.ftruncate(self._pinned_fd, prior_size)
            os.fsync(self._pinned_fd)
            prior = events[-2] if len(events) > 1 else None
            self._write_anchor(
                count=len(events) - 1,
                head_hash=prior.event_hash if prior is not None else GENESIS_PREV,
            )

    def _write_anchor(self, count: int, head_hash: str) -> None:
        if self.anchor_path is None:
            return
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.anchor_path.with_name(self.anchor_path.name + ".tmp")
        tmp.write_text(json.dumps({"count": count, "head_hash": head_hash}, sort_keys=True) + "\n")
        os.replace(tmp, self.anchor_path)

    # -- read + verify ----------------------------------------------------

    def events(self) -> Iterator[LedgerEvent]:
        for raw_line in self._read_raw().splitlines():
            line = raw_line.strip()
            if not line:
                continue
            data = json.loads(line.decode("utf-8"))
            yield LedgerEvent(
                seq=data["seq"],
                type=data["type"],
                timestamp=data["timestamp"],
                payload=data["payload"],
                prev_event_hash=data["prev_event_hash"],
                event_hash=data["event_hash"],
            )

    def verify_chain(self) -> None:
        """Recompute every event hash and every chain link.

        Raises LedgerIntegrityError on the first broken link.
        """
        prev_hash = GENESIS_PREV
        expected_seq = 0
        saw_genesis = False
        for event in self.events():
            if event.seq != expected_seq:
                raise LedgerIntegrityError(
                    f"sequence gap at seq={event.seq} (expected {expected_seq})"
                )
            if event.seq == 0:
                if event.type != EVENT_GENESIS:
                    raise LedgerIntegrityError("first event is not GENESIS")
                saw_genesis = True
            elif event.type == EVENT_GENESIS:
                raise LedgerIntegrityError(f"duplicate GENESIS at seq={event.seq}")
            if event.prev_event_hash != prev_hash:
                raise LedgerIntegrityError(f"chain break at seq={event.seq}")
            if hash_obj(event.body()) != event.event_hash:
                raise LedgerIntegrityError(f"event hash mismatch at seq={event.seq}")
            prev_hash = event.event_hash
            expected_seq += 1
        if not saw_genesis:
            raise LedgerIntegrityError("ledger has no GENESIS event")
        self._verify_anchor(count=expected_seq, head_hash=prev_hash)

    def _verify_anchor(self, count: int, head_hash: str) -> None:
        """Completeness proof: the chain must end exactly at the anchored head.

        Internal hash-chain checks prove a self-consistent PREFIX; only the
        out-of-tree anchor proves nothing was truncated, rewritten, or
        regenerated.
        """
        if self.anchor_path is None:
            return
        if not self.anchor_path.exists():
            raise LedgerIntegrityError("ledger anchor missing (chain unverifiable)")
        try:
            anchor = json.loads(self.anchor_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise LedgerIntegrityError(f"ledger anchor unreadable: {exc}") from exc
        if anchor.get("count") != count or anchor.get("head_hash") != head_hash:
            raise LedgerIntegrityError(
                "ledger does not match anchor checkpoint (truncated, rewritten, or regenerated)"
            )

    # -- derived state ----------------------------------------------------

    def genesis(self) -> LedgerEvent:
        for event in self.events():
            if event.type == EVENT_GENESIS:
                return event
        raise LedgerIntegrityError("ledger has no GENESIS event")

    def authorized_state(self, resource: str) -> str:
        """The hash the resource SHOULD have according to the ledger."""
        state = self.genesis().payload["baseline"].get(resource)
        for event in self.events():
            if event.type == EVENT_COMMIT and event.payload["resource"] == resource:
                state = event.payload["after_hash"]
        from .canonical import ABSENT

        return state if state is not None else ABSENT

    def committed_receipt_ids(self) -> set[str]:
        return {
            event.payload["receipt_id"] for event in self.events() if event.type == EVENT_COMMIT
        }

    def issued_receipts(self) -> dict[str, dict[str, Any]]:
        """receipt_id -> receipt dict, for every ALLOW decision ever made."""
        issued: dict[str, dict[str, Any]] = {}
        for event in self.events():
            if event.type == EVENT_DECISION and event.payload["decision"] == "ALLOW":
                receipt = event.payload["receipt"]
                issued[receipt["receipt_id"]] = receipt
        return issued

    def open_receipts_for(self, resource: str, now: int) -> list[dict[str, Any]]:
        """Receipts on `resource` that are issued, unconsumed, unexpired."""
        committed = self.committed_receipt_ids()
        return [
            receipt
            for receipt in self.issued_receipts().values()
            if receipt["resource"] == resource
            and receipt["receipt_id"] not in committed
            and receipt["expiry"] >= now
        ]

    def head_hash(self) -> str:
        prev = GENESIS_PREV
        for event in self.events():
            prev = event.event_hash
        return prev
