"""Append-only, hash-chained audit ledger (mutation_ledger.jsonl).

Every event embeds the hash of the previous event, so any retroactive
edit, deletion, or reordering breaks the chain. The genesis event binds
the ledger to the governance-root manifest hash and to a baseline
snapshot of the governed resources, which makes the ledger the single
source of truth for "what is the authorized state of resource X".
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
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

    def __init__(self, path: Path, anchor_path: Path | None = None):
        self.path = path
        self.anchor_path = anchor_path

    # -- construction -----------------------------------------------------

    @classmethod
    def initialize(
        cls,
        path: Path,
        root_manifest_hash: str,
        baseline: dict[str, str],
        timestamp: int,
        anchor_path: Path | None = None,
    ) -> AuditLedger:
        if path.exists():
            raise LedgerIntegrityError(f"ledger already exists: {path}")
        if anchor_path is not None and anchor_path.exists():
            raise LedgerIntegrityError(
                f"ledger anchor already exists: {anchor_path} "
                "(refusing to regenerate history for an existing chain)"
            )
        ledger = cls(path, anchor_path=anchor_path)
        ledger._append(
            EVENT_GENESIS,
            {"root_manifest_hash": root_manifest_hash, "baseline": baseline},
            timestamp,
        )
        return ledger

    # -- append -----------------------------------------------------------

    def append(self, event_type: str, payload: dict[str, Any], timestamp: int) -> LedgerEvent:
        if event_type not in (EVENT_DECISION, EVENT_COMMIT):
            raise ValueError(f"unsupported event type: {event_type}")
        return self._append(event_type, payload, timestamp)

    def _append(self, event_type: str, payload: dict[str, Any], timestamp: int) -> LedgerEvent:
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
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        self._write_anchor(count=len(events) + 1, head_hash=event.event_hash)
        return event

    def _write_anchor(self, count: int, head_hash: str) -> None:
        if self.anchor_path is None:
            return
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.anchor_path.with_name(self.anchor_path.name + ".tmp")
        tmp.write_text(json.dumps({"count": count, "head_hash": head_hash}, sort_keys=True) + "\n")
        os.replace(tmp, self.anchor_path)

    # -- read + verify ----------------------------------------------------

    def events(self) -> Iterator[LedgerEvent]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
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
