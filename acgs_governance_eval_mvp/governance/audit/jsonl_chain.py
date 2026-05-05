from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any, Iterable

from governance.models import DecisionRecord, sha256_json


GENESIS_HASH = "0" * 64


class ChainHashAuditStore:
    """Append-only JSONL audit store with hash chaining.

    Each event hash covers the canonical event payload excluding event_hash.
    previous_hash links to the prior event_hash.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        # Serialize read-then-write under an exclusive lock so concurrent
        # callers do not produce sibling events pointing at the same
        # previous_hash. Without this, verify_chain() reports the chain
        # broken under any thread- or process-level concurrency.
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                previous_hash = self.last_hash()
                payload = decision.to_dict()
                payload["previous_hash"] = previous_hash
                payload.pop("event_hash", None)
                payload["event_hash"] = sha256_json(payload)

                line = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        return payload

    def last_hash(self) -> str:
        last: dict[str, Any] | None = None
        for event in self.iter_events():
            last = event
        if not last:
            return GENESIS_HASH
        return str(last.get("event_hash", GENESIS_HASH))

    def iter_events(self) -> Iterable[dict[str, Any]]:
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
        event_id: str | None = None,
        rule_id: str | None = None,
        gate: str | None = None,
        allow: bool | None = None,
        risk_tag: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for event in self.iter_events():
            if event_id and event.get("event_id") != event_id:
                continue
            if allow is not None and bool(event.get("allow")) is not allow:
                continue
            if rule_id and rule_id not in event.get("rule_ids", []):
                continue
            if gate:
                if not any(check.get("gate") == gate for check in event.get("checks", [])):
                    continue
            if risk_tag:
                tags = event.get("request", {}).get("metadata", {}).get("risk_tags", [])
                if risk_tag not in tags:
                    continue
            out.append(event)
            if len(out) >= limit:
                break
        return out

    def verify_chain(self) -> dict[str, Any]:
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
