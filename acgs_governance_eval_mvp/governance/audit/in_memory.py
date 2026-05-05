from __future__ import annotations

import threading
from typing import Any, Iterable

from governance.models import DecisionRecord, sha256_json


GENESIS_HASH = "0" * 64


class InMemoryAuditStore:
    """In-memory audit store mirroring ChainHashAuditStore semantics.

    Same append/last_hash/iter_events/query/verify_chain interface as the disk
    store, but events live in a list. Useful for unit tests that exercise
    governance decisions without touching the filesystem. Produces identical
    event_hash values to the disk store for identical inputs (canonical
    payload + sha256_json), so chain verification logic is interchangeable.
    """

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._last_hash: str = GENESIS_HASH
        self._lock = threading.Lock()

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        with self._lock:
            previous_hash = self._last_hash
            payload = decision.to_dict()
            payload["previous_hash"] = previous_hash
            payload.pop("event_hash", None)
            payload["event_hash"] = sha256_json(payload)
            self._events.append(payload)
            self._last_hash = str(payload["event_hash"])
            return payload

    def last_hash(self) -> str:
        return self._last_hash

    def iter_events(self) -> Iterable[dict[str, Any]]:
        # Snapshot so callers cannot mutate the underlying list mid-iteration.
        for event in list(self._events):
            yield event

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
