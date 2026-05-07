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
        self._last_hash: str | None = None

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        # Serialize read-then-write under an exclusive lock so concurrent
        # callers do not produce sibling events pointing at the same
        # previous_hash. Without this, verify_chain() reports the chain
        # broken under any thread- or process-level concurrency.
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                if self._last_hash is None:
                    self._last_hash = self._read_last_hash_from_disk()
                previous_hash = self._last_hash
                payload = decision.to_dict()
                payload["previous_hash"] = previous_hash
                payload.pop("event_hash", None)
                payload["event_hash"] = sha256_json(payload)

                line = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
                self._last_hash = str(payload["event_hash"])
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        return payload

    def last_hash(self) -> str:
        if self._last_hash is not None:
            return self._last_hash
        return self._read_last_hash_from_disk()

    def _read_last_hash_from_disk(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last_line: str | None = None
        with self.path.open("rb") as fh:
            try:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return GENESIS_HASH
                # Tail-read in chunks until we find a newline preceding
                # the final record, so we never load the full file.
                chunk = 4096
                buf = b""
                pos = size
                while pos > 0:
                    read = min(chunk, pos)
                    pos -= read
                    fh.seek(pos)
                    buf = fh.read(read) + buf
                    # Strip a single trailing newline so we look for the
                    # newline that PRECEDES the last record.
                    stripped = buf.rstrip(b"\n")
                    nl = stripped.rfind(b"\n")
                    if nl != -1:
                        last_line = stripped[nl + 1 :].decode("utf-8")
                        break
                    if pos == 0:
                        last_line = stripped.decode("utf-8")
                        break
            except OSError:
                return GENESIS_HASH
        if not last_line:
            return GENESIS_HASH
        try:
            event = json.loads(last_line)
        except json.JSONDecodeError:
            return GENESIS_HASH
        return str(event.get("event_hash", GENESIS_HASH))

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
        tenant: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for event in self.iter_events():
            if tenant is not None and event.get("tenant") != tenant:
                continue
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
                request = event.get("request")
                metadata = request.get("metadata") if isinstance(request, dict) else None
                tags = metadata.get("risk_tags", []) if isinstance(metadata, dict) else []
                if not isinstance(tags, list) or risk_tag not in tags:
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
