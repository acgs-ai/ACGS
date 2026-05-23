from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from governance.models import AuthorizationTrace, AuthorizationTraceIntegrityError, DecisionRecord, sha256_json

GENESIS_HASH = "0" * 64


def extract_trace(event_dict: dict[str, Any]) -> AuthorizationTrace | None:
    """Extract and validate an authorization trace from an audit event.

    Returns ``None`` only when the event has no authorization_trace field.
    Malformed or tampered trace payloads always raise
    ``AuthorizationTraceIntegrityError``; callers that want fallback behavior
    must catch that exception at the call site.
    """
    trace_payload = event_dict.get("authorization_trace")
    if trace_payload is None:
        return None
    if not isinstance(trace_payload, dict):
        raise AuthorizationTraceIntegrityError("authorization_trace must be an object")

    try:
        trace = AuthorizationTrace.from_dict(trace_payload)
    except Exception as exc:
        raise AuthorizationTraceIntegrityError("authorization_trace is invalid") from exc

    receipt = trace_payload.get("receipt")
    if isinstance(receipt, dict) and receipt.get("trace_hash") != trace.trace_hash():
        raise AuthorizationTraceIntegrityError("authorization_trace trace_hash does not match trace payload")

    actor = event_dict.get("request", {}).get("actor") if isinstance(event_dict.get("request"), dict) else None
    actor_id = actor.get("id") if isinstance(actor, dict) else None
    if actor_id and actor_id not in {entry["principal_id"] for entry in trace.principal_chain}:
        raise AuthorizationTraceIntegrityError("authorization_trace principal_chain does not reference request actor")

    return trace


class ChainHashAuditStore:
    """Append-only JSONL audit store with hash chaining.

    Each event hash covers the canonical event payload excluding event_hash.
    previous_hash links to the prior event_hash.

    ``verify_chain()`` returns structured hash-chain failures for ordinary
    event hash mismatches. Trace-bearing events are stricter: malformed or
    tampered authorization traces raise ``AuthorizationTraceIntegrityError``.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        decision: DecisionRecord,
        authorization_trace: AuthorizationTrace | None = None,
    ) -> dict[str, Any]:
        trace_payload = authorization_trace.to_dict() if authorization_trace is not None else None
        # Serialize read-then-write under an exclusive lock so concurrent
        # callers do not produce sibling events pointing at the same
        # previous_hash. Without this, verify_chain() reports the chain
        # broken under any thread- or process-level concurrency.
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                previous_hash = self._read_last_hash_from_disk()
                payload = decision.to_dict()
                payload["previous_hash"] = previous_hash
                if trace_payload is not None:
                    payload["authorization_trace"] = trace_payload
                    extract_trace(payload)
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
        # Acquire a shared lock for the duration of the scan so concurrent
        # appenders (which hold LOCK_EX) cannot interleave a partial line
        # underneath the reader and trigger JSONDecodeError.
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_SH)
            try:
                return self._verify_chain_locked()
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def _verify_chain_locked(self) -> dict[str, Any]:
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

            if event.get("authorization_trace") is not None:
                if claimed_hash != recomputed:
                    raise AuthorizationTraceIntegrityError(
                        f"trace-bearing event hash mismatch for {event.get('event_id')}"
                    )
                extract_trace(event)

            previous = str(claimed_hash)

        return {
            "valid": len(failures) == 0,
            "checked": checked,
            "failures": failures,
            "last_hash": previous,
        }
