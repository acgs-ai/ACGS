"""
Chain-hashed evidence writer for Hermes + ACGS runtime governance.

Drop-in usage:
    writer = ChainEvidenceWriter("./evidence/session-123.jsonl")
    writer.append_event(
        hook="pre_tool",
        subject="web_search",
        input_payload={"tool": "web_search", "args": {"q": "ACGS"}},
        decision="ALLOW",
        reasons=[],
        policy_ids=["TOOL_ALLOWLIST"],
    )

The event hash identifies the event itself. Each event also carries prev_hash,
creating an append-only tamper-evident JSONL chain.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ZERO_HASH = "0" * 64


def utc_now_iso() -> str:
    """Return an RFC3339-ish UTC timestamp."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    """Stable JSON representation used for deterministic hashes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def stable_hash(value: Any) -> str:
    """SHA-256 hash of a canonical JSON value."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GovernEvent:
    id: str
    ts: str
    session_id: str
    hook: str
    subject: str
    input_hash: str
    decision: str
    reasons: list[str]
    policy_ids: list[str]
    actor_role: str = "validator"
    prev_hash: str = ZERO_HASH
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ChainEvidenceWriter:
    """Append-only JSONL writer with per-line hash chaining.

    This is intentionally small and dependency-free. For production, keep this
    writer behind a filesystem/DB append lock, periodically export Merkle roots,
    and store roots in an external timestamping system if required.
    """

    def __init__(self, path: str | Path, session_id: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or str(uuid.uuid4())
        self._lock = threading.Lock()
        self._prev_hash = self._load_previous_hash()

    @property
    def prev_hash(self) -> str:
        return self._prev_hash

    def _load_previous_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return ZERO_HASH

        last_line = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line

        if not last_line:
            return ZERO_HASH

        try:
            event = json.loads(last_line)
            event_hash = event["event_hash"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise ValueError(f"Invalid evidence log tail in {self.path}") from exc

        if not isinstance(event_hash, str) or len(event_hash) != 64:
            raise ValueError(f"Invalid event_hash in evidence log tail: {event_hash!r}")
        return event_hash

    def append_event(
        self,
        *,
        hook: str,
        subject: str,
        input_payload: Any,
        decision: str,
        reasons: Iterable[str] = (),
        policy_ids: Iterable[str] = (),
        actor_role: str = "validator",
        tags: Iterable[str] = (),
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append a governance event and return the written event dict."""
        with self._lock:
            body = GovernEvent(
                id=str(uuid.uuid4()),
                ts=utc_now_iso(),
                session_id=self.session_id,
                hook=hook,
                subject=subject,
                input_hash=stable_hash(input_payload),
                decision=decision,
                reasons=list(reasons),
                policy_ids=list(policy_ids),
                actor_role=actor_role,
                prev_hash=self._prev_hash,
                tags=list(tags),
                metadata=metadata or {},
            )
            event = asdict(body)
            event["event_hash"] = stable_hash(event)

            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(event) + "\n")
                handle.flush()
                os.fsync(handle.fileno())

            self._prev_hash = event["event_hash"]
            return event

    @staticmethod
    def read_events(path: str | Path) -> list[dict[str, Any]]:
        p = Path(path)
        if not p.exists():
            return []
        events: list[dict[str, Any]] = []
        with p.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    events.append(json.loads(line))
        return events

    @staticmethod
    def verify_chain(path: str | Path) -> tuple[bool, list[str]]:
        """Verify prev_hash links and event_hash values."""
        errors: list[str] = []
        previous = ZERO_HASH

        for index, event in enumerate(ChainEvidenceWriter.read_events(path), start=1):
            declared_hash = event.get("event_hash")
            if event.get("prev_hash") != previous:
                errors.append(
                    f"line {index}: prev_hash mismatch "
                    f"(expected {previous}, got {event.get('prev_hash')})"
                )

            body = dict(event)
            body.pop("event_hash", None)
            computed_hash = stable_hash(body)
            if declared_hash != computed_hash:
                errors.append(
                    f"line {index}: event_hash mismatch "
                    f"(expected {computed_hash}, got {declared_hash})"
                )

            previous = declared_hash or computed_hash

        return (len(errors) == 0, errors)


def merkle_root(hashes: Iterable[str]) -> str:
    """Compute a simple SHA-256 Merkle root over event hashes."""
    level = list(hashes)
    if not level:
        return ZERO_HASH

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        next_level: list[str] = []
        for left, right in zip(level[0::2], level[1::2], strict=True):
            next_level.append(hashlib.sha256((left + right).encode("utf-8")).hexdigest())
        level = next_level

    return level[0]
