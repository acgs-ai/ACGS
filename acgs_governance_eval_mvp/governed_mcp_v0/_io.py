"""IO + canonicalisation primitives used by the governed MCP runtime.

Kept as private (underscore prefix) because most helpers are internal.
The two public helpers — ``canonical_json`` and ``sha256_json`` — are also
re-exported by ``mcp_server`` for back-compat with external callers.
"""
from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Any

from .constants import GENESIS_HASH
from .models import RuntimeTargets


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(canonical_json(value))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(value))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _contains(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def _resolve_fixture_path(base: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = base / candidate
    resolved = candidate.resolve()
    if not _contains(base, resolved):
        raise ValueError("path escapes fixture directory")
    return resolved


def _load_constitution(targets: RuntimeTargets) -> tuple[dict[str, Any], str]:
    if not targets.constitution_path.exists():
        raise FileNotFoundError("constitution missing")
    constitution = _read_json(targets.constitution_path)
    policies = constitution.get("policies")
    if not isinstance(policies, list) or not policies:
        raise ValueError("constitution policies missing")
    return constitution, sha256_json(constitution)


def _last_audit_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS_HASH
    previous = GENESIS_HASH
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                event = json.loads(line)
                previous = str(event.get("event_hash", ""))
    return previous or GENESIS_HASH


def _constitution_hash_or_missing(targets: RuntimeTargets) -> str:
    try:
        _constitution, constitution_hash = _load_constitution(targets)
    except Exception:
        return "missing"
    return constitution_hash


def _next_receipt_index(audit_path: Path) -> int:
    if not audit_path.exists():
        return 1
    with audit_path.open("r", encoding="utf-8") as handle:
        return 1 + sum(1 for line in handle if line.strip())
