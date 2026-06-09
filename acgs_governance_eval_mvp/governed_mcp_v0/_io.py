"""IO + canonicalisation primitives used by the governed MCP runtime.

Kept as private (underscore prefix) because most helpers are internal.
The two public helpers — ``canonical_json`` and ``sha256_json`` — are also
re-exported by ``mcp_server`` for back-compat with external callers.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from hashlib import sha256
from pathlib import Path
from typing import IO, Any

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


def _write_json(path: Path, value: dict[str, Any], *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "x" if exclusive else "w"
    with path.open(mode, encoding="utf-8") as handle:
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


@contextmanager
def _evidence_lock(audit_path: Path) -> IO[str]:
    """Serialize evidence writers with a sidecar POSIX lock file.

    TODO: ``fcntl`` is POSIX-only; Windows fallback is out of scope because
    the package CI runs on Linux.
    """
    lock_path = audit_path.with_suffix(audit_path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield handle
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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


def write_constitution_registry(targets: RuntimeTargets) -> Path:
    """Generate the pinned constitution-hash registry from the live constitution.

    Writes a canonical JSON list containing the sha256_json hash of the
    current constitution to ``targets.constitution_registry_path`` and
    returns that path. Regenerable at any time — analogous to
    ``docs/constitutional-hashes.lock`` at the monorepo root. Raises if the
    constitution itself is unreadable (never pins a registry blindly).
    """
    _constitution, constitution_hash = _load_constitution(targets)
    registry_path = targets.constitution_registry_path
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    with registry_path.open("w", encoding="utf-8") as handle:
        handle.write(canonical_json([constitution_hash]))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return registry_path


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
    """Best-effort constitution hash for fail-closed receipt enrichment.

    Returns the literal string ``"missing"`` when the constitution cannot be
    read or parsed. Catches only file/format failures — never
    programming errors, so a real bug surfaces instead of being silently
    re-encoded into the receipt as ``constitution_hash="missing"``.
    """
    try:
        _constitution, constitution_hash = _load_constitution(targets)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return "missing"
    return constitution_hash


def _next_receipt_index(receipts_dir: Path, audit_path: Path) -> int:
    """Return the next 1-based receipt index.

    Prefer max(existing receipt filenames) + 1 — this is collision-proof
    against orphan audit lines (audit row written but receipt later unlinked
    by an external cleanup, or vice-versa). Falls back to audit-line count
    + 1 when no receipts exist yet so the very first admission still gets
    index 1.
    """
    indices: list[int] = []
    if receipts_dir.exists():
        for entry in receipts_dir.iterdir():
            name = entry.name
            if len(name) >= 5 and name[:4].isdigit() and name.endswith(".json"):
                indices.append(int(name[:4]))
    if indices:
        return max(indices) + 1
    if not audit_path.exists():
        return 1
    with audit_path.open("r", encoding="utf-8") as handle:
        return 1 + sum(1 for line in handle if line.strip())
