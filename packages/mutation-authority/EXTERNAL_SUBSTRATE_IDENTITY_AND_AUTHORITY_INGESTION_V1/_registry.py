"""Append-only authority-evidence registry (JSONL) in THIS package.

Never in the substrate. Blank lines are tolerated; a malformed non-blank line
is a fail-closed error, not a silently skipped record — a registry that cannot
be fully parsed must not be treated as if the unparseable records were absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REGISTRY_NAME = "authority_evidence_registry.jsonl"


class RegistryError(RuntimeError):
    """The registry contains a line that cannot be parsed — fail closed."""


def read_registry(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except ValueError as exc:
            raise RegistryError(f"{path}:{lineno}: malformed JSONL: {exc}") from exc
        if not isinstance(rec, dict):
            raise RegistryError(f"{path}:{lineno}: record is not an object")
        out.append(rec)
    return out


def append_record(path: Path, record: dict[str, Any]) -> None:
    line = json.dumps(record, sort_keys=True, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
