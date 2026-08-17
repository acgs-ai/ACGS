"""Deterministic serialization + hashing.

Every digest in the pipeline flows through here so that identical inputs
always yield byte-identical output and identical hashes (risk R6). Canonical
form = UTF-8, sorted keys, no insignificant whitespace, non-ASCII preserved.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical JSON bytes (stable across runs/machines)."""
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    """Lowercase hex SHA-256 of raw bytes (or UTF-8 of a str)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(obj: Any) -> str:
    """SHA-256 of the canonical serialization of ``obj``."""
    return sha256_hex(canonical_bytes(obj))
