"""Canonical JSON serialization, pinned for the frozen protocol.

The byte encoding here participates in every hash and signature in this
package, so it is pinned locally rather than imported from a sibling
package whose conventions may evolve: a formatting change elsewhere must
never silently change this protocol's hashes.

Convention (part of the frozen protocol identity):
- JSON object with keys sorted lexicographically (codepoint order);
- separators ("," and ":") with no whitespace;
- ensure_ascii=True (output is pure ASCII bytes);
- no NaN/Infinity;
- only null, bool, int, str, list, dict are admitted — floats are
  rejected because their formatting is platform- and version-sensitive;
- encoded as UTF-8 (ASCII subset).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .errors import ProtocolError


def _reject_unrepresentable(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise ProtocolError(f"float at {path} is not canonically representable")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _reject_unrepresentable(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ProtocolError(f"non-string key at {path}: {k!r}")
            _reject_unrepresentable(v, f"{path}.{k}")
        return
    raise ProtocolError(f"unrepresentable type at {path}: {type(value).__name__}")


def canonical_bytes(payload: Any) -> bytes:
    """Serialize payload to the pinned canonical byte form."""
    _reject_unrepresentable(payload)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256_hex(payload: Any) -> str:
    """SHA-256 hex digest of the canonical byte form."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def length_prefixed(*parts: bytes) -> bytes:
    """Unambiguous concatenation: 8-byte big-endian length before each part.

    Used for every signed payload so no two distinct field sequences can
    serialize to the same signing input (no delimiter-injection ambiguity).
    """
    out = bytearray()
    for part in parts:
        if not isinstance(part, bytes):
            raise ProtocolError("length_prefixed accepts bytes only")
        out += len(part).to_bytes(8, "big")
        out += part
    return bytes(out)
