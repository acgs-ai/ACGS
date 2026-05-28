"""Strict canonical-bytes serialization for the Phase 2 signature ABI.

Phase 1's `sha256_json` uses `json.dumps(..., default=str)` which can
silently coerce ambiguous types into strings. For long-lived
signatures we reject ambiguity instead.

See `docs/design/phase2-trace-crypto.md` (canonical serialization)
and ADR-0007.

Rules
-----
- Accept: ``None``, ``bool``, ``int``, ``str`` (NFC-normalized,
  no embedded NUL), ``list``/``tuple`` of acceptable values, ``dict``
  with ``str`` keys (sorted in code-point order, no duplicates).
- Reject (``CanonicalizationError``):

  * floats (require explicit string for fractional values)
  * NaN / Infinity / -Infinity
  * non-``str`` dict keys
  * ``bytes`` / ``bytearray`` / ``Decimal`` / ``datetime`` / ``date``
    (ambiguous serialization — caller must pre-format)
  * unnormalized Unicode (NFC normalization required)
  * embedded NUL bytes in strings
"""

from __future__ import annotations

import json
import math
import unicodedata
from typing import Any


class CanonicalizationError(ValueError):
    """Raised on any payload that would produce ambiguous canonical bytes."""


def _validate(value: Any, *, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        # bool is also int; handled above
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(f"non-finite float at {path}: {value!r}")
        raise CanonicalizationError(f"floats are not canonicalizable at {path}: use a string")
    if isinstance(value, str):
        if "\x00" in value:
            raise CanonicalizationError(f"embedded NUL byte in string at {path}")
        if unicodedata.normalize("NFC", value) != value:
            raise CanonicalizationError(f"string at {path} is not NFC-normalized")
        return
    if isinstance(value, (bytes, bytearray)):
        raise CanonicalizationError(f"bytes are not canonicalizable at {path}: encode upstream")
    if isinstance(value, dict):
        seen: set[str] = set()
        for key in value.keys():
            if not isinstance(key, str):
                raise CanonicalizationError(f"dict key at {path} is not a string: {key!r}")
            if key in seen:
                # plain dicts can't carry duplicates, but defend
                # against custom mappings that might.
                raise CanonicalizationError(f"duplicate dict key at {path}: {key!r}")
            seen.add(key)
            _validate(value[key], path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _validate(item, path=f"{path}[{i}]")
        return
    # Decimal, datetime, date, sets, custom objects all land here.
    raise CanonicalizationError(f"value of type {type(value).__name__} at {path} is not canonicalizable")


def canonical_bytes(value: Any) -> bytes:
    """Serialize ``value`` to canonical UTF-8 bytes suitable for signing.

    See module docstring for the accepted/rejected type contract.

    Raises:
        CanonicalizationError: on any ambiguous or unsupported input.
    """
    _validate(value)
    # sort_keys produces code-point order for str keys (validated above);
    # tight separators eliminate whitespace ambiguity; ensure_ascii=False
    # so NFC-normalized non-ASCII passes through unescaped.
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


__all__ = ["CanonicalizationError", "canonical_bytes"]
