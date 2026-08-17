"""Deterministic JSON normalization shared by the process-mining layer."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


def utc_datetime(value: datetime) -> datetime:
    """Return an aware UTC datetime, rejecting ambiguous naive timestamps."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def json_compatible(value: object) -> Any:
    """Return a deterministic, JSON-compatible copy without mutating *value*.

    Unsupported objects and non-finite floats are rejected instead of being
    stringified because their representation is not a stable integrity input.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats are not canonical JSON")
        return value
    if isinstance(value, datetime):
        return utc_datetime(value).isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return json_compatible(value.value)
    if isinstance(value, BaseModel):
        return json_compatible(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            normalized[key] = json_compatible(item)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [json_compatible(item) for item in value]
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: object) -> str:
    """Serialize *value* using the ACGS sorted, compact JSON convention."""
    return json.dumps(
        json_compatible(value),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_canonical(value: object) -> str:
    """Return the SHA-256 digest of :func:`canonical_json`."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
