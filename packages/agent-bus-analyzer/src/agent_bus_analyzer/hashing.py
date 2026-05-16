"""Canonical JSON serializer + SHA-256 chain hash primitive.

Mirrors the chain rule used by ``gove_zone.audit.ChainHashAuditStore`` so
the two chains can cross-validate. The rule is intentionally minimal:

    event_hash = sha256(canonical_json(event minus event_hash))

The predecessor's ``event_hash`` is stored on the successor as
``prev_hash`` (a field of the event), so it is naturally folded into the
input via canonical JSON — no separate concatenation.

`canonical_json` output:
    - sorted keys
    - no insignificant whitespace
    - UTF-8 (``ensure_ascii=False``)
    - compact separators (``","`` and ``":"``)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(payload: dict[str, Any]) -> str:
    """Return a deterministic JSON string for *payload*."""
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def compute_event_hash(event: dict[str, Any]) -> str:
    """SHA-256 hex digest of canonical_json(event minus event_hash).

    The caller is expected to set ``prev_hash`` on the event dict before
    invoking this function — that field is part of the hashed input. The
    function never mutates the input; it copies before stripping
    ``event_hash``.
    """
    payload = dict(event)
    payload.pop("event_hash", None)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
