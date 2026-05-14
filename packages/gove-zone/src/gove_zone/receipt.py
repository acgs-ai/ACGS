"""Receipt — the full proof-of-decision artifact for one dispatch.

A :class:`Receipt` is what the kernel returns alongside a successful tool
result. It packages the :class:`~gove_zone.decision.DecisionRecord`, the
audit chain hash, the actor identity, and a digest of the result. Receipts
are the unit of replay (see :mod:`gove_zone.replay`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from gove_zone.decision import DecisionRecord, sha256_json


def safe_result_hash(value: Any) -> str:
    """Hash *value* deterministically.

    Falls back to ``repr(value)[:512]`` for non-JSON-serializable values so
    the receipt always carries a hash even when a tool returns objects we
    cannot canonicalize.
    """
    try:
        json.dumps(value, sort_keys=True, default=str)
        return sha256_json(value)
    except (TypeError, ValueError):
        return sha256_json({"_repr": repr(value)[:512]})


@dataclass(frozen=True)
class Receipt:
    """Proof-of-decision: the decision, the audit anchor, and the outcome.

    Attributes:
        record: the policy's frozen :class:`DecisionRecord`.
        audit_hash: ``event_hash`` returned by the audit store on append.
        actor: opaque identity string ("anonymous" by default).
        result_hash: SHA-256 of the canonical-JSON of the tool result, or
            ``None`` if the dispatch did not execute (DENY/ESCALATE).
        error_class: class name of the exception raised by tool execution,
            or ``None`` if execution succeeded or never ran.
    """

    record: DecisionRecord
    audit_hash: str
    actor: str = "anonymous"
    result_hash: str | None = None
    error_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.record.to_dict(),
            "audit_hash": self.audit_hash,
            "actor": self.actor,
            "result_hash": self.result_hash,
            "error_class": self.error_class,
        }
