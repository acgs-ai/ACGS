"""Decision types and canonical-JSON / hash helpers.

A ``DecisionRecord`` is the unit of audit. Every governed action emits exactly
one record before the action runs; the audit layer attaches ``previous_hash``
and ``event_hash`` at append time.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """The four governance verdicts the kernel can emit."""

    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"
    ESCALATE = "escalate"


def canonical_json(payload: Any) -> str:
    """Canonical JSON: sorted keys, no whitespace, ensure_ascii=False.

    Stable across Python versions and machines so identical payloads hash to
    identical digests.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_json(payload: Any) -> str:
    """SHA-256 of canonical_json(payload), hex-encoded."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class DecisionRecord:
    """A single governance decision, ready to be appended to the audit chain.

    The audit layer attaches ``event_hash`` and ``previous_hash`` on append.
    ``transformed_args`` is only set when ``decision is Decision.TRANSFORM``.
    ``goal`` is the high-level intent the caller passed to ``Kernel.dispatch``
    — opaque to the kernel, but persisted alongside the decision for replay.
    """

    decision: Decision
    tool: str
    argument_hash: str
    policy_version: str
    event_id: str
    matched_rules: tuple[str, ...] = ()
    reason: str = ""
    timestamp_iso: str = field(default_factory=_now_iso)
    transformed_args: dict[str, Any] | None = None
    goal: str = ""
    request_id: str | None = None
    tenant_id: str | None = None
    actor: dict[str, Any] | str | None = None
    subject: dict[str, Any] | str | None = None
    proposed_action: dict[str, Any] | None = None
    execution_boundary: dict[str, Any] | None = None
    policy_bundle_id: str | None = None
    constitutional_hash: str | None = None
    receipt_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "tool": self.tool,
            "argument_hash": self.argument_hash,
            "policy_version": self.policy_version,
            "event_id": self.event_id,
            "matched_rules": list(self.matched_rules),
            "reason": self.reason,
            "timestamp_iso": self.timestamp_iso,
            "transformed_args": self.transformed_args,
            "goal": self.goal,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "subject": self.subject,
            "proposed_action": self.proposed_action,
            "execution_boundary": self.execution_boundary,
            "policy_bundle_id": self.policy_bundle_id,
            "constitutional_hash": self.constitutional_hash,
            "receipt_hash": self.receipt_hash,
        }
