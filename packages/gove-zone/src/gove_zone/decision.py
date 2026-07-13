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


class ActionTier(StrEnum):
    """Explore-vs-commit action tier for a governed call.

    Tiering separates information-gathering ("explore") actions from
    goal-executing ("commit") actions so a policy bundle can gate irreversible
    side effects strictly while keeping read-only probes cheap. It is a
    *policy-routing* dimension — it changes which rules match, never whether the
    receipt gate applies. ``COMMIT`` is the strict/top tier and the fail-closed
    default: an unknown, missing, or invalid declaration is always coerced to
    ``COMMIT`` (a misdeclaration can never grant leniency).
    """

    EXPLORE = "explore"
    COMMIT = "commit"

    @classmethod
    def coerce(cls, value: Any) -> ActionTier:
        """Map an untrusted declaration to a tier, defaulting to ``COMMIT``.

        The declared tier is proposed by the agent and is therefore untrusted:
        only the exact string ``"explore"`` (or an :class:`ActionTier` instance)
        yields ``EXPLORE``. Everything else — ``None``, empty string, wrong case,
        unknown names, non-strings — is ``COMMIT``. Never raises.
        """
        if isinstance(value, cls):
            return value
        if value == cls.EXPLORE.value:
            return cls.EXPLORE
        return cls.COMMIT


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
    ``actor``, ``path``, ``state_hash``, and ``decision_request_hash`` bind the
    decision to the policies-on-paths context without storing raw state.
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
    actor: str = ""
    path: tuple[str, ...] = ()
    state_hash: str | None = None
    decision_request_hash: str = ""
    action_tier: str | None = None
    declared_action_tier: str | None = None

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
            "actor": self.actor,
            "path": list(self.path),
            "state_hash": self.state_hash,
            "decision_request_hash": self.decision_request_hash,
            "action_tier": self.action_tier,
            "declared_action_tier": self.declared_action_tier,
        }
