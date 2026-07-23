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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gove_zone.signing import LifecycleAttestation, ReceiptSigner


class Decision(StrEnum):
    """The four governance verdicts the kernel can emit."""

    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"
    ESCALATE = "escalate"


class RecordKind(StrEnum):
    """Authenticated classification of one audit-chain record.

    ``EXECUTION_REFUSAL`` is a first-class third kind: it records that a final
    execution gate refused an attempt *before* any adapter ran. It is neither a
    policy decision (no policy was re-evaluated) nor an execution lifecycle
    phase (no attempt was reserved-and-run), so it never reuses either schema.
    """

    POLICY_DECISION = "policy_decision"
    EXECUTION_LIFECYCLE = "execution_lifecycle"
    EXECUTION_REFUSAL = "execution_refusal"


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
    record_kind: RecordKind = RecordKind.POLICY_DECISION
    execution_evidence: dict[str, str] | None = None
    lifecycle_attestation: LifecycleAttestation | None = None

    def __post_init__(self) -> None:
        from gove_zone.signing import LifecycleAttestation

        if type(self.record_kind) is not RecordKind:
            raise TypeError("record_kind must be a RecordKind")
        if self.record_kind is RecordKind.POLICY_DECISION:
            if self.execution_evidence is not None or self.lifecycle_attestation is not None:
                raise ValueError("policy decision cannot contain lifecycle material")
        elif self.record_kind is RecordKind.EXECUTION_REFUSAL:
            # A refusal is proved by its own evidence object (independent signer
            # and/or committed checkpoint), never by a lifecycle attestation:
            # no execution attempt was ever attested.
            if type(self.execution_evidence) is not dict:
                raise ValueError("execution refusal requires evidence")
            if self.lifecycle_attestation is not None:
                raise ValueError("execution refusal cannot carry a lifecycle attestation")
            if self.decision is not Decision.DENY:
                raise ValueError("execution refusal must be non-executable")
        elif (
            type(self.execution_evidence) is not dict
            or type(self.lifecycle_attestation) is not LifecycleAttestation
        ):
            raise ValueError("execution lifecycle requires evidence and attestation")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
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
            "record_kind": self.record_kind.value,
        }
        if self.execution_evidence is not None:
            payload["execution_evidence"] = dict(self.execution_evidence)
        if self.lifecycle_attestation is not None:
            payload["lifecycle_attestation"] = self.lifecycle_attestation.to_dict()
        return payload

    def lifecycle_signing_payload(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("lifecycle_attestation", None)
        return payload

    @classmethod
    def lifecycle(
        cls,
        *,
        decision: Decision,
        tool: str,
        argument_hash: str,
        policy_version: str,
        event_id: str,
        execution_evidence: dict[str, str],
        signer: ReceiptSigner,
        authority_id: str,
        matched_rules: tuple[str, ...] = (),
        reason: str = "",
        timestamp_iso: str | None = None,
        transformed_args: dict[str, Any] | None = None,
        goal: str = "",
        actor: str = "",
        path: tuple[str, ...] = (),
        state_hash: str | None = None,
        decision_request_hash: str = "",
        action_tier: str | None = None,
        declared_action_tier: str | None = None,
    ) -> DecisionRecord:
        from gove_zone.signing import LifecycleAttestation

        timestamp = timestamp_iso if timestamp_iso is not None else _now_iso()
        unsigned_payload: dict[str, Any] = {
            "decision": decision.value,
            "tool": tool,
            "argument_hash": argument_hash,
            "policy_version": policy_version,
            "event_id": event_id,
            "matched_rules": list(matched_rules),
            "reason": reason,
            "timestamp_iso": timestamp,
            "transformed_args": transformed_args,
            "goal": goal,
            "actor": actor,
            "path": list(path),
            "state_hash": state_hash,
            "decision_request_hash": decision_request_hash,
            "action_tier": action_tier,
            "declared_action_tier": declared_action_tier,
            "record_kind": RecordKind.EXECUTION_LIFECYCLE.value,
            "execution_evidence": dict(execution_evidence),
        }
        attestation = LifecycleAttestation.issue(
            unsigned_payload,
            signer=signer,
            authority_id=authority_id,
        )
        return cls(
            decision=decision,
            tool=tool,
            argument_hash=argument_hash,
            policy_version=policy_version,
            event_id=event_id,
            matched_rules=matched_rules,
            reason=reason,
            timestamp_iso=timestamp,
            transformed_args=transformed_args,
            goal=goal,
            actor=actor,
            path=path,
            state_hash=state_hash,
            decision_request_hash=decision_request_hash,
            action_tier=action_tier,
            declared_action_tier=declared_action_tier,
            record_kind=RecordKind.EXECUTION_LIFECYCLE,
            execution_evidence=dict(execution_evidence),
            lifecycle_attestation=attestation,
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> DecisionRecord:
        """Deserialize an audit payload without inferring kind from evidence.

        Historical records that predate ``record_kind`` are policy decisions.
        Explicit lifecycle classification requires evidence, while policy
        records may never acquire lifecycle evidence through deserialization.
        """

        from gove_zone.signing import LifecycleAttestation

        raw_kind = payload.get("record_kind", RecordKind.POLICY_DECISION.value)
        kind = RecordKind(raw_kind)
        has_evidence = "execution_evidence" in payload
        evidence = payload.get("execution_evidence")
        has_attestation = "lifecycle_attestation" in payload
        raw_attestation = payload.get("lifecycle_attestation")
        if kind is RecordKind.POLICY_DECISION and (has_evidence or has_attestation):
            raise ValueError("policy decision cannot contain lifecycle material")
        if kind is RecordKind.EXECUTION_REFUSAL:
            if not has_evidence or type(evidence) is not dict:
                raise ValueError("execution refusal requires evidence")
            if has_attestation:
                raise ValueError("execution refusal cannot carry a lifecycle attestation")
        if kind is RecordKind.EXECUTION_LIFECYCLE and (
            type(evidence) is not dict or type(raw_attestation) is not dict
        ):
            raise ValueError("execution lifecycle requires evidence and attestation")
        attestation = (
            LifecycleAttestation.from_dict(raw_attestation)
            if type(raw_attestation) is dict
            else None
        )
        return cls(
            decision=Decision(payload["decision"]),
            tool=payload["tool"],
            argument_hash=payload["argument_hash"],
            policy_version=payload["policy_version"],
            event_id=payload["event_id"],
            matched_rules=tuple(payload.get("matched_rules", ())),
            reason=payload.get("reason", ""),
            timestamp_iso=payload.get("timestamp_iso", _now_iso()),
            transformed_args=payload.get("transformed_args"),
            goal=payload.get("goal", ""),
            actor=payload.get("actor", ""),
            path=tuple(payload.get("path", ())),
            state_hash=payload.get("state_hash"),
            decision_request_hash=payload.get("decision_request_hash", ""),
            action_tier=payload.get("action_tier"),
            declared_action_tier=payload.get("declared_action_tier"),
            record_kind=kind,
            execution_evidence=dict(evidence) if type(evidence) is dict else None,
            lifecycle_attestation=attestation,
        )
