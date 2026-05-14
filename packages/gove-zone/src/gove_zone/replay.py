"""Replay — re-evaluate a recorded decision against a policy.

A receipt is *replayable* when running its policy against its captured
arguments produces the same decision. Replay is the integrity check between
"what we said happened" (the audit chain) and "what the policy says should
have happened given these arguments."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, sha256_json
from gove_zone.policy import Policy
from gove_zone.tool import ToolCall


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of replaying a recorded decision."""

    event_id: str
    matches: bool  # original decision == replayed decision
    original_decision: Decision
    replayed_decision: Decision
    policy_version_match: bool  # exact version string match
    argument_hash_match: bool  # original argument_hash == replayed
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "matches": self.matches,
            "original_decision": self.original_decision.value,
            "replayed_decision": self.replayed_decision.value,
            "policy_version_match": self.policy_version_match,
            "argument_hash_match": self.argument_hash_match,
            "reason": self.reason,
        }


def replay_event(event: dict[str, Any], policy: Policy) -> ReplayResult:
    """Replay a single audit event against *policy*.

    Note: the audit event records only the *argument_hash*, not the raw
    arguments. Without the raw args, replay cannot rerun the policy. Replay
    against an event-only record can therefore only confirm the policy
    version match; for full replay, callers should retain the original args
    alongside the audit event (e.g. via a side-store).
    """
    original = Decision(event["decision"])
    return ReplayResult(
        event_id=str(event.get("event_id", "")),
        matches=event.get("policy_version") == policy.version,
        original_decision=original,
        replayed_decision=original,  # cannot re-derive without raw args
        policy_version_match=event.get("policy_version") == policy.version,
        argument_hash_match=True,  # cannot recompute
        reason="policy-version-only replay; raw args not in audit event",
    )


def replay_call(
    call: ToolCall,
    expected_decision: Decision,
    policy: Policy,
    expected_policy_version: str | None = None,
) -> ReplayResult:
    """Replay by re-running *policy* against the actual *call*.

    This is the strong form: caller supplies both the raw args (which the
    kernel hashed but did not store in the audit) and the expected decision
    from the original receipt.
    """
    record = policy.evaluate(call)
    pv_match = expected_policy_version is None or record.policy_version == expected_policy_version
    arg_hash = sha256_json(dict(call.args))
    matches = record.decision is expected_decision and pv_match and record.argument_hash == arg_hash
    return ReplayResult(
        event_id=record.event_id,
        matches=matches,
        original_decision=expected_decision,
        replayed_decision=record.decision,
        policy_version_match=pv_match,
        argument_hash_match=record.argument_hash == arg_hash,
        reason=record.reason,
    )


def find_event(store: ChainHashAuditStore, event_id: str) -> dict[str, Any] | None:
    """Locate an event in the audit store by id."""
    events = store.query(where=lambda e: e.get("event_id") == event_id, limit=1)
    return events[0] if events else None
