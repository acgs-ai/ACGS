"""Receipt + replay tests.

Proves the third MVP acceptance criterion: *every decision records goal,
action, tool, argument hash, policy version, matched rules, decision,
reason, timestamp, and audit hash. Receipts are replayable.*
"""

from __future__ import annotations

from pathlib import Path

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    Kernel,
    find_event,
    replay_call,
    replay_event,
)
from gove_zone.tool import ToolCall


def _kernel(tmp_path: Path) -> Kernel:
    return Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["~/.ssh"]),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )


def test_receipt_records_every_required_field(tmp_path: Path) -> None:
    k = _kernel(tmp_path)

    @k.tool("write_file")
    def write_file(path: str, content: str) -> int:
        return len(content)

    _, receipt = k.dispatch("write_file", {"path": "/tmp/x", "content": "abc"})
    d = receipt.to_dict()

    # Required-by-MVP fields:
    for field in (
        "decision",
        "tool",
        "argument_hash",
        "policy_version",
        "matched_rules",
        "reason",
        "timestamp_iso",
        "audit_hash",
        "event_id",
        "goal",
    ):
        assert field in d, f"receipt missing required field: {field}"


def test_dispatch_preserves_goal_in_receipt_and_audit(tmp_path: Path) -> None:
    """The goal passed to dispatch round-trips through receipt and audit."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["~/.ssh"]),
        audit=audit,
    )

    @k.tool("ping")
    def ping() -> str:
        return "pong"

    _, receipt = k.dispatch("ping", goal="seed demo")
    assert receipt.record.goal == "seed demo"

    events = list(audit.iter_events())
    assert events[0]["goal"] == "seed demo"


def test_replay_call_matches_when_policy_unchanged(tmp_path: Path) -> None:
    """Re-evaluating the same call with the same policy reproduces the decision."""
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )

    @k.tool("send")
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})

    replayed = replay_call(
        ToolCall(name="send", args={"body": "hello"}),
        expected_decision=Decision.ALLOW,
        policy=policy,
        expected_policy_version=receipt.record.policy_version,
    )
    assert replayed.matches is True
    assert replayed.replayed_decision is Decision.ALLOW
    assert replayed.policy_version_match is True
    assert replayed.argument_hash_match is True


def test_replay_call_diverges_when_args_change(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    # Replay against args that NOW trip the policy — receipt was ALLOW
    replayed = replay_call(
        ToolCall(name="send", args={"body": "now this is secret"}),
        expected_decision=Decision.ALLOW,
        policy=policy,
    )
    assert replayed.matches is False
    assert replayed.replayed_decision is Decision.DENY


def test_replay_event_uses_audit_only(tmp_path: Path) -> None:
    """When raw args are not available, replay can only confirm policy version."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k = Kernel(policy=policy, audit=audit)

    @k.tool("touch")
    def touch() -> None:
        return None

    _, receipt = k.dispatch("touch")
    event = find_event(audit, receipt.record.event_id)
    assert event is not None
    result = replay_event(event, policy)
    assert result.policy_version_match is True

    # Different policy → version mismatch
    other = BoundaryPolicy(forbidden_keywords=["different"])
    assert replay_event(event, other).policy_version_match is False


def test_find_event_returns_none_for_missing(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    assert find_event(audit, "ev_does_not_exist") is None
