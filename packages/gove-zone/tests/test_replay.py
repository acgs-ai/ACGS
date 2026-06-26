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
from gove_zone.replay import replay_from_side_store
from gove_zone.replay_store import ReplaySideStore
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


def test_replay_event_does_not_claim_rederivation(tmp_path: Path) -> None:
    """Event-only replay must not advertise a re-derived decision or an arg-hash
    match: ``matches`` is a policy-version signal only, not proof the decision
    was reproduced.
    """
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k = Kernel(policy=policy, audit=audit)

    @k.tool("touch")
    def touch() -> None:
        return None

    _, receipt = k.dispatch("touch")
    event = find_event(audit, receipt.record.event_id)
    assert event is not None

    weak = replay_event(event, policy)
    # version matches, but the decision was NOT re-run and the arg hash was NOT
    # recomputed — both must be reported honestly.
    assert weak.matches is True  # policy-version signal only
    assert weak.re_derived is False
    assert weak.argument_hash_match is False
    assert weak.to_dict()["re_derived"] is False


def test_find_event_returns_none_for_missing(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    assert find_event(audit, "ev_does_not_exist") is None


def _seed(tmp_path: Path, policy: BoundaryPolicy, args: dict[str, object]) -> tuple[Kernel, str]:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(policy=policy, audit=audit, side_store=side_store)

    @k.tool("send")
    def send(**kwargs: object) -> None:
        return None

    try:
        _, receipt = k.dispatch("send", args)
        return k, receipt.record.event_id
    except Exception as exc:  # DeniedError carries the record
        return k, exc.record.event_id  # type: ignore[attr-defined]


def test_side_store_happy_rederivation(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "hello"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    result = replay_from_side_store(event, side, policy)
    assert result.matches is True
    assert result.replayed_decision is Decision.ALLOW
    assert result.argument_hash_match is True
    assert result.policy_version_match is True
    assert result.re_derived is True
    assert result.event_id == event_id


def test_side_store_deny_rederivation(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "this is secret"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    result = replay_from_side_store(event, side, policy)
    assert result.matches is True
    assert result.replayed_decision is Decision.DENY


def test_side_store_tamper_cross_check(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "hello"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    side["args"] = {"body": "tampered"}  # corrupt the side record only
    result = replay_from_side_store(event, side, policy)
    assert result.matches is False
    assert result.argument_hash_match is False
    assert "argument_hash" in result.reason


def test_side_store_policy_version_mismatch(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "hello"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    other = BoundaryPolicy(forbidden_keywords=["different"])
    result = replay_from_side_store(event, side, other)
    assert result.policy_version_match is False
    assert result.matches is False


def test_side_store_args_now_trip_changed_policy(tmp_path: Path) -> None:
    """A changed policy that would now DENY surfaces a non-matching re-derivation."""
    policy = BoundaryPolicy(forbidden_keywords=["never-matches"])
    k, event_id = _seed(tmp_path, policy, {"body": "danger"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    changed = BoundaryPolicy(forbidden_keywords=["danger"])
    result = replay_from_side_store(event, side, changed)
    assert result.matches is False
    assert result.replayed_decision is Decision.DENY


def test_side_store_allow_rederives_under_original_policy(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "safe text"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    result = replay_from_side_store(event, side, policy)
    assert result.matches is True
    assert result.replayed_decision is Decision.ALLOW
