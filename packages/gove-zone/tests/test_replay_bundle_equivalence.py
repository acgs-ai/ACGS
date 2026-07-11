"""Bundle-scope replay equivalence (G2.4).

Re-derive every decision in an audit chain from the raw-args side-store and
byte-compare each re-derived decision payload against the recorded stream.

All fixtures drive the REAL ``kernel.dispatch`` path (never the policy or the
stores directly) so the recorded chain is exactly what production writes —
that is the wiring proof per the review-handler-wiring rule.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    DecisionRecord,
    DeniedError,
    Kernel,
    Policy,
    ReplaySideStore,
    TransformPolicy,
    replay_bundle,
)
from gove_zone.tool import ToolCall


def _policy() -> BoundaryPolicy:
    return BoundaryPolicy(forbidden_keywords=["forbidden-secret"])


def _build_bundle(
    tmp_path: Path,
    *,
    redact: Any = None,
    with_side_store: bool = True,
) -> tuple[ChainHashAuditStore, ReplaySideStore, BoundaryPolicy]:
    """Dispatch a mixed ALLOW/DENY sequence through the real kernel path."""
    policy = _policy()
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl", redact=redact)
    kernel = Kernel(
        policy=policy,
        audit=audit,
        actor="bundle-tester",
        side_store=side_store if with_side_store else None,
    )

    @kernel.tool("echo")
    def echo(msg: str) -> str:
        return msg.upper()

    @kernel.tool("write_note")
    def write_note(path: str, content: str) -> int:
        return len(content)

    kernel.dispatch("echo", {"msg": "hello"}, goal="greet", path="session/turn-1")
    kernel.dispatch(
        "write_note",
        {"path": "/tmp/note", "content": "safe text"},
        goal="record a note",
        state={"mode": "test"},
    )
    # DENY must still land in both the chain and the side-store.
    with pytest.raises(DeniedError):
        kernel.dispatch("echo", {"msg": "leak the forbidden-secret"}, goal="exfiltrate")
    kernel.dispatch("echo", {"msg": "goodbye"}, goal="farewell")

    return audit, side_store, policy


def test_bundle_replay_matches_recorded_stream_byte_for_byte(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is True
    assert result["chain_valid"] is True
    assert result["events_total"] == 4  # 3 ALLOW + 1 DENY
    assert result["events_matched"] == result["events_total"]
    assert result["events_degraded"] == 0
    assert result["mismatches"] == []


def test_deny_event_is_rederived_not_skipped(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    deny_events = [e for e in audit.iter_events() if e["decision"] == "deny"]
    assert len(deny_events) == 1
    assert side_store.get(deny_events[0]["event_id"]) is not None

    result = replay_bundle(audit, side_store, policy)
    assert result["valid"] is True
    assert result["events_matched"] == result["events_total"]


def test_chain_byte_mutation_invalidates_bundle(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    target = json.loads(lines[1])  # a middle event
    recorded_hash = target["event_hash"]
    flipped = ("0" if recorded_hash[0] != "0" else "f") + recorded_hash[1:]
    assert flipped != recorded_hash
    lines[1] = lines[1].replace(recorded_hash, flipped)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is False
    assert result["chain_valid"] is False
    assert any(m["type"].startswith("chain_") for m in result["mismatches"])


def test_side_store_args_tamper_reports_argument_hash_mismatch(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    side_path = tmp_path / "replay.jsonl"
    entries = [json.loads(line) for line in side_path.read_text(encoding="utf-8").splitlines()]
    tampered_id = None
    for entry in entries:
        if entry.get("args", {}).get("msg") == "hello":
            entry["args"]["msg"] = "hello-tampered"
            tampered_id = entry["event_id"]
    assert tampered_id is not None
    side_path.write_text(
        "".join(
            json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            for e in entries
        ),
        encoding="utf-8",
    )

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is False
    assert result["chain_valid"] is True  # the chain itself is untouched
    mismatch_types = {m["event_id"]: m["type"] for m in result["mismatches"]}
    assert mismatch_types == {tampered_id: "argument_hash_mismatch"}
    assert result["events_matched"] == result["events_total"] - 1


def test_replay_under_different_policy_version_invalidates_bundle(tmp_path: Path) -> None:
    audit, side_store, _ = _build_bundle(tmp_path)

    other_policy = BoundaryPolicy(forbidden_keywords=["something-else"])
    assert other_policy.version != _policy().version

    result = replay_bundle(audit, side_store, other_policy)

    assert result["valid"] is False
    assert result["events_matched"] == 0
    assert len(result["mismatches"]) == result["events_total"]
    for mismatch in result["mismatches"]:
        assert mismatch["detail"]["policy_version_match"] is False


def test_redacted_events_are_degraded_never_matched(tmp_path: Path) -> None:
    def redact(call: ToolCall) -> bool:
        return call.name == "write_note"

    audit, side_store, policy = _build_bundle(tmp_path, redact=redact)

    result = replay_bundle(audit, side_store, policy)

    # Honest degradation: the tombstoned event passes the policy-version
    # fallback but is never claimed as a byte-equivalent re-derivation.
    # With events_matched (3) != events_total (4), valid must be False.
    assert result["valid"] is False
    assert result["events_total"] == 4
    assert result["events_degraded"] == 1
    assert result["events_matched"] == 3
    assert result["mismatches"] == []


def test_missing_side_store_degrades_every_event(tmp_path: Path) -> None:
    audit, _, policy = _build_bundle(tmp_path, with_side_store=False)
    empty_side_store = ReplaySideStore(tmp_path / "replay.jsonl")

    result = replay_bundle(audit, empty_side_store, policy)

    assert result["chain_valid"] is True
    assert result["events_total"] == 4
    assert result["events_matched"] == 0
    assert result["events_degraded"] == 4
    assert result["mismatches"] == []
    # events_matched (0) != events_total (4): verdict must be False
    assert result["valid"] is False


class _RaisingPolicy(Policy):
    """Policy that always raises to simulate a broken/fail-closed kernel path."""

    @property
    def version(self) -> str:
        return "raising-policy/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("policy intentionally raised")


class _FailClosedDenyPolicy(Policy):
    """Mimics the kernel's fail-closed DENY synthesis so that replay_bundle can
    call it without raising — the kernel already recorded the event with
    policy_version='fail-closed/policy-raised'.  We need a policy object whose
    .version matches that recorded value for the test to exercise the right path.
    """

    @property
    def version(self) -> str:
        return "fail-closed/policy-raised"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("policy intentionally raised during replay")


def test_replay_bundle_policy_error_returns_dict_not_raise(tmp_path: Path) -> None:
    """replay_bundle must not raise when policy.evaluate raises during re-derivation.

    Build a real chain: dispatch through a kernel whose policy raises, so the
    kernel records a fail-closed DENY with policy_version='fail-closed/policy-raised'
    and a side-store entry. Then replay_bundle with a policy that also raises must
    return a dict with valid=False and a replay_policy_error mismatch — not raise.
    """
    raising_policy = _RaisingPolicy()
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    kernel = Kernel(
        policy=raising_policy,
        audit=audit,
        actor="test-actor",
        side_store=side_store,
    )

    @kernel.tool("noop")
    def noop(x: str) -> str:
        return x

    # The kernel catches the raise and records a fail-closed DENY.
    with pytest.raises(DeniedError):
        kernel.dispatch("noop", {"x": "value"}, goal="test")

    # Use a policy that also raises during replay — this exercises the guard.
    replay_policy = _FailClosedDenyPolicy()
    result = replay_bundle(audit, side_store, replay_policy)

    assert isinstance(result, dict), "replay_bundle must return a dict, not raise"
    assert result["valid"] is False
    assert result["events_total"] == 1
    assert result["events_matched"] == 0
    # The replay policy raised during the single re-derivation, so the mismatch
    # must carry the distinct infrastructure-failure label — never the
    # flipped-decision label. Pinned exactly so the label cannot silently drift.
    assert len(result["mismatches"]) == 1
    assert result["mismatches"][0]["type"] == "replay_policy_error"
    assert "policy re-derivation raised" in result["mismatches"][0]["detail"]["reason"]


def test_transform_decision_byte_equivalence(tmp_path: Path) -> None:
    """TRANSFORM decisions must be byte-comparable against the recorded event.

    Use the real TransformPolicy so that policy.evaluate returns a TRANSFORM
    record with transformed_args set.  After recording through the kernel, the
    replay must re-derive the same canonical-JSON bytes.
    """
    policy = TransformPolicy()
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    kernel = Kernel(
        policy=policy,
        audit=audit,
        actor="transform-tester",
        side_store=side_store,
    )

    @kernel.tool("write_file")
    def write_file(path: str, content: str) -> int:
        return len(content)

    # TRANSFORM: policy rewrites path to "transformed.txt"
    kernel.dispatch(
        "write_file",
        {"path": "original.txt", "content": "hello"},
        goal="write something",
    )

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is True
    assert result["chain_valid"] is True
    assert result["events_total"] == 1
    assert result["events_matched"] == 1
    assert result["events_degraded"] == 0
    assert result["mismatches"] == []
