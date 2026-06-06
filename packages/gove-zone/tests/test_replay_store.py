"""ReplaySideStore tests.

Proves the opt-in raw-args side-store: round-trip fidelity (a reconstructed
ToolCall reproduces the recorded ``argument_hash``), redaction tombstones, and
lookup semantics. The store is a plain JSONL lookup table; its tamper guarantee
comes from cross-checking against the audit chain at replay time, exercised in
``test_replay.py``.
"""

from __future__ import annotations

from pathlib import Path

from gove_zone.decision import Decision, DecisionRecord, canonical_json
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall


def _record(call: ToolCall, event_id: str) -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool=call.name,
        argument_hash=call.argument_hash(),
        policy_version="test/v1",
        event_id=event_id,
    )


def test_append_then_get_returns_raw_call(tmp_path: Path) -> None:
    store = ReplaySideStore(tmp_path / "replay.jsonl")
    call = ToolCall(
        name="write_file",
        args={"path": "/tmp/x", "content": "hi"},
        goal="demo",
        actor="agent",
        path=("tenant", "matter"),
        state={"trust_tier": "analyst"},
    )
    record = _record(call, "ev_1")

    store.append(call, record)
    got = store.get("ev_1")

    assert got is not None
    assert got["args"] == {"path": "/tmp/x", "content": "hi"}
    assert got["state"] == {"trust_tier": "analyst"}
    assert got["path"] == ["tenant", "matter"]
    assert got["actor"] == "agent"
    assert got["goal"] == "demo"
    assert got["tool"] == "write_file"
    assert got["argument_hash"] == call.argument_hash()
    assert got["policy_version"] == "test/v1"
    assert got["decision"] == "allow"
    assert "redacted" not in got


def test_round_trip_reconstruction_preserves_argument_hash(tmp_path: Path) -> None:
    store = ReplaySideStore(tmp_path / "replay.jsonl")
    call = ToolCall(name="send", args={"body": "hello", "n": 3, "ok": True})
    record = _record(call, "ev_rt")
    store.append(call, record)

    got = store.get("ev_rt")
    assert got is not None
    reconstructed = ToolCall(
        name=got["tool"],
        args=dict(got["args"]),
        goal=got["goal"],
        actor=got["actor"],
        path=tuple(got["path"]),
        state=dict(got["state"]),
    )
    assert reconstructed.argument_hash() == call.argument_hash()


def test_redaction_writes_tombstone_without_raw_args(tmp_path: Path) -> None:
    store = ReplaySideStore(
        tmp_path / "replay.jsonl",
        redact=lambda c: "id_rsa" in canonical_json(dict(c.args)),
    )
    call = ToolCall(name="write_file", args={"path": "id_rsa", "content": "secret"})
    record = _record(call, "ev_secret")

    entry = store.append(call, record)
    assert entry == {"event_id": "ev_secret", "redacted": True}

    got = store.get("ev_secret")
    assert got == {"event_id": "ev_secret", "redacted": True}
    assert "args" not in got


def test_redaction_predicate_persists_non_matching_calls(tmp_path: Path) -> None:
    store = ReplaySideStore(
        tmp_path / "replay.jsonl",
        redact=lambda c: "id_rsa" in canonical_json(dict(c.args)),
    )
    call = ToolCall(name="write_file", args={"path": "public.txt", "content": "safe"})
    record = _record(call, "ev_safe")

    store.append(call, record)
    got = store.get("ev_safe")
    assert got is not None
    assert got.get("redacted") is None
    assert got["args"] == {"path": "public.txt", "content": "safe"}


def test_get_missing_id_returns_none(tmp_path: Path) -> None:
    store = ReplaySideStore(tmp_path / "replay.jsonl")
    assert store.get("ev_absent") is None


def test_multiple_events_each_resolve(tmp_path: Path) -> None:
    store = ReplaySideStore(tmp_path / "replay.jsonl")
    for i in range(5):
        call = ToolCall(name="noop", args={"i": i})
        store.append(call, _record(call, f"ev_{i}"))

    for i in range(5):
        got = store.get(f"ev_{i}")
        assert got is not None
        assert got["args"] == {"i": i}


def test_empty_state_and_path_round_trip(tmp_path: Path) -> None:
    store = ReplaySideStore(tmp_path / "replay.jsonl")
    call = ToolCall(name="ping", args={})
    record = _record(call, "ev_empty")
    store.append(call, record)

    got = store.get("ev_empty")
    assert got is not None
    assert got["state"] == {}
    assert got["path"] == []
    reconstructed = ToolCall(
        name=got["tool"],
        args=dict(got["args"]),
        path=tuple(got["path"]),
        state=dict(got["state"]),
    )
    assert reconstructed.argument_hash() == call.argument_hash()
