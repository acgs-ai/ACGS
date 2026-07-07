"""Tests for the performance-optimization surfaces added in the benchmark pass.

Covers:
- ``ChainHashAuditStore.append_many`` (batched, single-fsync appends) — chain
  rules identical to a loop of ``append``.
- The append tail-hash fast path — cross-instance interleaving must still
  produce one valid chain (the stat guard must fall back to the tail read).
- ``ToolCall`` hash memoization — values identical to the un-memoized hashes,
  and never carried across ``with_args``.
- ``ReplaySideStore(durable=False)`` — same records, fsync skipped.
- ``replay_bundle`` after the single-evaluation refactor — verdicts unchanged
  for the good, tampered, and missing-side-record cases.
"""

from __future__ import annotations

from pathlib import Path

from gove_zone import BoundaryPolicy, ChainHashAuditStore, Kernel
from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import sha256_json
from gove_zone.replay import replay_bundle, replay_from_side_store
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall

POLICY = BoundaryPolicy(forbidden_keywords=["~/.ssh"], rule_id="T")


def _record(i: int):
    call = ToolCall(name="t", args={"i": i}, goal="g", actor="a")
    return POLICY.evaluate(call)


class TestAppendMany:
    def test_batch_forms_valid_chain(self, tmp_path: Path) -> None:
        store = ChainHashAuditStore(tmp_path / "a.jsonl")
        payloads = store.append_many(_record(i) for i in range(5))
        assert len(payloads) == 5
        assert payloads[0]["previous_hash"] == GENESIS_HASH
        for prev, cur in zip(payloads, payloads[1:], strict=False):
            assert cur["previous_hash"] == prev["event_hash"]
        verdict = store.verify_chain(
            expected_count=5, expected_last_hash=payloads[-1]["event_hash"]
        )
        assert verdict["valid"], verdict

    def test_empty_batch_writes_nothing(self, tmp_path: Path) -> None:
        store = ChainHashAuditStore(tmp_path / "a.jsonl")
        assert store.append_many([]) == []
        assert not (tmp_path / "a.jsonl").exists()

    def test_batch_interleaves_with_single_appends(self, tmp_path: Path) -> None:
        store = ChainHashAuditStore(tmp_path / "a.jsonl")
        first = store.append(_record(0))
        batch = store.append_many([_record(1), _record(2)])
        last = store.append(_record(3))
        assert batch[0]["previous_hash"] == first["event_hash"]
        assert last["previous_hash"] == batch[-1]["event_hash"]
        assert store.verify_chain(expected_count=4)["valid"]


class TestAppendFastPath:
    def test_two_instances_interleaved_appends_stay_chained(self, tmp_path: Path) -> None:
        """A second writer advances the file; the first instance's cached tail
        must be invalidated by the size guard, never reused stale."""
        path = tmp_path / "a.jsonl"
        one = ChainHashAuditStore(path)
        two = ChainHashAuditStore(path)
        for i in range(6):
            (one if i % 2 == 0 else two).append(_record(i))
        assert one.verify_chain(expected_count=6)["valid"]

    def test_fast_path_survives_last_hash_read(self, tmp_path: Path) -> None:
        store = ChainHashAuditStore(tmp_path / "a.jsonl")
        p1 = store.append(_record(0))
        assert store.last_hash() == p1["event_hash"]
        p2 = store.append(_record(1))
        assert p2["previous_hash"] == p1["event_hash"]
        assert store.verify_chain(expected_count=2)["valid"]


class TestToolCallMemoization:
    def test_hashes_match_unmemoized_values(self) -> None:
        call = ToolCall(name="t", args={"x": 1}, goal="g", actor="a", state={"s": 2})
        assert call.argument_hash() == sha256_json({"x": 1})
        assert call.state_hash() == sha256_json({"s": 2})
        # Second call returns the cached value, identical.
        assert call.argument_hash() == sha256_json({"x": 1})
        assert call.decision_request_hash() == call.decision_request_hash()

    def test_with_args_never_inherits_cache(self) -> None:
        call = ToolCall(name="t", args={"x": 1})
        before = call.argument_hash()
        replaced = call.with_args({"x": 2})
        assert replaced.argument_hash() == sha256_json({"x": 2})
        assert replaced.argument_hash() != before

    def test_empty_state_hash_is_none(self) -> None:
        call = ToolCall(name="t", args={})
        assert call.state_hash() is None


class TestReplaySideStoreDurability:
    def test_non_durable_roundtrip(self, tmp_path: Path) -> None:
        store = ReplaySideStore(tmp_path / "side.jsonl", durable=False)
        call = ToolCall(name="t", args={"x": 1}, goal="g", actor="a")
        record = POLICY.evaluate(call)
        store.append(call, record)
        got = store.get(record.event_id)
        assert got is not None and got["args"] == {"x": 1}

    def test_default_is_durable(self, tmp_path: Path) -> None:
        store = ReplaySideStore(tmp_path / "side.jsonl")
        assert store._durable is True


class TestReplayBundleVerdicts:
    def _governed_run(self, tmp_path: Path, n: int = 4):
        audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
        side = ReplaySideStore(tmp_path / "side.jsonl")
        kernel = Kernel(policy=POLICY, audit=audit, actor="a", side_store=side)
        kernel.tool("t")(lambda **kw: kw)
        for i in range(n):
            kernel.dispatch("t", {"i": i}, goal="g")
        return audit, side

    def test_valid_chain_fully_matches(self, tmp_path: Path) -> None:
        audit, side = self._governed_run(tmp_path)
        verdict = replay_bundle(audit, side, POLICY)
        assert verdict["valid"], verdict
        assert verdict["events_matched"] == verdict["events_total"] == 4
        assert verdict["events_degraded"] == 0

    def test_tampered_side_args_fail_closed(self, tmp_path: Path) -> None:
        audit, side = self._governed_run(tmp_path)
        event = next(iter(audit.iter_events()))
        side_record = dict(side.get(str(event["event_id"])) or {})
        side_record["args"] = {"i": 999}
        result = replay_from_side_store(event, side_record, POLICY)
        assert not result.matches
        assert not result.argument_hash_match
        assert not result.re_derived

    def test_missing_side_record_never_counts_as_matched(self, tmp_path: Path) -> None:
        audit, _side = self._governed_run(tmp_path)
        empty_side = ReplaySideStore(tmp_path / "empty-side.jsonl")
        verdict = replay_bundle(audit, empty_side, POLICY)
        assert not verdict["valid"]
        assert verdict["events_matched"] == 0
        assert verdict["events_degraded"] == verdict["events_total"] == 4
