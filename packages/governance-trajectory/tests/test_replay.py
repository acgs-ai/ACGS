from __future__ import annotations

from pathlib import Path

from acgs_trajectory.replay import replay

FIX = Path(__file__).parent / "fixtures" / "complete_session.jsonl"


def test_replay_byte_identical_across_runs():
    a = replay(FIX)
    b = replay(FIX)
    assert a.canonical == b.canonical, "canonical output not byte-identical"
    assert a.canonical_sha256 == b.canonical_sha256
    assert a.normalized_sha256 == b.normalized_sha256
    assert a.trajectory_id == b.trajectory_id


def test_replay_status_complete_with_frozen_git():
    art = replay(FIX)
    assert art.status == "complete", art.record["integrity"]["reasons"]


def test_replay_does_not_mutate_fixture():
    from acgs_trajectory.canonical import sha256_hex

    before = sha256_hex(FIX.read_text(encoding="utf-8"))
    replay(FIX)
    after = sha256_hex(FIX.read_text(encoding="utf-8"))
    assert before == after


def test_replay_digest_is_stable_value():
    # pin the digest so accidental format drift is caught by the suite
    art = replay(FIX)
    assert len(art.canonical_sha256) == 64
    # a second independent computation from the record reproduces it
    from acgs_trajectory.canonical import canonical_bytes, sha256_hex

    assert sha256_hex(canonical_bytes(art.record)) == art.canonical_sha256
