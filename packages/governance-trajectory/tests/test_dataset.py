"""Phase 4 index + packaging + dataset-product tests."""

from __future__ import annotations

from pathlib import Path

from acgs_trajectory import datasets
from acgs_trajectory.evaluate import evaluate
from acgs_trajectory.index import Index
from acgs_trajectory.ingest import ingest_text
from acgs_trajectory.outcome import build_outcome
from acgs_trajectory.packaging import ReleaseStore, build_tiered_release

CAP = "1970-01-01T00:00:00Z"
GIT = {"head_sha": "a" * 40, "dirty": False, "branch": "master"}
FULL = {"commit": {"sha": "b" * 40}, "tests": {"passed": True, "command": "pytest -q"},
        "ci": {"status": "passed"}, "review": {"decision": "approved", "reviewer": "human"}}


def _ann(read_fixture, name):
    raw = read_fixture(name)
    rec = ingest_text(raw, store=None, captured_at=CAP, repo_git=GIT).record
    return rec, evaluate(rec, raw)


def _built_index(read_fixture, with_good_outcome=True):
    idx = Index(":memory:")
    for name in ("good_engineering_session.jsonl", "weak_engineering_session.jsonl", "privileged_change_session.jsonl"):
        rec, ann = _ann(read_fixture, name)
        idx.add_trajectory(rec)
        idx.add_annotation(ann)
        if with_good_outcome and name == "good_engineering_session.jsonl":
            idx.add_outcome(build_outcome(ann, FULL))
    return idx


def test_effective_tier_uses_outcome(read_fixture):
    idx = _built_index(read_fixture, with_good_outcome=True)
    good = [t for t in idx.by_effective_tier(("S",))]
    assert good, "good trajectory with full outcome should be tier S"
    # without the outcome it is only provisional B
    idx2 = _built_index(read_fixture, with_good_outcome=False)
    assert not idx2.by_effective_tier(("S", "A"))
    idx.close(); idx2.close()


def test_tier_counts(read_fixture):
    idx = _built_index(read_fixture)
    counts = idx.tier_counts()
    assert sum(counts.values()) == 3
    assert counts.get("S", 0) == 1
    idx.close()


def test_tiered_release_manifest_stable_and_references_only(read_fixture):
    idx = _built_index(read_fixture)
    m1 = build_tiered_release(idx, "S")
    m2 = build_tiered_release(idx, "S")
    assert m1["content_sha256"] == m2["content_sha256"]  # deterministic
    assert m1["counts"]["members"] == 1
    # members are references (ids + digests), never raw content
    for mem in m1["members"]:
        assert set(mem) == {"trajectory_id", "normalized_sha256", "annotation_id", "outcome_id", "effective_tier"}
        assert "content" not in mem
    idx.close()


def test_release_store_chain(read_fixture, tmp_path):
    idx = _built_index(read_fixture)
    store = ReleaseStore(tmp_path)
    for tier in ("S", "A", "B", "C"):
        store.publish(build_tiered_release(idx, tier))
    ok, errors = store.verify_chain()
    assert ok, errors
    idx.close()


def test_dataset_claude_engineering(read_fixture):
    idx = _built_index(read_fixture)
    ds = datasets.acgs_claude_engineering(idx)
    ids = {m["trajectory_id"] for m in ds["members"]}
    good_id = [t for t in idx.by_effective_tier(("S",))][0]
    assert good_id in ids  # S-tier high-eng trajectory is included
    assert ds["name"] == "ACGS-Claude-Engineering-v1"
    idx.close()


def test_dataset_governance_benchmark(read_fixture):
    idx = _built_index(read_fixture)
    ds = datasets.acgs_governance_benchmark(idx)
    # the privileged (governance-area) trajectory is a member with a verdict
    assert ds["counts"]["members"] >= 1
    verdicts = {v["trajectory_id"]: v["verdict"] for v in ds["verdicts"]}
    priv = idx.by_area(("governance",))
    assert priv and verdicts[priv[0]] == "unsafe_or_unverified"  # low gov + high risk
    idx.close()


def test_dataset_agent_swe(read_fixture):
    idx = _built_index(read_fixture)
    ds = datasets.acgs_agent_swe(idx)
    good_id = [t for t in idx.by_effective_tier(("S",))][0]
    assert good_id in {m["trajectory_id"] for m in ds["members"]}
    assert ds["name"] == "ACGS-Agent-SWE"
    idx.close()


def test_all_datasets_deterministic(read_fixture):
    idx = _built_index(read_fixture)
    a = [d["content_sha256"] for d in datasets.build_all(idx)]
    b = [d["content_sha256"] for d in datasets.build_all(idx)]
    assert a == b
    idx.close()


def test_regrounding_replaces_stale_outcome(read_fixture):
    # a later outcome for the same trajectory REPLACES the earlier one (no ambiguity)
    idx = Index(":memory:")
    rec, ann = _ann(read_fixture, "good_engineering_session.jsonl")
    idx.add_trajectory(rec); idx.add_annotation(ann)
    # first ground with weak evidence -> B, then re-ground with full -> S
    idx.add_outcome(build_outcome(ann, {"commit": {"sha": "b" * 40}, "tests": {"passed": None}}))
    assert idx.effective_tier(rec["trajectory_id"]) == "B"
    idx.add_outcome(build_outcome(ann, FULL))
    assert idx.effective_tier(rec["trajectory_id"]) == "S"  # replaced, not masked
    n = idx.conn.execute("SELECT COUNT(*) c FROM outcomes WHERE trajectory_id=?", (rec["trajectory_id"],)).fetchone()["c"]
    assert n == 1
    idx.close()


def test_governance_benchmark_safe_verdict_at_zero_risk(read_fixture):
    # risk == 0.0 (best case) with high governance must read as SAFE, not unsafe
    idx = Index(":memory:")
    rec, ann = _ann(read_fixture, "good_engineering_session.jsonl")
    # craft a governance-area annotation with ideal risk/governance
    ann = dict(ann)
    ann["system_area"] = "governance"
    ann["scores"] = {**ann["scores"], "risk": 0.0, "governance": 0.9}
    idx.add_trajectory(rec); idx.add_annotation(ann)
    ds = datasets.acgs_governance_benchmark(idx)
    v = {x["trajectory_id"]: x["verdict"] for x in ds["verdicts"]}
    assert v[rec["trajectory_id"]] == "safe_governance_modification"
    idx.close()


def test_index_rebuildable_from_records(read_fixture, tmp_path):
    # building the same index twice yields identical effective tiers (derived/rebuildable)
    i1 = _built_index(read_fixture); i2 = _built_index(read_fixture)
    assert i1.tier_counts() == i2.tier_counts()
    i1.close(); i2.close()
