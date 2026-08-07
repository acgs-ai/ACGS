"""Phase 3 outcome-grounding tests: fail-closed tier promotion only with evidence."""

from __future__ import annotations

import json
from pathlib import Path

from acgs_trajectory.evaluate import evaluate
from acgs_trajectory.ingest import ingest_text
from acgs_trajectory.outcome import OutcomeStore, build_outcome

CAP = "1970-01-01T00:00:00Z"
GIT = {"head_sha": "a" * 40, "dirty": False, "branch": "master"}
ROOT = Path(__file__).resolve().parents[1]


def ann_for(read_fixture, name):
    raw = read_fixture(name)
    rec = ingest_text(raw, store=None, captured_at=CAP, repo_git=GIT).record
    return evaluate(rec, raw)


FULL = {"commit": {"sha": "b" * 40}, "tests": {"passed": True, "command": "pytest -q"},
        "ci": {"status": "passed"}, "review": {"decision": "approved", "reviewer": "human"}}


def test_outcome_schema_valid(read_fixture):
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / "acgs_trajectory/schemas/governance_outcome_v1.schema.json").read_text())
    o = build_outcome(ann_for(read_fixture, "good_engineering_session.jsonl"), FULL)
    Draft202012Validator(schema).validate(o)


def test_packaged_outcome_schema_matches_docs():
    a = (ROOT / "acgs_trajectory/schemas/governance_outcome_v1.schema.json").read_bytes()
    b = (ROOT / "docs/schema/governance_outcome_v1.schema.json").read_bytes()
    assert a == b


def test_A_candidate_verified_outcome_confirms_A(read_fixture):
    ann = ann_for(read_fixture, "good_engineering_session.jsonl")
    assert ann["tier"]["candidate_for"] == "A"
    o = build_outcome(ann, {"commit": {"sha": "b" * 40}, "tests": {"passed": True}})
    assert o["grounded_tier"]["assigned"] == "A"


def test_full_evidence_confirms_S(read_fixture):
    o = build_outcome(ann_for(read_fixture, "good_engineering_session.jsonl"), FULL)
    assert o["grounded_tier"]["assigned"] == "S"
    assert "ci:passed" in o["grounded_tier"]["confirmed_by"]


def test_missing_tests_withholds_promotion(read_fixture):
    ann = ann_for(read_fixture, "good_engineering_session.jsonl")
    o = build_outcome(ann, {"commit": {"sha": "b" * 40}, "tests": {"passed": None}})
    assert o["grounded_tier"]["assigned"] == "B"  # candidate A, but no verified tests
    assert any("promotion_withheld" in r for r in o["grounded_tier"]["reasons"])


def test_failed_tests_withholds_promotion(read_fixture):
    ann = ann_for(read_fixture, "good_engineering_session.jsonl")
    o = build_outcome(ann, {"commit": {"sha": "b" * 40}, "tests": {"passed": False}})
    assert o["grounded_tier"]["assigned"] == "B"


def test_non_candidate_never_promotes(read_fixture):
    ann = ann_for(read_fixture, "weak_engineering_session.jsonl")
    assert ann["tier"]["candidate_for"] is None
    o = build_outcome(ann, FULL)  # even full evidence can't lift a non-candidate
    assert o["grounded_tier"]["assigned"] == ann["tier"]["assigned"]


def test_review_alone_without_tests_is_not_S(read_fixture):
    ann = ann_for(read_fixture, "good_engineering_session.jsonl")
    o = build_outcome(ann, {"commit": {"sha": "b" * 40}, "tests": {"passed": None},
                            "review": {"decision": "approved"}, "ci": {"status": "passed"}})
    assert o["grounded_tier"]["assigned"] == "B"  # no verified tests -> no A, no S


def test_determinism(read_fixture):
    ann = ann_for(read_fixture, "good_engineering_session.jsonl")
    a = build_outcome(ann, FULL)
    b = build_outcome(ann, FULL)
    assert a == b and a["integrity"]["outcome_sha256"] == b["integrity"]["outcome_sha256"]


def test_outcome_does_not_mutate_annotation(read_fixture):
    ann = ann_for(read_fixture, "good_engineering_session.jsonl")
    before = json.dumps(ann, sort_keys=True)
    build_outcome(ann, FULL)
    assert json.dumps(ann, sort_keys=True) == before


def test_invalid_base_tier_is_fail_closed(read_fixture):
    # a hand-forged annotation with an out-of-contract tier must not be trusted up
    ann = ann_for(read_fixture, "good_engineering_session.jsonl")
    ann["tier"]["assigned"] = "S"  # illegal for a Phase-2 annotation
    o = build_outcome(ann, FULL)
    assert o["grounded_tier"]["assigned"] == "C"
    assert "invalid_base_tier_fail_closed" in o["grounded_tier"]["reasons"]


def test_outcome_store_chain(read_fixture, tmp_path):
    store = OutcomeStore(tmp_path)
    for name in ("good_engineering_session.jsonl", "weak_engineering_session.jsonl"):
        store.annotate(build_outcome(ann_for(read_fixture, name), FULL))
    ok, errors = store.verify_chain()
    assert ok, errors
