"""Phase 2 evaluator + annotation tests (deterministic, evidence-cited, fail-closed)."""

from __future__ import annotations

import json
from pathlib import Path

from acgs_trajectory import scoring
from acgs_trajectory.annotation_store import AnnotationStore
from acgs_trajectory.evaluate import evaluate
from acgs_trajectory.ingest import ingest_text

CAP = "1970-01-01T00:00:00Z"
GIT = {"head_sha": "a" * 40, "dirty": False, "branch": "master"}
ROOT = Path(__file__).resolve().parents[1]


def annotate(read_fixture, name):
    raw = read_fixture(name)
    rec = ingest_text(raw, store=None, captured_at=CAP, repo_git=GIT).record
    return evaluate(rec, raw), rec, raw


# ---- schema + structure -----------------------------------------------------


def test_annotation_validates_against_schema(read_fixture):
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / "acgs_trajectory/schemas/governance_annotation_v1.schema.json").read_text())
    ann, _, _ = annotate(read_fixture, "good_engineering_session.jsonl")
    Draft202012Validator(schema).validate(ann)


def test_packaged_annotation_schema_matches_docs():
    a = (ROOT / "acgs_trajectory/schemas/governance_annotation_v1.schema.json").read_bytes()
    b = (ROOT / "docs/schema/governance_annotation_v1.schema.json").read_bytes()
    assert a == b


# ---- good engineering: high scores, A-candidate, capped at B ----------------


def test_good_engineering_scores_high(read_fixture):
    ann, _, _ = annotate(read_fixture, "good_engineering_session.jsonl")
    by = {c["name"]: c for c in ann["checks"]}
    assert by["investigate_before_modify"]["passed"]
    assert by["tests_added"]["passed"]
    assert by["verified_claims"]["passed"]
    assert ann["scores"]["engineering_quality"] >= 0.8
    assert ann["scores"]["governance"] >= 0.8


def test_good_engineering_is_A_candidate_capped_at_B(read_fixture):
    ann, _, _ = annotate(read_fixture, "good_engineering_session.jsonl")
    assert ann["tier"]["assigned"] == "B"
    assert ann["tier"]["ceiling"] == "B"
    assert ann["tier"]["candidate_for"] == "A"  # never confirmed in Phase 2
    assert any("phase3" in r for r in ann["tier"]["reasons"])


# ---- weak engineering: low, no candidate ------------------------------------


def test_weak_engineering_low_no_candidate(read_fixture):
    ann, _, _ = annotate(read_fixture, "weak_engineering_session.jsonl")
    by = {c["name"]: c for c in ann["checks"]}
    assert not by["investigate_before_modify"]["passed"]
    assert not by["tests_added"]["passed"]
    assert ann["scores"]["engineering_quality"] < 0.5
    assert ann["tier"]["candidate_for"] is None


# ---- privileged change: high risk, low governance, security check fails ------


def test_benign_hook_does_not_grant_fail_closed(read_fixture):
    # a privileged change with ONLY a benign PostToolUse hook must FAIL fail_closed_preserved
    ann, _, _ = annotate(read_fixture, "privileged_benign_hook_session.jsonl")
    by = {c["name"]: c for c in ann["checks"]}
    assert by["fail_closed_preserved"]["passed"] is False
    assert by["fail_closed_preserved"]["score"] == 0.0
    assert "privileged_change_no_governance_hooks" in by["fail_closed_preserved"]["evidence"]


def test_unrelated_investigation_does_not_pass(read_fixture):
    # reading an unrelated path before editing a different file must NOT count as investigation
    ann, _, _ = annotate(read_fixture, "unrelated_investigation_session.jsonl")
    by = {c["name"]: c for c in ann["checks"]}
    assert by["investigate_before_modify"]["passed"] is False
    assert by["investigate_before_modify"]["score"] == 0.0


def test_failing_checks_still_carry_evidence(read_fixture):
    # P2-3: every check cites >=1 evidence ref even when it FAILS (reason tokens)
    for name in ("weak_engineering_session.jsonl", "privileged_change_session.jsonl"):
        ann, _, _ = annotate(read_fixture, name)
        for c in ann["checks"]:
            assert c["evidence"], f"{name}: check {c['name']} failed with empty evidence"


def test_privileged_change_high_risk(read_fixture):
    ann, _, _ = annotate(read_fixture, "privileged_change_session.jsonl")
    assert ann["system_area"] == "governance"
    by = {c["name"]: c for c in ann["checks"]}
    assert not by["security_risk_identified"]["passed"]
    assert not by["fail_closed_preserved"]["passed"]
    assert ann["scores"]["risk"] >= 0.5
    assert ann["scores"]["governance"] < 0.5


# ---- determinism ------------------------------------------------------------


def test_determinism_identical(read_fixture):
    raw = read_fixture("good_engineering_session.jsonl")
    rec = ingest_text(raw, store=None, captured_at=CAP, repo_git=GIT).record
    a1 = evaluate(rec, raw)
    a2 = evaluate(rec, raw)
    assert a1 == a2
    assert a1["integrity"]["annotation_sha256"] == a2["integrity"]["annotation_sha256"]


def test_annotation_id_binds_trajectory_and_evaluator(read_fixture):
    ann, rec, _ = annotate(read_fixture, "good_engineering_session.jsonl")
    from acgs_trajectory.canonical import sha256_hex

    expect = sha256_hex(rec["integrity"]["normalized_sha256"] + scoring.EVALUATOR_VERSION)
    assert ann["annotation_id"] == expect
    assert ann["trajectory_ref"]["normalized_sha256"] == rec["integrity"]["normalized_sha256"]


# ---- evidence completeness --------------------------------------------------


def test_every_check_and_label_present_and_evidenced(read_fixture):
    ann, _, _ = annotate(read_fixture, "good_engineering_session.jsonl")
    assert [c["name"] for c in ann["checks"]] == list(scoring.CHECK_NAMES)
    for c in ann["checks"]:
        assert c["evidence"], f"check {c['name']} has no evidence"
    eng = {l["name"] for l in ann["labels"]["engineering"]}
    gov = {l["name"] for l in ann["labels"]["governance"]}
    assert eng == set(scoring.ENGINEERING_LABELS)
    assert gov == set(scoring.GOVERNANCE_LABELS)


# ---- fail-closed on tampered / mismatched input -----------------------------


def test_input_mismatch_fails_closed(read_fixture):
    raw = read_fixture("good_engineering_session.jsonl")
    rec = ingest_text(raw, store=None, captured_at=CAP, repo_git=GIT).record
    ann = evaluate(rec, raw + "\n{}")  # raw no longer matches provenance digest
    assert ann["integrity"]["inputs_verified"] is False
    assert ann["scores"]["trajectory"] == 0.0
    assert ann["tier"]["assigned"] == "C"


def test_quarantined_trajectory_is_tier_C(read_fixture):
    raw = read_fixture("secret_session.jsonl")
    rec = ingest_text(raw, store=None, captured_at=CAP).record
    assert rec["integrity"]["status"] == "quarantined"
    ann = evaluate(rec, raw)
    assert ann["tier"]["assigned"] == "C"


# ---- separation: evaluator never mutates the frozen record ------------------


def test_evaluator_does_not_mutate_record(read_fixture):
    raw = read_fixture("good_engineering_session.jsonl")
    rec = ingest_text(raw, store=None, captured_at=CAP, repo_git=GIT).record
    before = json.dumps(rec, sort_keys=True)
    evaluate(rec, raw)
    assert json.dumps(rec, sort_keys=True) == before
    assert rec["derived"] == {"scores": None, "labels": None, "tier": None, "outcome": None}


# ---- no LLM / network / wall-clock in the evaluator path --------------------


def test_no_forbidden_imports_in_evaluator():
    src = (ROOT / "acgs_trajectory/evaluate.py").read_text() + (ROOT / "acgs_trajectory/scoring.py").read_text()
    for forbidden in ("import requests", "import urllib", "import openai", "anthropic",
                      "import socket", "import random", "time.time", "datetime.now"):
        assert forbidden not in src, f"forbidden dependency in evaluator: {forbidden}"


# ---- annotation store: hash-chained, rebuildable ----------------------------


def test_annotation_store_chain_and_rebuild(read_fixture, tmp_path):
    store = AnnotationStore(tmp_path)
    for name in ("good_engineering_session.jsonl", "weak_engineering_session.jsonl"):
        ann, _, _ = annotate(read_fixture, name)
        store.annotate(ann)
    ok, errors = store.verify_chain()
    assert ok, errors
    # rebuild: recomputing the annotation reproduces the same content hash
    ann2, _, _ = annotate(read_fixture, "good_engineering_session.jsonl")
    stored = json.loads((tmp_path / f"annotations/{ann2['annotation_id'][:2]}/{ann2['annotation_id']}.json").read_text())
    assert stored["integrity"]["annotation_sha256"] == ann2["integrity"]["annotation_sha256"]
