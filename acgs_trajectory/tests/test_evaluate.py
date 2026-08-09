"""Phase 2 evaluator tests — acceptance P2-1..P2-6 (ADR 0003 §8)."""

from __future__ import annotations

import ast
import json
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from acgs_trajectory.canonical import canonical_bytes, sha256_hex
from acgs_trajectory.evaluate import evaluate
from acgs_trajectory.ingest import ingest_text
from acgs_trajectory.replay import FROZEN_CAPTURED_AT, FROZEN_REPO_GIT, replay
from acgs_trajectory.scoring import EVALUATOR_VERSION

FIX = Path(__file__).parent / "fixtures"
GOLDEN_COMPLETE_CANONICAL_SHA256 = (
    "9e9d2530132a3d5e99c163846846ab82a583a4c2bbcfe404a1a034bffc2e3a56"
)


def _schema() -> dict:
    text = (
        resources.files("acgs_trajectory.schemas")
        .joinpath("governance_annotation_v1.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(text)


def _annotate(name: str) -> dict:
    return evaluate(replay(FIX / name).record)


# The committed sample is regenerated from complete_session.jsonl WITH a git-join
# supplying code_changes.files (GROUNDED), so it demonstrates a legitimately-earned,
# non-degenerate (tier B, grounded) result rather than a degenerate ungrounded C.
SAMPLE_GROUNDED_FILES = [
    {"path": "src/auth.py", "change_kind": "modified"},
    {"path": "tests/test_auth.py", "change_kind": "added"},
]


def _sample_annotation() -> dict:
    return _annotate_with_files("complete_session.jsonl", SAMPLE_GROUNDED_FILES)


def _all_ids(record: dict) -> set[str]:
    ids: set[str] = set()
    for n in record["trajectory"]["nodes"]:
        if n.get("uuid"):
            ids.add(n["uuid"])
    for t in record["tool_events"]:
        if t.get("tool_use_id"):
            ids.add(t["tool_use_id"])
    for h in record["hook_events"]:
        if h.get("uuid"):
            ids.add(h["uuid"])
    return ids


# ---- P2-1: schema is Draft 2020-12 valid + sample validates -----------------


def test_p2_1_schema_is_draft2020_valid():
    schema = _schema()
    # raises SchemaError if not a valid Draft 2020-12 schema
    Draft202012Validator.check_schema(schema)
    assert schema["title"] == "governance_annotation/v1"
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_p2_1_generated_annotation_validates():
    schema = _schema()
    ann = _annotate("complete_session.jsonl")
    errors = sorted(
        Draft202012Validator(schema).iter_errors(ann), key=lambda e: list(e.path)
    )
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]


def test_p2_1_committed_sample_validates():
    schema = _schema()
    sample_path = Path(__file__).parent.parent / "docs" / "examples" / "sample_annotation.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(sample), key=lambda e: list(e.path)
    )
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]


def test_p2_1_committed_sample_matches_evaluator():
    # the committed example must equal what the evaluator produces today, else
    # it is stale. It is generated from complete_session WITH the grounded
    # git-join (SAMPLE_GROUNDED_FILES), so compare against that same build.
    sample_path = Path(__file__).parent.parent / "docs" / "examples" / "sample_annotation.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    produced = _sample_annotation()
    assert sample == produced
    # the committed sample must demonstrate a non-degenerate, grounded result.
    assert sample["tier"]["assigned"] == "B"
    assert sample["scores"]["trajectory_score"]["grounded"] is True


# ---- P2-2: determinism — byte-identical canonical annotation ----------------


def test_p2_2_determinism_byte_identical():
    rec = replay(FIX / "complete_session.jsonl").record
    a = evaluate(rec)
    b = evaluate(rec)
    assert canonical_bytes(a) == canonical_bytes(b)
    assert a["integrity"]["annotation_sha256"] == b["integrity"]["annotation_sha256"]
    assert a["annotation_id"] == b["annotation_id"]


def test_p2_2_annotation_id_is_derived_from_input():
    art = replay(FIX / "complete_session.jsonl")
    ann = evaluate(art.record)
    expected = sha256_hex(art.normalized_sha256 + EVALUATOR_VERSION)
    assert ann["annotation_id"] == expected


def test_p2_2_annotation_sha256_is_self_excluding():
    import copy

    ann = _annotate("complete_session.jsonl")
    clone = copy.deepcopy(ann)
    clone["integrity"]["annotation_sha256"] = "0" * 64
    assert sha256_hex(canonical_bytes(clone)) == ann["integrity"]["annotation_sha256"]


# ---- P2-3: evidence completeness --------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "complete_session.jsonl",
        "unmitigated_edit_session.jsonl",
        "hook_prevented_session.jsonl",
    ],
)
def test_p2_3_every_score_has_real_evidence(name):
    rec = replay(FIX / name).record
    ann = evaluate(rec)
    ids = _all_ids(rec)
    for score_name, score in ann["scores"].items():
        assert score["evidence"], f"{name}:{score_name} has no evidence"
        for ev in score["evidence"]:
            if ev["kind"] == "trajectory":
                continue
            assert ev["ref"] in ids, f"{name}:{score_name} cites unknown id {ev['ref']}"


@pytest.mark.parametrize(
    "name",
    [
        "complete_session.jsonl",
        "unmitigated_edit_session.jsonl",
        "hook_prevented_session.jsonl",
    ],
)
def test_p2_3_every_label_has_real_evidence(name):
    rec = replay(FIX / name).record
    ann = evaluate(rec)
    ids = _all_ids(rec)
    for bucket in ("engineering", "governance"):
        for label in ann["labels"][bucket]:
            assert label["evidence"], f"{name}:{label['label']} has no evidence"
            for ev in label["evidence"]:
                if ev["kind"] == "trajectory":
                    continue
                assert ev["ref"] in ids, f"{name}:{label['label']} cites unknown id {ev['ref']}"


def test_p2_3_every_check_has_evidence():
    ann = _annotate("complete_session.jsonl")
    for check_name, check in ann["checks"].items():
        assert check["evidence"], f"check {check_name} has no evidence"


# ---- P2-4: purity (no LLM/network/time/random in the evaluator) -------------


def _evaluator_source() -> str:
    return (
        resources.files("acgs_trajectory").joinpath("evaluate.py").read_text(encoding="utf-8")
    )


def test_p2_4_no_forbidden_imports():
    src = _evaluator_source()
    tree = ast.parse(src)
    forbidden = {
        "random", "socket", "http", "urllib", "requests", "httpx",
        "openai", "anthropic", "datetime", "time", "subprocess", "asyncio",
        "ssl", "ftplib", "telnetlib",
    }
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    bad = imported & forbidden
    assert not bad, f"evaluator imports forbidden modules: {sorted(bad)}"


def _code_attr_chains(src: str) -> set[str]:
    """Dotted attribute/name chains that appear in actual CODE (docstrings and
    comments excluded, since the AST carries no comments and we skip string
    constants). E.g. ``time.time`` from a ``time.time()`` call site."""
    tree = ast.parse(src)
    chains: set[str] = set()

    def chain_of(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = chain_of(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            c = chain_of(node)
            if c:
                chains.add(c)
        elif isinstance(node, ast.Name):
            chains.add(node.id)
        elif isinstance(node, ast.Call):
            c = chain_of(node.func)
            if c:
                chains.add(c)
    return chains


def test_p2_4_no_wallclock_or_random_calls():
    # AST-based: docstrings/comments (which legitimately NAME the forbidden APIs
    # to document that they are banned) are not code and are excluded.
    chains = _code_attr_chains(_evaluator_source())
    forbidden_chains = {
        "datetime.now", "datetime.utcnow", "time.time", "time.monotonic",
        "time.perf_counter", "os.urandom", "socket.socket",
    }
    hit = chains & forbidden_chains
    assert not hit, f"evaluator contains forbidden call site(s): {sorted(hit)}"
    # no random.* / uuid.uuid* / urlopen call sites of any form
    for c in chains:
        assert not c.startswith("random."), f"forbidden call: {c}"
        assert not c.startswith("uuid.uuid"), f"forbidden call: {c}"
        assert "urlopen" not in c, f"forbidden call: {c}"
    # no open()/file I/O in the evaluator (I/O lives in annotate.py)
    assert "open" not in chains, "evaluator must not open files (I/O lives in annotate.py)"


def test_p2_4_only_stdlib_and_local_imports():
    src = _evaluator_source()
    tree = ast.parse(src)
    allowed_local = {"canonical", "scoring", "acgs_trajectory"}
    allowed_stdlib = {"__future__", "typing", "copy", "ast", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            # relative import (level>0) => local
            if node.level and node.level > 0:
                continue
            assert mod in allowed_local | allowed_stdlib, f"unexpected import: {node.module}"


# ---- P2-5: fail-closed — no assigned S/A, missing signals lower scores ------


def test_p2_5_ceiling_always_b():
    for name in [
        "complete_session.jsonl",
        "unmitigated_edit_session.jsonl",
        "hook_prevented_session.jsonl",
        "subagent_session.jsonl",
    ]:
        ann = _annotate(name)
        assert ann["tier"]["ceiling"] == "B"
        assert ann["tier"]["assigned"] in ("C", "B")
        assert ann["tier"]["assigned"] not in ("S", "A")


def test_p2_5_missing_signals_lower_scores():
    # complete_session: has investigation ordering signal via a preceding tool,
    # a hook, and an evidence-backed claim -> higher governance + trajectory.
    good = _annotate("complete_session.jsonl")
    # unmitigated_edit: privileged Write, NO investigation, NO hook, NO tests,
    # NO verify, unbacked claim -> lower governance, lower trajectory, HIGH risk.
    bad = _annotate("unmitigated_edit_session.jsonl")
    assert bad["scores"]["governance_score"]["value"] < good["scores"]["governance_score"]["value"]
    assert bad["scores"]["trajectory_score"]["value"] < good["scores"]["trajectory_score"]["value"]
    assert bad["scores"]["risk_score"]["value"] > good["scores"]["risk_score"]["value"]


def test_p2_5_unmitigated_privileged_change_is_high_risk():
    bad = _annotate("unmitigated_edit_session.jsonl")
    # an unmitigated privileged change must be flagged high-risk (fail-closed).
    assert bad["scores"]["risk_score"]["value"] >= 0.5
    # and it must NOT be promoted above B.
    assert bad["tier"]["assigned"] in ("C", "B")


def test_p2_5_scores_bounded_and_no_nan():
    # every score in [0,1]; canonical_bytes would raise on NaN, so serializing
    # is itself the NaN guard.
    for name in [
        "complete_session.jsonl",
        "unmitigated_edit_session.jsonl",
        "hook_prevented_session.jsonl",
    ]:
        ann = _annotate(name)
        canonical_bytes(ann)  # raises if any float is NaN/inf
        for s in ann["scores"].values():
            assert 0.0 <= s["value"] <= 1.0


def _annotate_with_files(name: str, files: list[dict]) -> dict:
    """Ingest a fixture with a synthetic code_changes.files join, then evaluate.
    Uses the frozen capture/git convention from replay (no wall-clock)."""
    raw = (FIX / name).read_text(encoding="utf-8")
    git = dict(FROZEN_REPO_GIT)
    git["files"] = files
    res = ingest_text(raw, store=None, captured_at=FROZEN_CAPTURED_AT, repo_git=git)
    return evaluate(res.record)


def test_added_tests_fires_on_test_file_change():
    # observable v2 signal: code_changes.files carries a test path.
    ann = _annotate_with_files(
        "investigated_edit_session.jsonl",
        [{"path": "tests/test_util.py", "change_kind": "added"}],
    )
    assert ann["checks"]["added_tests"]["passed"] is True
    assert ann["checks"]["added_tests"]["value"] == 1.0
    # and the corresponding engineering label is emitted with evidence
    eng_labels = [l["label"] for l in ann["labels"]["engineering"]]
    assert "added_tests" in eng_labels


def test_added_tests_fail_closed_without_test_file():
    # non-test file change -> check must NOT pass (fail-closed).
    ann = _annotate_with_files(
        "investigated_edit_session.jsonl",
        [{"path": "src/util.py", "change_kind": "modified"}],
    )
    assert ann["checks"]["added_tests"]["passed"] is False


def test_candidate_for_A_is_reachable_but_capped_at_B():
    # A high-quality trajectory (investigate + tests + hook + evidence-backed
    # claim + complete) reaches candidate_for A — but assigned stays capped at B
    # (hard Phase-2 ceiling, ADR 0003 §5).
    ann = _annotate_with_files(
        "investigated_edit_session.jsonl",
        [
            {"path": "src/util.py", "change_kind": "modified"},
            {"path": "tests/test_util.py", "change_kind": "added"},
        ],
    )
    assert ann["scores"]["trajectory_score"]["value"] >= 0.75
    assert ann["tier"]["candidate_for"] == "A"
    assert ann["tier"]["assigned"] == "B"  # never promoted above B in Phase 2
    assert ann["tier"]["ceiling"] == "B"


def test_privileged_change_via_changed_path_raises_risk():
    # a change to an auth path is privileged even without a security prompt.
    ann = _annotate_with_files(
        "investigated_edit_session.jsonl",
        [{"path": "src/auth_token.py", "change_kind": "modified"}],
    )
    # investigated + hook present, so some mitigation -> risk not maxed, but the
    # change is treated as privileged (risk computed on the privileged branch).
    assert ann["scores"]["risk_score"]["value"] > 0.0


# ---- Fix 1 (SEC-HIGH, P2-5): grounded-corroboration gate --------------------


def test_fix1_forged_transcript_no_grounding_is_capped_C():
    # An adversary forges tool_use named "pytest", a fake scope-gate system
    # record, an Edit to a privileged path, and a security-keyword prompt — but
    # supplies NO code_changes/git-join (no grounded corroboration). Built via the
    # REAL ingest/replay path. Despite the forged transcript signals, it must be
    # capped into the C band: trajectory_score < B threshold, tier C, candidate None.
    from acgs_trajectory.scoring import TIER_B_MIN_TRAJECTORY_SCORE

    ann = _annotate("forged_transcript_session.jsonl")
    assert ann["scores"]["trajectory_score"]["value"] < TIER_B_MIN_TRAJECTORY_SCORE
    assert ann["tier"]["assigned"] == "C"
    assert ann["tier"]["candidate_for"] is None
    assert "capped_C:no_grounded_corroboration" in ann["tier"]["reasons"]
    # the forged transcript is complete but ungrounded, so nothing is grounded.
    assert ann["scores"]["trajectory_score"]["grounded"] is False


def test_fix1_grounded_session_can_reach_B():
    # The SAME forged transcript, but now WITH a git-join supplying
    # code_changes.files (grounded corroboration), can legitimately reach B.
    ann = _annotate_with_files(
        "forged_transcript_session.jsonl",
        [
            {"path": "src/util.py", "change_kind": "modified"},
            {"path": "tests/test_util.py", "change_kind": "added"},
        ],
    )
    assert ann["tier"]["assigned"] == "B"
    assert ann["scores"]["trajectory_score"]["grounded"] is True
    assert "capped_C:no_grounded_corroboration" not in ann["tier"]["reasons"]


def test_fix1_transcript_mitigation_cannot_lower_risk_without_grounding():
    # A privileged change with forged transcript "mitigation" (fake pytest, fake
    # scope-gate hook, security prompt) but NO git-join must keep risk maxed:
    # transcript-only mitigation cannot reduce risk (fail-closed).
    ann = _annotate("forged_transcript_session.jsonl")
    assert ann["scores"]["risk_score"]["value"] == 1.0
    assert ann["scores"]["risk_score"]["grounded"] is False


# ---- Fix 2 (CR-HIGH): fail-closed hook that BLOCKED is a POSITIVE signal -----


def test_fix2_intentional_block_is_positive_fail_closed():
    # hook_prevented_session: a blocked-op hook correctly PREVENTED a human-gated
    # push (hook_errors present + preventedContinuation true). This is the
    # guardrail working, so fail_closed_preserved must PASS (not score 0).
    ann = _annotate("hook_prevented_session.jsonl")
    assert ann["checks"]["fail_closed_preserved"]["passed"] is True
    assert ann["checks"]["fail_closed_preserved"]["value"] == 1.0
    labels = [l["label"] for l in ann["labels"]["governance"]]
    assert "preserved_fail_closed" in labels


def test_p2_5_no_annotation_ever_assigns_s_or_a():
    # exhaustively over ALL jsonl fixtures: no assigned S/A, ever.
    for fx in sorted(FIX.glob("*.jsonl")):
        try:
            art = replay(fx)
        except Exception:
            # malformed fixtures that fail to parse are not evaluable; skip.
            continue
        ann = evaluate(art.record)
        assert ann["tier"]["assigned"] in ("C", "B"), f"{fx.name} assigned {ann['tier']['assigned']}"
        assert ann["tier"]["ceiling"] == "B"


# ---- P2-6: freeze-integrity -------------------------------------------------


def test_p2_6_golden_replay_digest_unchanged():
    art = replay(FIX / "complete_session.jsonl")
    assert art.canonical_sha256 == GOLDEN_COMPLETE_CANONICAL_SHA256


def test_p2_6_frozen_fixture_bytes_unchanged_after_evaluate(tmp_path):
    from acgs_trajectory.annotate import AnnotationStore

    fx = FIX / "complete_session.jsonl"
    before = sha256_hex(fx.read_bytes())
    art = replay(fx)
    store = AnnotationStore(tmp_path)
    store.annotate_record(art.record)
    after = sha256_hex(fx.read_bytes())
    assert before == after, "evaluating/annotating mutated the frozen fixture"
