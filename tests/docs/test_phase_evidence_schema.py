"""Validates the governed-loop-v2 phase-evidence schema (Phase 1 of the B3 plan).

The schema (``evidence/schema/phase.schema.json``) is the machine form of the
phase-N.json contract documented in ``evidence/README.md``. It pins STRUCTURE —
field presence, types, the ``ledger_head_hash`` format, and ``exit_criteria``
being an array of criterion-id STRINGS (the form the loop actually writes, not
objects). It deliberately does NOT pin the pass/fail VALUES: the Executor writes
``phase-N.json`` every cycle (``.claude/prompts/loop-v2.md`` §CYCLE PROTOCOL step
7), including a not-yet-passing mid-cycle snapshot that ``loop-stop-gate.sh`` then
blocks on, so a valid ``phase-N.json`` may legitimately have ``failed > 0`` or the
booleans false. Those three pass/fail conditions are owned by the jq Stop gate,
not this schema.

``jsonschema`` is an optional dependency absent from the minimal ``tests-docs`` CI
venv, so the behavioral checks below ``importorskip`` it. The CORE regression
guards (``exit_criteria`` is string-typed, the required fields, no value-pinning)
are therefore ALSO asserted STRUCTURALLY against the schema dict with the stdlib
alone — so they run, and cannot silently skip, in that CI job.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "evidence" / "schema" / "phase.schema.json"
README_PATH = ROOT / "evidence" / "README.md"

REQUIRED_FIELDS = {
    "phase",
    "exit_criteria",
    "exit_criteria_met",
    "validator_signoff",
    "test_results",
    "artifacts",
    "ledger_head_hash",
    "timestamp",
}
# The three conditions loop-stop-gate.sh checks with jq. The schema must REQUIRE
# these fields (so an evidence file omitting them is structurally invalid) but must
# NOT pin their pass/fail values — the gate owns that.
GATE_FIELDS = {"exit_criteria_met", "validator_signoff", "test_results"}


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _good_evidence() -> dict:
    return {
        "phase": 1,
        "exit_criteria": ["EC-1", "EC-2"],
        "exit_criteria_met": True,
        "validator_signoff": True,
        "test_results": {"passed": 4, "failed": 0},
        "artifacts": ["evidence/ledger.jsonl"],
        "ledger_head_hash": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
        "timestamp": "2026-07-06T00:00:00Z",
    }


# --- Structural guards: stdlib only, NEVER skip (run in the minimal tests-docs CI venv) ---


def test_required_is_exactly_the_eight_contract_fields() -> None:
    assert set(_schema()["required"]) == REQUIRED_FIELDS


def test_exit_criteria_items_are_strings_structurally() -> None:
    """Core regression guard: ``exit_criteria`` is an array of STRINGS, not
    objects. Asserted on the schema shape (not via a validator) so it holds even
    where ``jsonschema`` is absent. An object form would silently break the loop,
    which writes string criterion ids."""
    items = _schema()["properties"]["exit_criteria"]["items"]
    assert items.get("type") == "string"


def test_gate_fields_required_but_values_not_pinned() -> None:
    """Lockstep with loop-stop-gate.sh WITHOUT overclaiming: the schema must
    REQUIRE the three fields the jq gate reads, but must NOT pin their pass/fail
    values — the Executor writes not-yet-passing snapshots the gate blocks on, so
    pinning e.g. ``failed==0`` would reject a legitimate ``phase-N.json``. The
    gate, not the schema, decides pass/fail."""
    schema = _schema()
    assert GATE_FIELDS <= set(schema["required"])
    failed = schema["properties"]["test_results"]["properties"]["failed"]
    assert "const" not in failed and "enum" not in failed
    for b in ("exit_criteria_met", "validator_signoff"):
        assert "const" not in schema["properties"][b]


def test_readme_example_keys_match_schema_required() -> None:
    """Drift guard: the documented phase-N.json example must carry exactly the
    schema's required keys, so README and schema cannot diverge silently."""
    text = README_PATH.read_text(encoding="utf-8")
    m = re.search(r"## phase-N\.json schema.*?```json\n(.*?)\n```", text, re.DOTALL)
    assert m, "phase-N.json json example not found in evidence/README.md"
    example = json.loads(m.group(1))
    assert set(example) == set(_schema()["required"])


def test_ledger_head_hash_pattern_is_sha256_hex() -> None:
    pat = _schema()["properties"]["ledger_head_hash"]["pattern"]
    assert re.fullmatch(pat, "a" * 64) is not None
    assert re.fullmatch(pat, "nope") is None


# --- Behavioral guards: need jsonschema; a bonus where it is installed ---


def test_schema_is_valid_draft_2020_12() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(_schema())


def test_good_phase_evidence_validates() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator(_schema()).validate(_good_evidence())


def test_accepts_mid_loop_failing_snapshot() -> None:
    """The schema validates STRUCTURE, so a not-yet-passing snapshot (failed>0,
    booleans false) — which the loop legitimately writes and the gate blocks on —
    must VALIDATE. Guards against re-adding a value-pin that would reject it."""
    jsonschema = pytest.importorskip("jsonschema")
    snap = _good_evidence()
    snap["exit_criteria_met"] = False
    snap["validator_signoff"] = False
    snap["test_results"]["failed"] = 3
    jsonschema.Draft202012Validator(_schema()).validate(snap)


def test_rejects_object_exit_criteria() -> None:
    """Behavioral twin of the structural guard: an object ``exit_criteria`` is
    rejected by the validator (the loop writes string ids)."""
    jsonschema = pytest.importorskip("jsonschema")
    bad = _good_evidence()
    bad["exit_criteria"] = [{"id": "EC-1", "met": True}]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(_schema()).validate(bad)


def test_rejects_bad_ledger_hash_and_missing_field() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    v = jsonschema.Draft202012Validator(_schema())
    bad_hash = _good_evidence()
    bad_hash["ledger_head_hash"] = "nope"
    with pytest.raises(jsonschema.ValidationError):
        v.validate(bad_hash)
    missing = _good_evidence()
    del missing["validator_signoff"]
    with pytest.raises(jsonschema.ValidationError):
        v.validate(missing)
