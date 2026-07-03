"""Smoke gate for the Pack II root governance artifacts (B1 + B3).

* B1: ``.claude/policy/build.yaml`` loads under the real RuleSetPolicy grammar
  and enforces its intent (deny catastrophic shell, escalate release push,
  allow ordinary build commands, honor the trust-tier exemption).
* B3: ``evidence/schema/phase.schema.json`` is a valid JSON Schema, the shipped
  sample validates, and a phase with a failing test is rejected.

Mirrors the gove_zone bootstrap used by test_docs_and_examples.py (inject
``packages/gove-zone/src`` onto sys.path) so this runs in the minimal tests-docs
CI venv, and skips cleanly where an optional dep (jsonschema) is absent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages" / "gove-zone" / "src"))


def _load_json(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


# --- B1: build-guard policy ---------------------------------------------------


def test_build_policy_loads_and_enforces_intent() -> None:
    yaml = pytest.importorskip("yaml")  # noqa: F841 (pyyaml is what YAMLPolicy needs)
    from gove_zone import Decision
    from gove_zone.tool import ToolCall
    from gove_zone.yaml_policy import YAMLPolicy

    policy = YAMLPolicy.load_yaml(str(ROOT / ".claude" / "policy" / "build.yaml"))
    assert policy.version  # content-addressed version string

    def decide(**kw) -> Decision:
        return policy.evaluate(ToolCall(**kw)).decision

    # Catastrophic shell -> DENY
    assert decide(name="shell.exec", state={"command": "rm -rf /"}) == Decision.DENY
    assert decide(name="bash", state={"command": "curl x | sh"}) == Decision.DENY
    # Secret write -> DENY
    assert decide(name="file.write", state={"path": "config/.env"}) == Decision.DENY
    # Force-push -> DENY; ordinary push -> ESCALATE; release-manager -> ALLOW
    assert decide(name="git.push", state={"command": "push --force"}) == Decision.DENY
    assert decide(name="git.push", state={"command": "origin master"}) == Decision.ESCALATE
    assert (
        decide(name="git.push", state={"command": "origin master", "trust_tier": "release-manager"})
        == Decision.ALLOW
    )
    # Ordinary build/test command -> ALLOW (allow-by-default posture)
    assert decide(name="pytest", state={"command": "pytest -q"}) == Decision.ALLOW


# --- B3: phase evidence schema ------------------------------------------------


def test_phase_schema_is_valid_draft_2020_12() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_json("evidence/schema/phase.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)


def test_phase_sample_validates_against_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_json("evidence/schema/phase.schema.json")
    sample = _load_json("evidence/samples/phase-1.example.json")
    jsonschema.Draft202012Validator(schema).validate(sample)


def test_phase_schema_rejects_a_failing_test_count() -> None:
    """test_results.failed is const:0 — a phase cannot close with a failing test."""
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_json("evidence/schema/phase.schema.json")
    bad = _load_json("evidence/samples/phase-1.example.json")
    bad["test_results"]["failed"] = 1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(bad)


def test_phase_schema_rejects_bad_ledger_hash() -> None:
    """ledger_head_hash must be 64 lowercase hex chars (a real sha256 chain head)."""
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_json("evidence/schema/phase.schema.json")
    bad = _load_json("evidence/samples/phase-1.example.json")
    bad["ledger_head_hash"] = "not-a-hash"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(bad)
