"""Schema + decision tests for Admission Gate v0.1."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from governance.admission import (
    SCHEMA_VERSION,
    decide,
    load_policy_bundle,
    verify_decision,
)
from governance.admission.policy import policy_bundle_from_dict

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "admission_gate_v0_1"
SCHEMA_DIR = REPO_ROOT / "governance" / "schema"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DECISIONS = ("allow", "deny", "transform", "require_review")


# ---------------------------------------------------------------------------
# schema sanity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "admission_request.schema.json",
        "admission_decision.schema.json",
        "decision_receipt.schema.json",
    ],
)
def test_schema_files_are_valid_json(name: str) -> None:
    body = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    assert body["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert body["$id"].endswith(f"/{name}")


def test_decision_schema_enumerates_all_four_actions() -> None:
    body = json.loads((SCHEMA_DIR / "admission_decision.schema.json").read_text(encoding="utf-8"))
    assert set(body["properties"]["decision"]["enum"]) == set(_DECISIONS)


# ---------------------------------------------------------------------------
# fixtures decode + decide
# ---------------------------------------------------------------------------


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture()
def bundle():
    return load_policy_bundle(FIXTURES / "policy_bundle.json")


@pytest.mark.parametrize(
    "fixture, expected",
    [
        ("allow_request.json", "allow"),
        ("deny_request.json", "deny"),
        ("transform_request.json", "transform"),
        ("require_review_request.json", "require_review"),
    ],
)
def test_decide_produces_expected_action(fixture, expected, bundle) -> None:
    req = _load_fixture(fixture)
    dec = decide(req, policy_bundle=bundle)
    assert dec["decision"] == expected, dec
    _assert_decision_shape(dec, req, bundle)


def _assert_decision_shape(dec, req, bundle) -> None:
    assert dec["schema_version"] == SCHEMA_VERSION
    assert dec["request_id"] == req["request_id"]
    assert dec["decision_id"].startswith("dec_")
    assert dec["policy_version"] == bundle.version
    rcpt = dec["receipt"]
    assert rcpt["receipt_id"].startswith("rcpt_")
    assert rcpt["hash_alg"] == "sha256"
    for h in ("request_hash", "decision_hash", "policy_bundle_hash"):
        assert _HEX64.match(rcpt[h]), (h, rcpt[h])
    # round-trip
    report = verify_decision(request=req, decision=dec, policy_bundle=bundle)
    assert report["ok"] is True


def test_transform_decision_has_transformed_boundary(bundle) -> None:
    req = _load_fixture("transform_request.json")
    dec = decide(req, policy_bundle=bundle)
    tb = dec["transform"]["transformed_boundary"]
    assert dec["transform"]["applied"] is True
    assert tb is not None
    assert "internal_draft" in tb["allowed_outputs"]
    assert "client_facing_legal_advice" in tb["disallowed_outputs"]


def test_require_review_decision_has_reviewer_role(bundle) -> None:
    req = _load_fixture("require_review_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["review"]["required"] is True
    assert dec["review"]["reviewer_role"] == "licensed_lawyer"


def test_deny_decision_blocks_all_capabilities(bundle) -> None:
    req = _load_fixture("deny_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["execution_boundary"]["effective_permissions"] == []
    assert set(dec["execution_boundary"]["blocked_capabilities"]) == set(req["requested_capabilities"])


# ---------------------------------------------------------------------------
# fail-closed: mismatched bundle id
# ---------------------------------------------------------------------------


def test_mismatched_bundle_id_denies(bundle) -> None:
    req = _load_fixture("allow_request.json")
    rogue = policy_bundle_from_dict(
        {
            "bundle_id": "OTHER_BUNDLE",
            "version": "9.9.9",
            "rules": [],
        }
    )
    dec = decide(req, policy_bundle=rogue)
    assert dec["decision"] == "deny"
    assert dec["reason_code"] == "policy_violation"


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------


def _run_cli(args, cwd=REPO_ROOT):
    return subprocess.run(
        [sys.executable, "-m", "governance.admission.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "fixture, decision, exit_code",
    [
        ("allow_request.json", "allow", 0),
        ("deny_request.json", "deny", 10),
        ("transform_request.json", "transform", 11),
        ("require_review_request.json", "require_review", 12),
    ],
)
def test_cli_decide_exit_codes(tmp_path, fixture, decision, exit_code) -> None:
    out = tmp_path / "decision.json"
    res = _run_cli(
        [
            "decide",
            "--request",
            str(FIXTURES / fixture),
            "--policy",
            str(FIXTURES / "policy_bundle.json"),
            "--out",
            str(out),
            "--quiet",
        ]
    )
    assert res.returncode == exit_code, res.stderr
    body = json.loads(out.read_text())
    assert body["decision"] == decision


def test_cli_verify_passes_on_clean_decision(tmp_path) -> None:
    out = tmp_path / "decision.json"
    _run_cli(
        [
            "decide",
            "--request",
            str(FIXTURES / "allow_request.json"),
            "--policy",
            str(FIXTURES / "policy_bundle.json"),
            "--out",
            str(out),
            "--quiet",
        ]
    )
    res = _run_cli(
        [
            "verify",
            "--request",
            str(FIXTURES / "allow_request.json"),
            "--decision",
            str(out),
            "--policy",
            str(FIXTURES / "policy_bundle.json"),
        ]
    )
    assert res.returncode == 0, res.stderr
