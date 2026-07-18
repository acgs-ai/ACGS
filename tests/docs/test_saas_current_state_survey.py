"""Regression guards for the bounded G006 current-state reconciliation record.

The survey is deliberately a portable, credential-free summary. These checks
make it difficult to silently promote frozen local observations into deployment
or production claims, or to leak machine-local or request material into the
program record.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SURVEY_PATH = ROOT / "docs" / "saas" / "CURRENT_STATE_SURVEY.md"
SNAPSHOT_PATH = ROOT / "evidence" / "saas" / "g006" / "current-state-survey.json"
DAG_PATH = ROOT / "docs" / "saas" / "DELIVERY_DAG.yaml"
MATRIX_PATH = ROOT / "docs" / "saas" / "ACCEPTANCE_MATRIX.md"

BASELINE_COMMIT = "1d9c9b21372ebdbd20aefc3ca454a47a3d5d1f96"
PARENT_PROGRAM_RECORD = "b2aa0c928b6ba21baa8e4a123452eebeeda3e050"
OBSERVED_PARENT_HEAD = "e4af0731aece89c1b7bcc050b609260571497145"
OBSERVED_AT = "2026-07-13T09:59:25Z"
PARENT_PROGRAM_RECORD_DRIFT = (
    "Survey work started from the parent commit; the parent ref advanced with a test-only "
    "hardening commit. Rebase onto the observed parent head before publication."
)
BASELINE_SCOPE = (
    "Source, tests, tracked documentation, and forge metadata observed at the frozen baseline."
)
HYPOTHESIS_KEYS = {"id", "status", "finding", "evidence_class", "source_refs", "next_validation"}
REQUIRED_HYPOTHESES = {
    "H-RUNTIME-CANONICAL-001",
    "H-CP-LEGACY-002",
    "H-CP-AUDIT-SCALING-003",
    "H-CP-AUDIT-ATOMICITY-004",
    "H-CP-EXPORT-PROVENANCE-005",
    "H-POLICY-ACTIVATION-RACE-006",
    "H-CP-FOUNDATION-007",
    "H-EVIDENCE-INGESTION-008",
    "H-CONSOLE-CONTRACT-009",
    "H-FORGE-STATE-010",
    "H-VALIDATION-011",
}
REQUIRED_CAPABILITIES = {
    "CM-RUNTIME",
    "CM-CONTROL-PLANE",
    "CM-EVIDENCE",
    "CM-CONSOLE",
    "CM-OPERATIONS",
}
REQUIRED_VALIDATIONS = {"NV-001", "NV-002", "NV-003", "NV-004", "NV-005"}


def _snapshot() -> dict[str, Any]:
    payload = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_snapshot_schema_baseline_and_evidence_boundary() -> None:
    snapshot = _snapshot()
    assert set(snapshot) == {
        "schema_version",
        "survey_id",
        "baseline",
        "capture_boundary",
        "source_paths",
        "source_ref_provenance",
        "hypotheses",
        "capability_matrix",
        "forge_snapshot",
        "validation_snapshot",
        "next_validations",
        "conclusion",
    }
    assert snapshot["schema_version"] == "1.0"
    assert snapshot["survey_id"] == "G006-current-state-survey"
    assert snapshot["baseline"] == {
        "source_ref": "origin/master",
        "commit": BASELINE_COMMIT,
        "program_record_parent_commit": PARENT_PROGRAM_RECORD,
        "program_record_parent_ref": "beta/p0-program-record-005",
        "program_record_parent_observed_head": OBSERVED_PARENT_HEAD,
        "program_record_parent_drift": PARENT_PROGRAM_RECORD_DRIFT,
        "observed_at": OBSERVED_AT,
        "scope": BASELINE_SCOPE,
    }
    boundary = snapshot["capture_boundary"]
    assert boundary["mode"] == "summaries only"
    assert set(boundary["not_proof_of"]) == {
        "deployment",
        "customer use",
        "independent assessment",
        "certification",
        "production readiness",
    }
    assert set(boundary["excluded_content"]) == {
        "credential material",
        "request payloads",
        "machine-local paths",
        "raw command output",
    }
    assert "rebase" in snapshot["baseline"]["program_record_parent_drift"].lower()


def test_hypotheses_cover_required_ids_and_all_dispositions() -> None:
    hypotheses = _snapshot()["hypotheses"]
    assert isinstance(hypotheses, list) and hypotheses
    by_id = {item["id"]: item for item in hypotheses}
    assert set(by_id) == REQUIRED_HYPOTHESES
    assert {item["status"] for item in hypotheses} == {
        "confirmed",
        "contradicted",
        "unverified",
    }
    for item in hypotheses:
        assert set(item) == HYPOTHESIS_KEYS
        assert item["status"] in {"confirmed", "contradicted", "unverified"}
        assert item["finding"].strip()
        assert item["evidence_class"].strip()
        assert isinstance(item["source_refs"], list) and item["source_refs"]
        assert item["next_validation"].strip()
    assert by_id["H-EVIDENCE-INGESTION-008"]["status"] == "contradicted"
    assert "local and mcp approval-resume" in by_id["H-EVIDENCE-INGESTION-008"]["finding"].lower()
    assert (
        "managed control-plane approval/resume api"
        in by_id["H-EVIDENCE-INGESTION-008"]["finding"].lower()
    )
    assert (
        "when a consumption ledger is configured"
        in by_id["H-RUNTIME-CANONICAL-001"]["finding"].lower()
    )
    assert by_id["H-CP-AUDIT-ATOMICITY-004"]["status"] == "unverified"
    assert by_id["H-POLICY-ACTIVATION-RACE-006"]["status"] == "unverified"


def test_matrix_is_bounded_and_references_known_hypotheses() -> None:
    snapshot = _snapshot()
    hypotheses = {item["id"] for item in snapshot["hypotheses"]}
    matrix = snapshot["capability_matrix"]
    assert {item["id"] for item in matrix} == REQUIRED_CAPABILITIES
    assert {item["state"] for item in matrix} == {"partial", "missing", "conflicting"}
    for item in matrix:
        assert set(item) == {"id", "plane", "state", "finding", "evidence_hypotheses"}
        assert item["state"] in {"built", "partial", "missing", "conflicting"}
        assert item["state"] != "built"
        assert item["finding"].strip()
        assert set(item["evidence_hypotheses"]) <= hypotheses
    assert next(item for item in matrix if item["id"] == "CM-EVIDENCE")["state"] == "missing"
    assert next(item for item in matrix if item["id"] == "CM-CONSOLE")["state"] == "conflicting"


def test_forge_release_and_validation_snapshot_are_conservative() -> None:
    snapshot = _snapshot()
    forge = snapshot["forge_snapshot"]
    prs = {item["number"]: item for item in forge["pull_requests"]}
    assert prs[317] == {
        "number": 317,
        "state": "open",
        "draft": True,
        "merged": False,
        "disposition": "overlapping draft; not accepted baseline evidence",
    }
    assert prs[308]["state"] == "open" and prs[308]["merged"] is False
    assert prs[267]["state"] == "closed" and prs[267]["merged"] is False
    assert {item["number"]: item["state"] for item in forge["issues"]} == {167: "open", 168: "open"}
    assert forge["release"] == {"version_label": "v0.1.0a1", "published_release_observed": False}
    assert forge["deployment_evidence"] == "Metadata observed; not proof of deployment."

    validations = {item["id"]: item for item in snapshot["validation_snapshot"]}
    assert set(validations) == {"V-CP-TESTS", "V-CONSOLE-AUTH-BOUNDARY", "V-GOVE-ZONE-BROAD"}
    assert validations["V-CP-TESTS"]["state"] == "pass_with_warning"
    assert validations["V-CONSOLE-AUTH-BOUNDARY"]["state"] == "partial"
    assert validations["V-GOVE-ZONE-BROAD"]["state"] == "environment_blocked"
    assert "No rerun was performed." in validations["V-GOVE-ZONE-BROAD"]["summary"]
    expected_validation_keys = {
        "id",
        "state",
        "command",
        "exit_code",
        "tool_or_environment",
        "summary",
        "warning_classification",
        "raw_output_published",
        "raw_output_retained",
        "summary_sha256",
    }
    for validation in validations.values():
        assert set(validation) == expected_validation_keys
        assert validation["command"].strip()
        assert isinstance(validation["exit_code"], int)
        assert validation["tool_or_environment"].strip()
        assert validation["warning_classification"].strip()
        assert validation["raw_output_published"] is False
        assert validation["raw_output_retained"] is False
        assert re.fullmatch(r"[0-9a-f]{64}", validation["summary_sha256"])
    assert {item["id"] for item in snapshot["next_validations"]} == REQUIRED_VALIDATIONS


def test_paths_are_portable_and_capture_is_sanitized() -> None:
    snapshot = _snapshot()
    for path in snapshot["source_paths"]:
        parsed = PurePosixPath(path)
        assert not parsed.is_absolute()
        assert ".." not in parsed.parts
        assert not path.startswith("~")
    for hypothesis in snapshot["hypotheses"]:
        for path in hypothesis["source_refs"]:
            parsed = PurePosixPath(path)
            assert not parsed.is_absolute()
            assert ".." not in parsed.parts
            assert not path.startswith("~")

    provenance = snapshot["source_ref_provenance"]
    cited_paths = set(snapshot["source_paths"]) | {
        path for hypothesis in snapshot["hypotheses"] for path in hypothesis["source_refs"]
    }
    assert cited_paths <= set(provenance)
    for path in cited_paths:
        record = provenance[path]
        assert set(record) == {"source_ref_commit", "context"}
        assert re.fullmatch(r"[0-9a-f]{40}", record["source_ref_commit"])
        assert record["context"] in {"frozen_source_baseline", "program_record_parent"}
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{record['source_ref_commit']}:{path}"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"missing frozen source: {path}"
    assert "packages/gove-zone/src/gove_zone/audit.py" in provenance

    text = "\n".join(
        [
            SURVEY_PATH.read_text(encoding="utf-8"),
            SNAPSHOT_PATH.read_text(encoding="utf-8"),
        ]
    ).lower()
    for forbidden in (
        "/home/",
        "http://",
        "https://",
        "authorization:",
        "bearer ",
        "x-api-key:",
    ):
        assert forbidden not in text
    assert "credential material" in text
    assert "request payloads" in text
    assert "machine-local paths" in text
    assert "raw command output" in text
    assert "raw command output is neither retained nor published" in text


def test_markdown_is_a_readable_projection_of_the_snapshot() -> None:
    markdown = SURVEY_PATH.read_text(encoding="utf-8")
    assert "# Frozen Current-State Survey" in markdown
    assert BASELINE_COMMIT in markdown
    assert OBSERVED_AT in markdown
    assert "../../evidence/saas/g006/current-state-survey.json" in markdown
    assert "not deployment, customer-use, independent-assessment," in markdown
    assert "certification, or production-readiness evidence" in markdown
    for hypothesis_id in REQUIRED_HYPOTHESES:
        assert hypothesis_id in markdown
    assert "**25 passed with one warning**" in markdown
    assert "**Node 22**" in markdown and "**Node 24**" in markdown
    assert "single-use is enforced when a consumption ledger is configured" in markdown
    assert "Local/MCP approval-resume exists" in markdown
    assert "Raw command output is neither retained nor published." in markdown
    assert "No hypothesis in this survey upgrades public claims." in markdown


def test_dag_completion_preserves_partial_product_contract_boundary() -> None:
    dag = json.loads(DAG_PATH.read_text(encoding="utf-8"))
    g006 = next(item for item in dag["nodes"] if item["id"] == "G006")
    assert (g006["status"], g006["implementation_state"], g006["evidence_state"]) == (
        "completed",
        "built",
        "independently_reviewed",
    )
    assert {
        "docs/saas/CURRENT_STATE_SURVEY.md",
        "evidence/saas/g006/current-state-survey.json",
        "tests/docs/test_saas_current_state_survey.py",
    } <= set(g006["likely_interfaces_files"])
    assert g006["blocker"] is None
    assert "g007/g008" in g006["next_safe_action"].lower()
    assert "current-state-survey.json" in g006["evidence_artifact"]

    matrix = MATRIX_PATH.read_text(encoding="utf-8")
    match = re.search(
        r"^\| AM-002 \| (.*?) \| (.*?) \| (.*?) \| (.*?) \| (.*?) \|$",
        matrix,
        re.MULTILINE,
    )
    assert match
    criterion, state, evidence, refs, artifact = match.groups()
    assert criterion == "Frozen current-state and product-contract reconciliation"
    assert state == "partial"
    assert evidence == "current_local"
    assert refs == "G006, G007, G008"
    assert "CURRENT_STATE_SURVEY.md" in artifact
    assert "independently reviewed" in artifact
    assert "not an accepted product-contract decision" in artifact
