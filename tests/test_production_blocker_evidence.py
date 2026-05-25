"""Tests for scripts/build_production_blocker_evidence.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_production_blocker_evidence.py"
FORBIDDEN_MUTATING_INVOCATIONS = (
    ("gcloud", "run", "deploy"),
    ("wrangler",),
    ("vercel", "deploy"),
    ("gh", "secret"),
    ("kubectl",),
    ("terraform", "apply"),
)


def _dry_run(*args: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dry-run", "--json", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_dry_run_plan_is_claim_safe_and_does_not_execute_live_checks():
    payload = _dry_run()

    assert payload["artifactKind"] == "production-blocker-evidence-plan"
    assert payload["status"] == "dry-run"
    assert "not live production proof" in payload["claimBoundary"]
    assert "does not deploy" in payload["claimBoundary"]
    assert payload["outputs"]["preflight"] == (
        "dist-release-evidence/production-launch-preflight.json"
    )

    commands = {entry["id"]: entry for entry in payload["commands"]}
    assert list(commands) == [
        "build-buyer-evidence-gallery",
        "run-production-live-verifier",
        "build-production-blocker-report",
        "build-production-cutover-plan",
        "build-hosted-storybook-handoff",
        "build-production-evidence-draft-when-live-fails",
        "validate-deployment-blocked-production-evidence-when-live-fails",
        "refresh-release-evidence-bundle",
        "write-production-launch-preflight-json",
    ]
    assert commands["build-buyer-evidence-gallery"]["env"] == {
        "ACGI_EVIDENCE_CNAME": "storybook.acgs.ai"
    }
    assert commands["run-production-live-verifier"]["continueOnNonzeroWithOutput"] == (
        "dist-release-evidence/production-live-verification.json"
    )
    assert "--out" in commands["run-production-live-verifier"]["cmd"]
    live_out_index = commands["run-production-live-verifier"]["cmd"].index("--out")
    assert (
        commands["run-production-live-verifier"]["cmd"][live_out_index + 1]
        == "../dist-release-evidence/production-live-verification.json"
    )
    assert "verify:production-live" in " ".join(commands["run-production-live-verifier"]["cmd"])
    assert "build:production-evidence-draft" in " ".join(
        commands["build-production-evidence-draft-when-live-fails"]["cmd"]
    )
    assert "validate:production-evidence" in " ".join(
        commands["validate-deployment-blocked-production-evidence-when-live-fails"]["cmd"]
    )


def test_dry_run_plan_excludes_deploy_dns_secret_and_infra_mutations():
    payload = _dry_run()

    for entry in payload["commands"]:
        tokens = [str(token) for token in entry["cmd"]]
        for forbidden in FORBIDDEN_MUTATING_INVOCATIONS:
            for start in range(len(tokens) - len(forbidden) + 1):
                assert tuple(tokens[start : start + len(forbidden)]) != forbidden, (
                    f"{entry['id']} includes forbidden mutating invocation {forbidden}: "
                    f"{entry['cmd']}"
                )


def test_dry_run_with_supplied_live_output_copies_instead_of_running_network_verifier():
    payload = _dry_run("--live-output", "tmp-live-output.json")
    command_ids = [entry["id"] for entry in payload["commands"]]

    assert "copy-supplied-live-output" in command_ids
    assert "run-production-live-verifier" not in command_ids
    copy_command = next(
        entry for entry in payload["commands"] if entry["id"] == "copy-supplied-live-output"
    )
    assert "--internal-copy-live-output" in copy_command["cmd"]
    assert copy_command["cmd"][-1].endswith(
        "dist-release-evidence/production-live-verification.json"
    )


def test_internal_copy_live_output_canonicalizes_wrapper_captured_json(tmp_path: Path):
    source = tmp_path / "pnpm-captured-live-output.txt"
    destination = tmp_path / "production-live-verification.json"
    source.write_text(
        ". | WARN Unsupported engine: wanted node>=24\n"
        "{\n"
        '  "schemaVersion": 1,\n'
        '  "artifactKind": "production-live-verification",\n'
        '  "generatedAt": "2026-05-25T16:45:50.037Z",\n'
        '  "status": "fail",\n'
        '  "blockers": [{"blockerId": "live-console-dns"}],\n'
        '  "checks": []\n'
        "}\n"
        "ERR_PNPM_RECURSIVE_RUN_FIRST_FAIL Exit status 1\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--internal-copy-live-output",
            str(source),
            str(destination),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    copied = json.loads(destination.read_text(encoding="utf-8"))
    assert copied["artifactKind"] == "production-live-verification"
    assert copied["status"] == "fail"
    assert copied["blockers"] == [{"blockerId": "live-console-dns"}]
    assert destination.read_text(encoding="utf-8").lstrip().startswith("{")
    assert "WARN Unsupported engine" not in destination.read_text(encoding="utf-8")


def test_internal_copy_live_output_rejects_ambiguous_wrapper_captured_json(tmp_path: Path):
    first = {
        "schemaVersion": 1,
        "artifactKind": "production-live-verification",
        "status": "fail",
    }
    source = tmp_path / "ambiguous-live-output.txt"
    destination = tmp_path / "production-live-verification.json"
    source.write_text(
        f"prefix {json.dumps(first)} middle {json.dumps(first)} suffix",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--internal-copy-live-output",
            str(source),
            str(destination),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "found 2 production-live-verification artifacts" in result.stderr
    assert not destination.exists()
