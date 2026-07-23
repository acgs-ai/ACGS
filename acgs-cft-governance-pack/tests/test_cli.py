from __future__ import annotations

import json
from pathlib import Path

import pytest

from acgs_cft_governance_pack.cli import main

ROOT = Path(__file__).resolve().parents[1]
CLI_SOURCE = ROOT / "acgs_cft_governance_pack" / "cli.py"


def test_cli_imports_stable_package_facade() -> None:
    source = CLI_SOURCE.read_text(encoding="utf-8")

    assert "from acgs_cft_governance_pack import evaluate_plan, load_policies, write_evidence_jsonl" in source
    assert "from acgs_cft_governance_pack.evaluator import" not in source


def test_cli_denied_plan_exits_two_and_writes_evidence(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "denied.jsonl"

    exit_code = main(
        [
            "evaluate",
            "--plan",
            str(ROOT / "examples/network-firewall-policy/terraform-plan.denied.json"),
            "--policy-dir",
            str(ROOT / "policies"),
            "--actor",
            "platform-ci",
            "--role",
            "validator",
            "--tenant",
            "cft",
            "--out",
            str(output),
        ],
    )

    captured = capsys.readouterr()
    lines = output.read_text(encoding="utf-8").splitlines()
    evidence = json.loads(lines[0])

    assert exit_code == 2
    assert "DENY: Denied by" in captured.err
    assert len(lines) == 1
    assert evidence["decision"] == "deny"
    assert evidence["tenant"] == "cft"
    assert evidence["plan_hash"].startswith("sha256:")
    assert evidence["merkle_root"].startswith("sha256:")
