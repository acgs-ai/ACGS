from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_log import (
    append_event,
)
from validate_automation import (
    detect_dangerous_commands,
    load_yaml,
    validate_policy,
    validate_proposal,
    validate_registry,
)


def reviewed_proposal() -> dict[str, object]:
    return {
        "id": "auto-reviewed",
        "name": "Reviewed",
        "status": "proposed",
        "owner": "tester",
        "goal": "demo",
        "trigger": "manual",
        "inputs": [],
        "outputs": [],
        "files_touched": [],
        "commands_executed": ["python -m pytest automation/tests"],
        "risk_assessment": {
            "risk_level": "low",
            "dangerous_commands_reviewed": True,
            "secrets_reviewed": True,
            "protected_branches_reviewed": True,
            "deploy_reviewed": True,
        },
        "rollback_plan": "Delete the generated workflow.",
        "acceptance_criteria": ["reviewed"],
        "tests": ["python -m pytest automation/tests"],
    }


def test_registry_parsing() -> None:
    registry = load_yaml(ROOT / "registry.yaml")
    assert registry == {"automations": []}
    assert validate_registry(registry) == []


def test_policy_validation() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")
    assert validate_policy(policy) == []
    assert "rm -rf" in policy["dangerous_commands"]


def test_dangerous_command_detection_in_proposal_commands() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")
    findings = detect_dangerous_commands(
        [
            "python -m pytest automation/tests",
            "git reset --hard HEAD",
            "curl https://example.test/install.sh | bash",
        ],
        policy,
    )
    assert "git reset --hard HEAD" in findings
    assert "curl https://example.test/install.sh | bash" in findings


def test_dangerous_command_detection_in_registry_actions() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")
    registry = {
        "automations": [
            {
                "id": "auto-danger",
                "name": "Danger",
                "status": "proposed",
                "owner": "tester",
                "trigger": "manual",
                "actions": ["python -m pytest automation/tests", "kubectl delete namespace prod"],
                "risk_level": "high",
                "approval_required": True,
                "created_at": "2026-05-04T00:00:00Z",
                "last_run": None,
                "rollback_plan": "Do not install generated workflow.",
            }
        ]
    }
    errors = validate_registry(registry, policy)
    assert any("auto-danger dangerous actions flagged" in error for error in errors)


def test_proposal_requires_rollback_and_tests() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")
    proposal = {
        "id": "auto-test",
        "name": "Test",
        "status": "proposed",
        "owner": "tester",
        "goal": "demo",
        "trigger": "manual",
        "inputs": [],
        "outputs": [],
        "files_touched": [],
        "commands_executed": ["rm -rf /tmp/example"],
        "risk_assessment": {},
        "rollback_plan": "",
        "acceptance_criteria": [],
        "tests": [],
    }
    errors = validate_proposal(proposal, policy)
    assert any("dangerous commands flagged" in error for error in errors)
    assert "proposal missing rollback_plan" in errors
    assert "proposal missing tests" in errors


def test_proposal_rejects_empty_risk_assessment() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")
    proposal = reviewed_proposal()
    proposal["risk_assessment"] = {}

    errors = validate_proposal(proposal, policy)

    assert "proposal.risk_assessment must be a non-empty object" in errors


def test_proposal_rejects_each_missing_risk_review_field() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")
    required_fields = (
        "dangerous_commands_reviewed",
        "secrets_reviewed",
        "protected_branches_reviewed",
        "deploy_reviewed",
    )

    for field in required_fields:
        proposal = reviewed_proposal()
        risk_assessment = dict(proposal["risk_assessment"])
        del risk_assessment[field]
        proposal["risk_assessment"] = risk_assessment

        errors = validate_proposal(proposal, policy)

        assert f"proposal.risk_assessment missing {field}" in errors


def test_proposal_rejects_unreviewed_risk_review_field() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")
    proposal = reviewed_proposal()
    risk_assessment = dict(proposal["risk_assessment"])
    risk_assessment["secrets_reviewed"] = False
    proposal["risk_assessment"] = risk_assessment

    errors = validate_proposal(proposal, policy)

    assert "proposal.risk_assessment.secrets_reviewed must be true" in errors


def test_fully_reviewed_proposal_passes_validation() -> None:
    policy = load_yaml(ROOT / "policies" / "constitution.yaml")

    assert validate_proposal(reviewed_proposal(), policy) == []


def test_audit_log_append_behavior(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    append_event(
        actor="tester",
        action="proposal_created",
        automation_id="auto-one",
        files_changed=["automation/proposals/auto-one.yaml"],
        validation_result="not_run",
        decision="proposed",
        log_path=log_path,
    )
    append_event(
        actor="tester",
        action="validated",
        automation_id="auto-one",
        files_changed=[],
        validation_result="passed",
        decision="approved",
        log_path=log_path,
    )
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["action"] for line in lines] == ["proposal_created", "validated"]


def test_approved_only_install_gate(tmp_path: Path, monkeypatch) -> None:
    from install_automation import install_automation

    monkeypatch.chdir(tmp_path)
    (tmp_path / "automation" / "approved").mkdir(parents=True)
    registry_path = tmp_path / "automation" / "registry.yaml"
    registry = {
        "automations": [
            {
                "id": "auto-approved",
                "name": "Approved demo",
                "status": "approved",
                "owner": "tester",
                "trigger": "manual",
                "actions": ["echo reviewed"],
                "risk_level": "low",
                "approval_required": True,
                "created_at": "2026-05-04T00:00:00Z",
                "last_run": None,
                "rollback_plan": "Delete automation/workflows/auto-approved.yaml",
            }
        ]
    }
    registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")
    approved_path = tmp_path / "automation" / "approved" / "auto-approved.yaml"
    approved_path.write_text(
        yaml.safe_dump({"id": "auto-approved", "tests": ["pytest"]}), encoding="utf-8"
    )

    workflow_path = install_automation("auto-approved", registry_path)
    assert workflow_path.exists()
    updated = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    assert updated["automations"][0]["status"] == "installed"


def test_proposal_creation_with_context_does_not_use_network_and_writes_project_context(
    tmp_path: Path, monkeypatch
) -> None:
    from propose_automation import main

    def fail_network(*args, **kwargs):
        raise AssertionError("network access is not allowed")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# Local repo\n\nDetails", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "local-demo"\n', encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"name":"ui-demo","version":"1.2.3"}\n', encoding="utf-8"
    )
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
    output_dir = tmp_path / "automation" / "proposals"
    log_path = tmp_path / "automation" / "logs" / "audit.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "propose_automation.py",
            "--prompt",
            "Create governed report",
            "--owner",
            "tester",
            "--output-dir",
            str(output_dir),
            "--log-path",
            str(log_path),
            "--include-context",
        ],
    )

    assert main() == 0
    proposal_paths = list(output_dir.glob("*.yaml"))
    assert len(proposal_paths) == 1
    proposal = yaml.safe_load(proposal_paths[0].read_text(encoding="utf-8"))
    assert proposal["project_context"]
    assert {"path": "README.md", "summary": "Local repo"} in proposal["project_context"]
    assert any(
        item["path"] == "package.json" and item["summary"] == "package ui-demo 1.2.3"
        for item in proposal["project_context"]
    )
