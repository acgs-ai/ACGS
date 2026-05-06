#!/usr/bin/env python3
"""Validate automation registry, policies, and optional proposals."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml


REGISTRY_REQUIRED_FIELDS = {
    "id",
    "name",
    "status",
    "owner",
    "trigger",
    "actions",
    "risk_level",
    "approval_required",
    "created_at",
    "last_run",
    "rollback_plan",
}
VALID_STATUSES = {"proposed", "approved", "installed", "disabled", "rejected"}
PROPOSAL_REQUIRED_FIELDS = {
    "id",
    "name",
    "status",
    "owner",
    "goal",
    "trigger",
    "inputs",
    "outputs",
    "files_touched",
    "commands_executed",
    "risk_assessment",
    "rollback_plan",
    "acceptance_criteria",
    "tests",
}
DEFAULT_DANGEROUS_COMMANDS = [
    "rm -rf",
    "sudo",
    "chmod 777",
    "curl | bash",
    "wget | bash",
    "git push --force",
    "git reset --hard",
    "docker system prune",
    "kubectl delete",
    "terraform destroy",
]
REQUIRED_RISK_REVIEW_FIELDS = (
    "dangerous_commands_reviewed",
    "secrets_reviewed",
    "protected_branches_reviewed",
    "deploy_reviewed",
)


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return data if data is not None else {}


def dangerous_patterns(policy: dict[str, Any]) -> list[re.Pattern[str]]:
    patterns = []
    for command in policy.get("dangerous_commands", DEFAULT_DANGEROUS_COMMANDS):
        command_text = str(command)
        if command_text == "curl | bash":
            patterns.append(re.compile(r"\bcurl\b.*\|\s*bash\b", re.IGNORECASE))
            continue
        if command_text == "wget | bash":
            patterns.append(re.compile(r"\bwget\b.*\|\s*bash\b", re.IGNORECASE))
            continue
        escaped = re.escape(command_text).replace(r"\ ", r"\s+")
        patterns.append(re.compile(escaped, re.IGNORECASE))
    return patterns


def detect_dangerous_commands(commands: list[str], policy: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    patterns = dangerous_patterns(policy)
    for command in commands:
        for pattern in patterns:
            if pattern.search(command):
                findings.append(command)
                break
    return findings


def validate_registry(registry: dict[str, Any], policy: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    automations = registry.get("automations")
    if not isinstance(automations, list):
        return ["registry.automations must be a list"]

    seen: set[str] = set()
    for index, automation in enumerate(automations):
        if not isinstance(automation, dict):
            errors.append(f"registry.automations[{index}] must be an object")
            continue
        missing = sorted(REGISTRY_REQUIRED_FIELDS - set(automation))
        if missing:
            errors.append(f"{automation.get('id', index)} missing fields: {', '.join(missing)}")
        automation_id = str(automation.get("id", ""))
        if automation_id in seen:
            errors.append(f"duplicate automation id: {automation_id}")
        seen.add(automation_id)
        if automation.get("status") not in VALID_STATUSES:
            errors.append(f"{automation_id} has invalid status: {automation.get('status')}")
        if not automation.get("rollback_plan"):
            errors.append(f"{automation_id} missing rollback_plan")
        actions = automation.get("actions", [])
        if not isinstance(actions, list):
            errors.append(f"{automation_id} actions must be a list")
            actions = []
        dangerous = detect_dangerous_commands([str(action) for action in actions], policy or {})
        if dangerous:
            errors.append(f"{automation_id} dangerous actions flagged: {', '.join(dangerous)}")
    return errors


def validate_policy(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in ("hard_rules", "dangerous_commands", "defaults"):
        if key not in policy:
            errors.append(f"policy missing {key}")
    defaults = policy.get("defaults", {})
    for key in ("network_calls", "background_daemon", "secret_access", "auto_merge", "auto_deploy"):
        if defaults.get(key) != "disabled":
            errors.append(f"policy default {key} must be disabled")
    return errors


def validate_proposal(proposal: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(PROPOSAL_REQUIRED_FIELDS - set(proposal))
    if missing:
        errors.append(f"proposal missing fields: {', '.join(missing)}")

    commands = proposal.get("commands_executed", [])
    if not isinstance(commands, list):
        errors.append("proposal.commands_executed must be a list")
        commands = []
    dangerous = detect_dangerous_commands([str(command) for command in commands], policy)
    if dangerous:
        errors.append(f"dangerous commands flagged: {', '.join(dangerous)}")
    risk_assessment = proposal.get("risk_assessment")
    if not isinstance(risk_assessment, dict) or not risk_assessment:
        errors.append("proposal.risk_assessment must be a non-empty object")
        risk_assessment = {}
    for field in REQUIRED_RISK_REVIEW_FIELDS:
        if field not in risk_assessment:
            errors.append(f"proposal.risk_assessment missing {field}")
        elif risk_assessment[field] is not True:
            errors.append(f"proposal.risk_assessment.{field} must be true")
    if not proposal.get("rollback_plan"):
        errors.append("proposal missing rollback_plan")
    if not proposal.get("tests"):
        errors.append("proposal missing tests")
    if not proposal.get("acceptance_criteria"):
        errors.append("proposal missing acceptance_criteria")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate automation registry, policy, and proposal files.")
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--proposal", type=Path)
    args = parser.parse_args()

    registry = load_yaml(args.registry)
    policy = load_yaml(args.policy)
    errors = validate_policy(policy) + validate_registry(registry, policy)
    proposal_result = None
    if args.proposal:
        proposal = load_yaml(args.proposal)
        proposal_errors = validate_proposal(proposal, policy)
        errors.extend(proposal_errors)
        proposal_result = {"path": str(args.proposal), "errors": proposal_errors}

    result = {
        "ok": not errors,
        "registry": str(args.registry),
        "policy": str(args.policy),
        "proposal": proposal_result,
        "errors": errors,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
