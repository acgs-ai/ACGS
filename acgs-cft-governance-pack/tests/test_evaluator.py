from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from acgs_cft_governance_pack.evaluator import evaluate_plan, load_policies, write_evidence_jsonl

ROOT = Path(__file__).resolve().parents[1]
JsonDict = dict[str, Any]


def load_plan(path: str) -> JsonDict:
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return cast(JsonDict, json.load(handle))


def policies() -> list[JsonDict]:
    return load_policies(ROOT / "policies")


def test_project_factory_allowed_plan_emits_allow_decision() -> None:
    evidence = evaluate_plan(
        load_plan("examples/project-factory/terraform-plan.allowed.json"),
        policies(),
        actor_id="platform-ci",
        actor_role="validator",
        tenant="cft",
    )

    assert evidence["decision"] == "allow"
    assert evidence["plan_hash"].startswith("sha256:")
    assert evidence["merkle_root"].startswith("sha256:")
    assert not [result for result in evidence["control_results"] if result["status"] == "fail"]


def test_project_factory_denied_plan_reports_governance_violations() -> None:
    evidence = evaluate_plan(
        load_plan("examples/project-factory/terraform-plan.denied.json"),
        policies(),
        actor_id="platform-ci",
        actor_role="validator",
        tenant="cft",
    )

    failed_controls = {result["control_id"] for result in evidence["control_results"] if result["status"] == "fail"}
    assert evidence["decision"] == "deny"
    assert {
        "cft-project-required-labels",
        "cft-project-approved-folder",
        "cft-project-approved-billing",
        "cft-project-forbidden-apis",
        "cft-deny-long-lived-service-account-keys",
        "cft-deny-broad-iam-roles",
    }.issubset(failed_controls)


def test_network_denied_plan_catches_public_ssh_and_missing_logs() -> None:
    evidence = evaluate_plan(
        load_plan("examples/network-firewall-policy/terraform-plan.denied.json"),
        policies(),
        actor_id="platform-ci",
        actor_role="validator",
        tenant="cft",
    )

    failed_controls = {result["control_id"] for result in evidence["control_results"] if result["status"] == "fail"}
    assert evidence["decision"] == "deny"
    assert {
        "cft-network-deny-public-admin-ingress",
        "cft-network-firewall-logging",
        "cft-network-subnet-flow-logs",
    }.issubset(failed_controls)


def test_evidence_jsonl_writer_round_trips_one_event(tmp_path: Path) -> None:
    evidence = evaluate_plan(
        load_plan("examples/project-factory/terraform-plan.allowed.json"),
        policies(),
        actor_id="platform-ci",
        actor_role="validator",
        tenant="cft",
    )
    output = tmp_path / "evidence.jsonl"

    write_evidence_jsonl(output, evidence)

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["schema"] == "acgs.cft.evidence.v1"


def test_github_oidc_substring_without_equality_is_denied() -> None:
    evidence = evaluate_plan(
        load_plan("examples/github-actions-runner-gate/terraform-plan.denied.json"),
        policies(),
        actor_id="platform-ci",
        actor_role="validator",
        tenant="cft",
    )

    failed_controls = {r["control_id"] for r in evidence["control_results"] if r["status"] == "fail"}
    assert evidence["decision"] == "deny"
    assert "cft-github-actions-oidc-provider" in failed_controls


def test_github_oidc_disallowed_owner_is_denied() -> None:
    evidence = evaluate_plan(
        load_plan("examples/github-actions-runner-gate/terraform-plan.denied-wrong-owner.json"),
        policies(),
        actor_id="platform-ci",
        actor_role="validator",
        tenant="cft",
    )

    failed_controls = {r["control_id"] for r in evidence["control_results"] if r["status"] == "fail"}
    assert evidence["decision"] == "deny"
    assert "cft-github-actions-oidc-provider" in failed_controls
