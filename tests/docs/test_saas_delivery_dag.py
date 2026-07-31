from __future__ import annotations

import copy
import json
import re
import shlex
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DAG_PATH = ROOT / "docs" / "saas" / "DELIVERY_DAG.yaml"
MATRIX_PATH = ROOT / "docs" / "saas" / "ACCEPTANCE_MATRIX.md"
ROADMAP_PATH = ROOT / "docs" / "ROADMAP.md"

REQUIRED_NODE_FIELDS = {
    "id",
    "phase",
    "title",
    "buyer_user_outcome",
    "repo_owner",
    "dependencies",
    "consumers",
    "likely_interfaces_files",
    "risk_class",
    "positive_tests",
    "forbidden_side_effect_negative_tests",
    "validation_commands",
    "evidence_artifact",
    "branch",
    "worktree",
    "pr",
    "status",
    "implementation_state",
    "evidence_state",
    "blocker",
    "next_safe_action",
    "mandatory",
    "completion_scope",
}
REQUIRED_BLOCKER_FIELDS = {
    "id",
    "title",
    "owner",
    "state",
    "exact_need",
    "why_not_assumed",
    "validation_after_unblock",
    "downstream_nodes",
}
REQUIRED_GRANULAR_NODES = {
    "G101",
    "G102",
    "G102A",
    "G102B",
    "G102C",
    "G102D",
    "G103",
    "G104",
    "G105",
    "G106",
    "G201",
    "G202",
    "G203",
    "G204",
    "G205",
    "G206",
    "G301",
    "G302",
    "G303",
    "G304",
    "G305",
    "G306",
    "G401",
    "G402",
    "G403",
    "G404",
    "G405",
    "G406",
    "G407",
    "G501",
    "G502",
    "G503",
    "G601",
    "G602",
    "G603",
    "G604",
    "G605",
    "G606",
    "G701",
    "G702",
    "G703",
    "G704",
}
EXPECTED_MATRIX_IDS = {f"AM-{number:03d}" for number in range(1, 16)}
VERIFIED_EVIDENCE = {"local_verified", "independently_reviewed", "external_verified"}
PHASE_ZERO_ARTIFACTS = {
    "G007": {
        "docs/saas/PRODUCT_REQUIREMENTS.md",
        "docs/saas/ASSURANCE_CLASSES.md",
        "docs/saas/OPEN_CORE_BOUNDARY.md",
        "docs/saas/ENTITLEMENT_AND_METERING_MATRIX.md",
    },
    "G008": {
        "docs/saas/ARCHITECTURE.md",
        "docs/saas/THREAT_MODEL.md",
        "docs/saas/API_AND_DATA_CONTRACT.md",
        "docs/saas/MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md",
        "docs/adr/saas-identity-oidc-saml-scim-build-vs-buy.md",
        "docs/adr/saas-kms-build-vs-buy.md",
        "docs/adr/saas-object-retention-build-vs-buy.md",
        "docs/adr/saas-independent-witness-build-vs-buy.md",
        "docs/adr/saas-billing-build-vs-buy.md",
        "docs/adr/saas-commercial-module-boundary.md",
    },
}


def _load_dag() -> dict[str, Any]:
    # JSON is a strict YAML 1.2 subset, so the canonical .yaml stays dependency-free.
    payload = json.loads(DAG_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _nonempty_list(value: Any) -> list[Any]:
    assert isinstance(value, list) and value
    return value


def _validate_state_invariants(dag: dict[str, Any]) -> None:
    by_id = {node["id"]: node for node in dag["nodes"]}
    for node in by_id.values():
        if node["status"] == "completed":
            assert node["implementation_state"] == "built"
            assert node["evidence_state"] in VERIFIED_EVIDENCE
            assert node["blocker"] is None
            assert all(
                by_id[dependency]["status"] == "completed" for dependency in node["dependencies"]
            )
        if node["evidence_state"] in {"independently_reviewed", "external_verified"}:
            assert node["status"] == "completed"
            assert node["implementation_state"] == "built"
            assert all(
                by_id[dependency]["status"] == "completed" for dependency in node["dependencies"]
            )
        if node["status"] == "ready":
            assert all(
                by_id[dependency]["status"] == "completed" for dependency in node["dependencies"]
            )
        if node["status"] == "blocked":
            assert isinstance(node["blocker"], str) and node["blocker"].strip()


def _matrix_rows() -> list[dict[str, str]]:
    rows = []
    pattern = re.compile(
        r"^\| (AM-\d{3}) \| (.*?) \| (built|partial|missing|conflicting) "
        r"\| (none|current_local|independently_reviewed|external|historical_only) "
        r"\| ([^|]+) \| (.*?) \|$"
    )
    for line in MATRIX_PATH.read_text(encoding="utf-8").splitlines():
        if match := pattern.match(line):
            matrix_id, criterion, state, evidence, refs, artifact = match.groups()
            rows.append(
                {
                    "id": matrix_id,
                    "criterion": criterion,
                    "state": state,
                    "evidence": evidence,
                    "refs": refs,
                    "artifact": artifact,
                }
            )
    return rows


def _validate_matrix_state(rows: list[dict[str, str]], dag: dict[str, Any]) -> None:
    by_id = {node["id"]: node for node in dag["nodes"]}
    for row in rows:
        refs = [item.strip() for item in row["refs"].split(",")]
        referenced = [by_id[item] for item in refs]
        if row["state"] == "built":
            assert row["evidence"] in {"current_local", "independently_reviewed", "external"}
            assert any(node["implementation_state"] == "built" for node in referenced)
            assert any(node["evidence_state"] in VERIFIED_EVIDENCE for node in referenced)
            assert all(node["status"] == "completed" for node in referenced)
        elif row["state"] == "partial":
            assert any(node["implementation_state"] in {"partial", "built"} for node in referenced)
        elif row["state"] == "missing":
            assert row["evidence"] == "none"
        elif row["state"] == "conflicting":
            assert any(node["implementation_state"] == "conflicting" for node in referenced)
        assert not (row["evidence"] == "historical_only" and row["state"] == "built")


def _assert_repo_files_exist(paths: set[str]) -> None:
    missing = [path for path in sorted(paths) if not (ROOT / path).is_file()]
    assert missing == []


def test_schema_types_vocabularies_and_portability() -> None:
    dag = _load_dag()
    assert dag["schema"] == {
        "name": "acgs-saas-delivery-dag",
        "version": 3,
        "updated": "2026-07-30",
        "source_of_truth": "docs/ROADMAP.md",
        "serialization": "JSON, a strict YAML 1.2 subset",
    }
    assert all(
        key in dag
        for key in (
            "program",
            "vocabularies",
            "external_blocker_packets",
            "acceptance_criteria",
            "nodes",
        )
    )
    assert "/home/" not in DAG_PATH.read_text(encoding="utf-8")
    assert dag["program"]["worktree_locator"] == "git worktree list --porcelain"
    assert dag["vocabularies"]["phases"] == list(range(8))
    for node in _nonempty_list(dag["nodes"]):
        assert REQUIRED_NODE_FIELDS <= node.keys()
        assert node["phase"] in dag["vocabularies"]["phases"]
        assert node["risk_class"] in dag["vocabularies"]["risk_classes"]
        assert node["status"] in dag["vocabularies"]["statuses"]
        assert node["implementation_state"] in dag["vocabularies"]["implementation_states"]
        assert node["evidence_state"] in dag["vocabularies"]["evidence_states"]
        assert isinstance(node["mandatory"], bool)
        assert node["completion_scope"] in dag["vocabularies"]["completion_scopes"]
        assert node["worktree"] is None or not str(node["worktree"]).startswith("/")
        for field in (
            "positive_tests",
            "forbidden_side_effect_negative_tests",
            "validation_commands",
        ):
            assert all(
                isinstance(item, str) and item.strip() for item in _nonempty_list(node[field])
            )
        for command in node["validation_commands"]:
            parts = shlex.split(command)
            assert parts, f"Node {node['id']} has an empty validation command"
            assert parts[0] in {"uv", "make", "git", "gh", "test", "cd"}


def test_beta_completion_scope_is_mechanical_and_excludes_external_only() -> None:
    dag = _load_dag()
    policy = dag["program"]["completion_policy"]["beta_code_complete"]
    assert policy == {
        "required_selector": "mandatory == true and completion_scope == non_external",
        "satisfied_selector": (
            "status == completed and implementation_state == built "
            "and evidence_state in verified evidence states"
        ),
        "external_only_excluded": True,
    }
    non_external = [
        node
        for node in dag["nodes"]
        if node["mandatory"] and node["completion_scope"] == "non_external"
    ]
    external_only = [node for node in dag["nodes"] if node["completion_scope"] == "external_only"]
    assert non_external
    assert {node["id"] for node in external_only} == {"G701", "G702", "G703", "G704"}
    assert all(node["mandatory"] for node in external_only)
    assert all(node["phase"] <= 6 and node["mandatory"] for node in non_external)
    assert all(
        node["mandatory"] and node["completion_scope"] == "non_external"
        for node in dag["nodes"]
        if node["phase"] <= 6
    )
    pending = {
        node["id"]
        for node in non_external
        if not (
            node["status"] == "completed"
            and node["implementation_state"] == "built"
            and node["evidence_state"] in VERIFIED_EVIDENCE
        )
    }
    assert pending
    assert pending.isdisjoint({node["id"] for node in external_only})
    # Completing external validation alone cannot change the mechanical beta result.
    externally_completed = copy.deepcopy(dag)
    for node in externally_completed["nodes"]:
        if node["completion_scope"] == "external_only":
            node.update(
                status="completed",
                implementation_state="built",
                evidence_state="external_verified",
                blocker=None,
            )
    pending_after_external = {
        node["id"]
        for node in externally_completed["nodes"]
        if node["mandatory"]
        and node["completion_scope"] == "non_external"
        and not (
            node["status"] == "completed"
            and node["implementation_state"] == "built"
            and node["evidence_state"] in VERIFIED_EVIDENCE
        )
    }
    assert pending_after_external == pending


def test_unique_references_acyclic_graph_and_all_phases() -> None:
    dag = _load_dag()
    nodes = dag["nodes"]
    ids = [node["id"] for node in nodes]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"G\d{3}[A-Z]?", node_id) for node_id in ids)
    known = set(ids)
    by_id = {node["id"]: node for node in nodes}
    for node in nodes:
        assert set(node["dependencies"]) <= known
        assert set(node["consumers"]) <= known
        assert node["id"] not in node["dependencies"]
        assert all(
            node["id"] in by_id[dependency]["consumers"] for dependency in node["dependencies"]
        )
        assert all(node["id"] in by_id[consumer]["dependencies"] for consumer in node["consumers"])
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        assert node_id not in visiting, f"dependency cycle at {node_id}"
        if node_id in visited:
            return
        visiting.add(node_id)
        for dependency in by_id[node_id]["dependencies"]:
            visit(dependency)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in ids:
        visit(node_id)
    assert visited == known
    assert {node["phase"] for node in nodes} == set(range(8))
    assert REQUIRED_GRANULAR_NODES <= known


def test_state_invariants_and_mutation_regressions() -> None:
    dag = _load_dag()
    _validate_state_invariants(dag)
    by_id = {node["id"]: node for node in dag["nodes"]}
    assert (
        by_id["G005"]["status"],
        by_id["G005"]["implementation_state"],
        by_id["G005"]["evidence_state"],
    ) == ("completed", "built", "independently_reviewed")
    assert by_id["G031"]["evidence_state"] == "local_verified"

    completed = copy.deepcopy(dag)
    completed_g031 = next(node for node in completed["nodes"] if node["id"] == "G031")
    completed_g031["evidence_state"] = "unverified"
    try:
        _validate_state_invariants(completed)
    except AssertionError:
        pass
    else:
        raise AssertionError("completed node with unverified evidence was accepted")

    ready = copy.deepcopy(dag)
    next(node for node in ready["nodes"] if node["id"] == "G103")["status"] = "ready"
    try:
        _validate_state_invariants(ready)
    except AssertionError:
        pass
    else:
        raise AssertionError("ready node with incomplete dependency was accepted")


def test_external_blockers_are_complete_actionable_and_referenced() -> None:
    dag = _load_dag()
    node_ids = {node["id"] for node in dag["nodes"]}
    blockers = _nonempty_list(dag["external_blocker_packets"])
    expected = {
        "EXT-CREDENTIALS",
        "EXT-SPEND",
        "EXT-LEGAL",
        "EXT-AUDITOR",
        "EXT-CUSTOMERS",
        "EXT-DEPLOY-APPROVAL",
        "EXT-GITHUB-BILLING",
    }
    assert {blocker["id"] for blocker in blockers} == expected
    for blocker in blockers:
        assert REQUIRED_BLOCKER_FIELDS <= blocker.keys()
        assert blocker["state"] in dag["vocabularies"]["blocker_states"]
        assert set(_nonempty_list(blocker["downstream_nodes"])) <= node_ids
        for node_id in blocker["downstream_nodes"]:
            node = next(item for item in dag["nodes"] if item["id"] == node_id)
            if blocker["state"] == "open":
                assert blocker["id"] in str(node["blocker"])
            else:
                assert blocker["id"] not in str(node["blocker"])
    github_billing = next(item for item in blockers if item["id"] == "EXT-GITHUB-BILLING")
    assert github_billing["state"] == "resolved"
    assert set(github_billing["downstream_nodes"]) == {
        "G004",
        "G101",
        "G102",
        "G102A",
        "G102B",
        "G102C",
        "G102D",
    }
    assert github_billing["validation_after_unblock"].startswith("for pr in 353")


def test_acceptance_criteria_and_exact_matrix_rows_are_consistent() -> None:
    dag = _load_dag()
    node_ids = {node["id"] for node in dag["nodes"]}
    criteria = _nonempty_list(dag["acceptance_criteria"])
    assert {item["id"] for item in criteria} == {
        "AC-SECURITY",
        "AC-JOURNEY",
        "AC-RELIABILITY",
        "AC-COMMERCIAL",
        "AC-CLAIMS",
    }
    assert all(set(_nonempty_list(item["node_refs"])) <= node_ids for item in criteria)
    rows = _matrix_rows()
    assert {row["id"] for row in rows} == EXPECTED_MATRIX_IDS
    assert len(rows) == len(EXPECTED_MATRIX_IDS)
    assert all({item.strip() for item in row["refs"].split(",")} <= node_ids for row in rows)
    matrix_refs: list[str] = []
    for row in rows:
        row_refs = [item.strip() for item in row["refs"].split(",")]
        assert len(row_refs) == len(set(row_refs))
        matrix_refs.extend(row_refs)
    assert set(matrix_refs) == node_ids
    assert all(row["artifact"].strip() for row in rows)
    _validate_matrix_state(rows, dag)
    assert {row["state"] for row in rows} == {"built", "partial", "missing"}
    assert sum(row["state"] == "built" for row in rows) == 1
    assert sum(row["state"] == "partial" for row in rows) == 5
    assert sum(row["state"] == "missing" for row in rows) == 9
    assert sum(row["state"] == "conflicting" for row in rows) == 0

    mutated = copy.deepcopy(rows)
    am_003_row = next(row for row in mutated if row["id"] == "AM-003")
    am_003_row["state"] = "built"
    try:
        _validate_matrix_state(mutated, dag)
    except AssertionError:
        pass
    else:
        raise AssertionError("blocked local evidence promoted a matrix row to built")


def test_phase_zero_artifact_ownership_is_explicit() -> None:
    dag = _load_dag()
    by_id = {node["id"]: node for node in dag["nodes"]}
    for node_id, artifacts in PHASE_ZERO_ARTIFACTS.items():
        node = by_id[node_id]
        assert artifacts <= set(node["likely_interfaces_files"])
        combined_acceptance = " ".join(node["positive_tests"] + [node["evidence_artifact"]])
        for artifact in artifacts:
            assert (
                Path(artifact).name in combined_acceptance
                or "build-vs-buy ADRs" in combined_acceptance
            )


def test_disaster_recovery_node_has_executable_evidence_gates() -> None:
    dag = _load_dag()
    g603 = next(node for node in dag["nodes"] if node["id"] == "G603")
    commands = g603["validation_commands"]
    joined = " ".join(commands).lower()
    assert "test -f docs/saas/delivery_dag.yaml" not in joined
    assert "pytest" in joined and any(term in joined for term in ("backup", "restore", "pitr"))
    assert "verify_dr_report.py" in joined
    assert "timestamped-dr-report.json" in g603["evidence_artifact"]
    assert all(
        term in g603["evidence_artifact"].lower()
        for term in ("backup", "pitr", "witness", "rollback")
    )


def test_g004_and_frozen_pr_snapshot_preserve_historical_boundary() -> None:
    dag = _load_dag()
    snapshot = dag["program"]["survey_snapshot"]
    assert snapshot["baseline_commit"] == "c20b51ee9ab1d89cfa496330568ca032c34d5022"
    assert snapshot["github_observed_at"] == "2026-07-30T07:41:08Z"
    prs = {item["number"]: item for item in snapshot["pull_requests"]}
    assert snapshot["repository"] == "acgs-ai/ACGS"
    assert prs[391]["state"] == "OPEN" and prs[391]["draft"] is False and prs[391]["merged"] is False
    assert prs[391]["base"] == "beta/p2-idempotency-002-retry"
    assert prs[391]["disposition"] == "current_local_g042_evidence_isolation_stack_unmerged"
    assert prs[393]["base"] == "beta/p2-evidence-isolation-002b"
    assert prs[393]["disposition"] == "current_local_g201_bootstrap_registration_stack_unmerged"
    assert prs[395]["base"] == "beta/p2-vertical-gate-003"
    assert prs[395]["disposition"] == "current_local_g202_signed_policy_stack_unmerged"
    assert prs[398]["base"] == "beta/p3-policy-001"
    assert prs[398]["disposition"] == "current_local_g105_mutation_inventory_stack_unmerged"
    assert prs[413]["base"] == "beta/p3-mutations-002"
    assert (
        prs[413]["disposition"]
        == "current_local_g015_g305_fixed_quorum_agent_register_unmerged_failed_authoritative_proof"
    )
    g030b = next(node for node in dag["nodes"] if node["id"] == "G030B")
    assert (g030b["status"], g030b["implementation_state"], g030b["evidence_state"]) == (
        "completed",
        "built",
        "local_verified",
    )
    assert g030b["pr"] == 353
    g004 = next(node for node in dag["nodes"] if node["id"] == "G004")
    assert set(g004["dependencies"]) == {"G005", "G030B", "G031"}
    assert (g004["implementation_state"], g004["evidence_state"]) == ("built", "local_verified")
    assert g004["status"] == "blocked"
    assert "evidence/g004/manifest.json is absent" in g004["blocker"]
    assert "exact-proof job was skipped" in g004["blocker"]
    assert g004["historical_evidence"]["disposition"] == "superseded"
    assert g004["historical_evidence"]["usable_as_current_verification"] is False
    dag_text = DAG_PATH.read_text(encoding="utf-8").lower()
    assert "issue 308" not in dag_text
    assert "pr #308 is open" not in dag_text
    assert "308 remains open" not in dag_text
    assert "active_baseline_candidate" not in dag_text


def test_g305_reconciliation_keeps_failed_authoritative_proof_blocked() -> None:
    dag = _load_dag()
    by_id = {node["id"]: node for node in dag["nodes"]}
    g305 = by_id["G305"]
    g405 = by_id["G405"]
    assert (g305["status"], g305["implementation_state"], g305["evidence_state"]) == (
        "blocked",
        "partial",
        "local_verified",
    )
    assert g305["branch"] == "beta/p3-approval-003-reconciled"
    assert g305["worktree"] == "saas-beta/p3-approval-003-ci-review"
    assert g305["pr"] == 413
    assert "88377db825c522748e1e1ef1ea7db5b86d141106" in g305["evidence_artifact"]
    assert "c8518859818916d772fb939ea567b6c22fe0ed54" in g305["evidence_artifact"]
    assert "ccc9f6ffb9fa459852932691302bcda6f58fc3e5cf66e5605389994b5363abd1" in g305["evidence_artifact"]
    assert "1008763134 bytes" in g305["evidence_artifact"]
    assert "7 failed, 817 passed, 84 skipped" in g305["evidence_artifact"]
    assert "later CI/local repair is non-authoritative only" in g305["evidence_artifact"]
    assert "fixed-quorum-1 agent.register approval/resume slice" in g305["evidence_artifact"]
    assert "consumed" in g305["blocker"]
    assert "retry/evidence goal" in g305["blocker"]
    assert "do not map this partial approval slice to enrollment completion" in g305["next_safe_action"]
    assert by_id["G201"]["dependencies"] == ["G106"]
    assert "G305" not in by_id["G201"]["dependencies"]
    assert "G201" not in g305["consumers"]
    orchestration = dag["program"]["local_orchestration_snapshot"]
    assert orchestration["G015-p3-approval-003"]["status"] == "failed"
    assert "consumed" in orchestration["G015-p3-approval-003"]["reason"]
    assert orchestration["G016-p4-enrollment-001"]["status"] == "pending"
    assert "distinct replacement approval evidence node" in orchestration["G016-p4-enrollment-001"]["scheduler_blocker"]
    assert "G305 -> G201" in orchestration["canonical_dependency_boundary"]
    assert (g405["status"], g405["implementation_state"], g405["evidence_state"]) == (
        "planned",
        "missing",
        "unverified",
    )
    rows = {row["id"]: row for row in _matrix_rows()}
    assert rows["AM-009"]["state"] == "partial"
    assert rows["AM-009"]["evidence"] == "current_local"
    assert rows["AM-009"]["refs"] == "G305, G405"
    assert "PR #413" in rows["AM-009"]["artifact"]
    assert "c8518859818916d772fb939ea567b6c22fe0ed54" in rows["AM-009"]["artifact"]
    assert "G405 console approval UX remain missing" in rows["AM-009"]["artifact"]

def test_g101_reconciliation_keeps_current_merged_slices_and_dr_separate() -> None:
    dag = _load_dag()
    by_id = {node["id"]: node for node in dag["nodes"]}
    g101 = by_id["G101"]
    g102 = by_id["G102"]
    g103 = by_id["G103"]
    g104 = by_id["G104"]
    g105 = by_id["G105"]
    g106 = by_id["G106"]
    g201 = by_id["G201"]
    g202 = by_id["G202"]
    g603 = by_id["G603"]

    for node_id, pr, branch in (
        ("G101", 355, "beta/p1-g101-tool-provenance"),
        ("G102A", 357, "beta/p1-g102-request-admission"),
        ("G102B", 359, "beta/p1-g102b-receipt-cursors"),
        ("G102C", 361, "beta/p1-g102c-openapi-drift"),
        ("G102D", 363, "beta/p1-g102d-v1-api-contract"),
    ):
        node = by_id[node_id]
        assert (node["status"], node["implementation_state"], node["evidence_state"]) == (
            "completed",
            "built",
            "independently_reviewed",
        )
        assert node["pr"] == pr
        assert node["branch"] == branch
        assert node["blocker"] is None
        assert "current master" in node["evidence_artifact"]
        assert "EXT-GITHUB-BILLING" not in node["evidence_artifact"]

    assert (g102["status"], g102["implementation_state"], g102["evidence_state"]) == (
        "in_progress",
        "partial",
        "local_verified",
    )
    assert g102["dependencies"] == ["G101", "G102A", "G102B", "G102C", "G102D"]
    assert "EXT-GITHUB-BILLING" not in g102["blocker"]
    for missing_contract in (
        "complete all-collections cursor pagination",
        "durable idempotency for mutating routes beyond native agent.register",
        "async export jobs",
        "production provider wiring",
        "complete tenant isolation",
    ):
        assert missing_contract in g102["blocker"]

    assert (g103["status"], g103["implementation_state"], g103["evidence_state"]) == (
        "blocked",
        "partial",
        "local_verified",
    )
    assert g103["pr"] == 369
    assert "tenant isolation" in g103["blocker"]
    assert (g104["status"], g104["implementation_state"], g104["evidence_state"]) == (
        "planned",
        "missing",
        "unverified",
    )
    assert (g105["status"], g105["implementation_state"], g105["evidence_state"]) == (
        "blocked",
        "partial",
        "local_verified",
    )
    assert set(g105["dependencies"]) == {"G103", "G104", "G004"}
    assert g105["pr"] == 398
    assert (g106["status"], g106["implementation_state"], g106["evidence_state"]) == (
        "blocked",
        "partial",
        "local_verified",
    )
    assert g106["dependencies"] == ["G105"]
    assert g106["pr"] == 391

    assert g201["dependencies"] == ["G106"]
    assert "G305" not in g201["dependencies"]
    assert "G305" not in g201["consumers"]
    assert (g201["status"], g201["implementation_state"], g201["evidence_state"]) == (
        "blocked",
        "partial",
        "local_verified",
    )
    assert g201["pr"] == 393
    assert (g202["status"], g202["implementation_state"], g202["evidence_state"]) == (
        "blocked",
        "partial",
        "local_verified",
    )
    assert set(g202["dependencies"]) == {"G105", "G201"}
    assert g202["pr"] == 395

    actual_files = {
        "packages/acgs-control-plane/src/acgs_control_plane/app.py",
        "packages/acgs-control-plane/src/acgs_control_plane/governance.py",
        "packages/acgs-control-plane/src/acgs_control_plane/pagination.py",
        "packages/acgs-control-plane/src/acgs_control_plane/schemas.py",
        "packages/acgs-control-plane/tests/test_api_contract.py",
        "packages/acgs-control-plane/tests/test_receipt_cursor_pagination.py",
        "packages/acgs-control-plane/tests/test_openapi_drift.py",
        "packages/acgs-control-plane/tests/test_v1_api_contract.py",
        "packages/acgs-control-plane/tests/integration/test_production_posture.py",
        "requirements/saas-beta/cp-test.lock",
    }
    _assert_repo_files_exist(actual_files)
    assert actual_files <= set(g102["likely_interfaces_files"])
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_api_contract.py -q"
        in g102["validation_commands"]
    )
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_receipt_cursor_pagination.py -q"
        in g102["validation_commands"]
    )
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_openapi_drift.py -q"
        in g102["validation_commands"]
    )

    assert g603["status"] == "planned"
    assert g603["implementation_state"] == "missing"
    assert "timestamped-dr-report.json" in g603["evidence_artifact"]

    matrix = MATRIX_PATH.read_text(encoding="utf-8")
    assert "G101 and slices G102A-D are completed/built/independently reviewed" in matrix
    assert "hosted GitHub checks did not start" not in matrix
    assert "EXT-GITHUB-BILLING" not in matrix
    assert "Open clean PR #393" in matrix
    assert "Open clean PR #395" in matrix
    assert "G201 depends on G106 only" in matrix
    assert "1008763134" in matrix

def test_roadmap_links_to_canonical_program_records() -> None:
    roadmap = ROADMAP_PATH.read_text(encoding="utf-8")
    assert "saas/DELIVERY_DAG.yaml" in roadmap
    assert "saas/ACCEPTANCE_MATRIX.md" in roadmap
