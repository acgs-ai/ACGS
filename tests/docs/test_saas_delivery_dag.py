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
    "id", "phase", "title", "buyer_user_outcome", "repo_owner", "dependencies",
    "consumers", "likely_interfaces_files", "risk_class", "positive_tests",
    "forbidden_side_effect_negative_tests", "validation_commands", "evidence_artifact",
    "branch", "worktree", "pr", "status", "implementation_state", "evidence_state",
    "blocker", "next_safe_action", "mandatory", "completion_scope",
}
REQUIRED_BLOCKER_FIELDS = {
    "id", "title", "owner", "state", "exact_need", "why_not_assumed",
    "validation_after_unblock", "downstream_nodes",
}
REQUIRED_GRANULAR_NODES = {
    "G101", "G102", "G103", "G104", "G105", "G106",
    "G201", "G202", "G203", "G204", "G205", "G206",
    "G301", "G302", "G303", "G304", "G305", "G306",
    "G401", "G402", "G403", "G404", "G405", "G406", "G407",
    "G501", "G502", "G503",
    "G601", "G602", "G603", "G604", "G605", "G606",
    "G701", "G702", "G703", "G704",
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
            assert all(by_id[dependency]["status"] == "completed" for dependency in node["dependencies"])
        if node["evidence_state"] in VERIFIED_EVIDENCE:
            assert node["status"] == "completed"
            assert node["implementation_state"] == "built"
            assert all(by_id[dependency]["status"] == "completed" for dependency in node["dependencies"])
        if node["status"] == "ready":
            assert all(by_id[dependency]["status"] == "completed" for dependency in node["dependencies"])
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
            rows.append({"id": matrix_id, "criterion": criterion, "state": state,
                         "evidence": evidence, "refs": refs, "artifact": artifact})
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
        elif row["state"] == "partial":
            assert any(node["implementation_state"] in {"partial", "built"} for node in referenced)
        elif row["state"] == "missing":
            assert row["evidence"] == "none"
        elif row["state"] == "conflicting":
            assert any(node["implementation_state"] == "conflicting" for node in referenced)
        assert not (row["evidence"] == "historical_only" and row["state"] == "built")


def test_schema_types_vocabularies_and_portability() -> None:
    dag = _load_dag()
    assert dag["schema"] == {
        "name": "acgs-saas-delivery-dag", "version": 3, "updated": "2026-07-13",
        "source_of_truth": "docs/ROADMAP.md", "serialization": "JSON, a strict YAML 1.2 subset",
    }
    assert all(key in dag for key in ("program", "vocabularies", "external_blocker_packets", "acceptance_criteria", "nodes"))
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
        for field in ("positive_tests", "forbidden_side_effect_negative_tests", "validation_commands"):
            assert all(isinstance(item, str) and item.strip() for item in _nonempty_list(node[field]))
        for command in node["validation_commands"]:
            assert shlex.split(command)[0] in {"uv", "make", "git", "gh", "test", "cd"}


def test_beta_completion_scope_is_mechanical_and_excludes_external_only() -> None:
    dag = _load_dag()
    policy = dag["program"]["completion_policy"]["beta_code_complete"]
    assert policy == {
        "required_selector": "mandatory == true and completion_scope == non_external",
        "satisfied_selector": "status == completed and implementation_state == built and evidence_state in verified evidence states",
        "external_only_excluded": True,
    }
    non_external = [
        node for node in dag["nodes"]
        if node["mandatory"] and node["completion_scope"] == "non_external"
    ]
    external_only = [node for node in dag["nodes"] if node["completion_scope"] == "external_only"]
    assert non_external
    assert {node["id"] for node in external_only} == {"G701", "G702", "G703", "G704"}
    assert all(node["mandatory"] for node in external_only)
    assert all(node["phase"] <= 6 and node["mandatory"] for node in non_external)
    assert all(
        node["mandatory"] and node["completion_scope"] == "non_external"
        for node in dag["nodes"] if node["phase"] <= 6
    )
    pending = {
        node["id"] for node in non_external
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
            node.update(status="completed", implementation_state="built", evidence_state="external_verified", blocker=None)
    pending_after_external = {
        node["id"] for node in externally_completed["nodes"]
        if node["mandatory"] and node["completion_scope"] == "non_external"
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
        assert all(node["id"] in by_id[dependency]["consumers"] for dependency in node["dependencies"])
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
    next(node for node in ready["nodes"] if node["id"] == "G007")["status"] = "ready"
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
    expected = {"EXT-CREDENTIALS", "EXT-SPEND", "EXT-LEGAL", "EXT-AUDITOR", "EXT-CUSTOMERS", "EXT-DEPLOY-APPROVAL"}
    assert {blocker["id"] for blocker in blockers} == expected
    for blocker in blockers:
        assert REQUIRED_BLOCKER_FIELDS <= blocker.keys()
        assert blocker["state"] in dag["vocabularies"]["blocker_states"]
        assert set(_nonempty_list(blocker["downstream_nodes"])) <= node_ids
        for node_id in blocker["downstream_nodes"]:
            node = next(item for item in dag["nodes"] if item["id"] == node_id)
            assert blocker["id"] in str(node["blocker"])


def test_acceptance_criteria_and_exact_matrix_rows_are_consistent() -> None:
    dag = _load_dag()
    node_ids = {node["id"] for node in dag["nodes"]}
    criteria = _nonempty_list(dag["acceptance_criteria"])
    assert {item["id"] for item in criteria} == {"AC-SECURITY", "AC-JOURNEY", "AC-RELIABILITY", "AC-COMMERCIAL", "AC-CLAIMS"}
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

    mutated = copy.deepcopy(rows)
    mutated[2]["state"] = "built"
    try:
        _validate_matrix_state(mutated, dag)
    except AssertionError:
        pass
    else:
        raise AssertionError("historical-only evidence promoted a matrix row to built")


def test_phase_zero_artifact_ownership_is_explicit() -> None:
    dag = _load_dag()
    by_id = {node["id"]: node for node in dag["nodes"]}
    for node_id, artifacts in PHASE_ZERO_ARTIFACTS.items():
        node = by_id[node_id]
        assert artifacts <= set(node["likely_interfaces_files"])
        combined_acceptance = " ".join(node["positive_tests"] + [node["evidence_artifact"]])
        for artifact in artifacts:
            assert Path(artifact).name in combined_acceptance or "build-vs-buy ADRs" in combined_acceptance


def test_disaster_recovery_node_has_executable_evidence_gates() -> None:
    dag = _load_dag()
    g603 = next(node for node in dag["nodes"] if node["id"] == "G603")
    commands = g603["validation_commands"]
    joined = " ".join(commands).lower()
    assert "test -f docs/saas/delivery_dag.yaml" not in joined
    assert "pytest" in joined and any(term in joined for term in ("backup", "restore", "pitr"))
    assert "verify_dr_report.py" in joined
    assert "timestamped-dr-report.json" in g603["evidence_artifact"]
    assert all(term in g603["evidence_artifact"].lower() for term in ("backup", "pitr", "witness", "rollback"))


def test_g004_and_frozen_pr_snapshot_preserve_historical_boundary() -> None:
    dag = _load_dag()
    snapshot = dag["program"]["survey_snapshot"]
    assert snapshot["baseline_commit"] == "1d9c9b21372ebdbd20aefc3ca454a47a3d5d1f96"
    assert snapshot["github_observed_at"] == "2026-07-13T09:59:25Z"
    prs = {item["number"]: item for item in snapshot["pull_requests"]}
    assert prs[308]["state"] == "OPEN" and prs[308]["merged"] is False
    assert prs[308]["disposition"] == "active_baseline_candidate"
    assert prs[267]["state"] == "CLOSED" and prs[267]["merged"] is False
    assert prs[267]["disposition"] == "superseded_closed_unmerged"
    g004 = next(node for node in dag["nodes"] if node["id"] == "G004")
    assert set(g004["dependencies"]) == {"G005", "G030B", "G031"}
    assert (g004["implementation_state"], g004["evidence_state"]) == ("conflicting", "historical_only")
    assert g004["status"] != "completed"
    assert g004["historical_evidence"]["disposition"] == "superseded"
    assert g004["historical_evidence"]["usable_as_current_verification"] is False
    assert "issue 308" not in DAG_PATH.read_text(encoding="utf-8").lower()


def test_roadmap_links_to_canonical_program_records() -> None:
    roadmap = ROADMAP_PATH.read_text(encoding="utf-8")
    assert "saas/DELIVERY_DAG.yaml" in roadmap
    assert "saas/ACCEPTANCE_MATRIX.md" in roadmap
