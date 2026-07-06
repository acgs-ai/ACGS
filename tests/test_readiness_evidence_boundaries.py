from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readiness_docs_do_not_treat_node22_warning_as_success_evidence() -> None:
    readiness = (ROOT / "docs" / "integration-readiness-task-map.md").read_text()

    assert "local Node 22 emitted expected Node 24 engine warning" not in readiness
    assert "Pass with local Node 22 engine warning" not in readiness
    assert "Node 22 warning is not readiness evidence" in readiness


def test_governance_index_makes_conditional_surfaces_explicit() -> None:
    index = (ROOT / "docs" / "governance-stack-index.md").read_text()

    assert "parent CI skip is not clinical verification" in index
    # The enterprise admin adjunct conditional was resolved by archiving it
    # (roadmap 00#5); the index must record that decision explicitly.
    assert "docs/archive/acgs-enterprise-ai-manager/frontend/" in index
    assert "archive over integrate with the shared evidence API" in index


def test_readiness_baseline_docs_exist_and_separate_claims() -> None:
    ledger = (ROOT / "docs" / "readiness-baseline-workspace-ledger-2026-05-25.md").read_text()
    matrix = (ROOT / "docs" / "readiness-evidence-matrix-2026-05-25.md").read_text()

    assert "211 dirty paths" in ledger
    assert "Do not reset, clean, bulk format, or broad-stage" in ledger
    for claim_area in [
        "Local",
        "Staging",
        "Production",
        "Legal/compliance",
        "Security",
        "Accessibility",
    ]:
        assert claim_area in matrix
    assert "Unsupported Claims" in matrix


def test_current_readiness_evidence_docs_track_live_summary() -> None:
    import platform_readiness_report as pr

    summary = pr.summarize(pr.build_items(ROOT))
    current_summary = (
        f"`{summary['pass']}/{summary['total']} pass`, "
        f"`{summary['fail']} fail`, "
        f"`{summary['pending']} pending`"
    )
    packet = (ROOT / "docs" / "readiness-evidence-packet-2026-05-25.md").read_text()
    matrix = (ROOT / "docs" / "readiness-evidence-matrix-2026-05-25.md").read_text()

    assert current_summary in packet
    assert current_summary in matrix
    assert "30/31 pass" not in packet
    assert "30/31 pass" not in matrix


def test_integration_readiness_task_map_uses_generated_branch_proof() -> None:
    readiness = (ROOT / "docs" / "integration-readiness-task-map.md").read_text()

    assert "make release-evidence" in readiness
    assert "make production-launch-preflight" in readiness
    assert "gove-zone smoke" in readiness
    assert "branch or deployment proof" in readiness
    assert "feat/acgs-conductor-adapter-spike" not in readiness
    assert "Scope: current checkout at" not in readiness
