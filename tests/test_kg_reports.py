"""Guards for ``tools/kg/reports.py`` — the governance report generator.

Both generated reports are claim-safety surfaces: they are read as statements
about what compliance evidence exists. The rules that keep them honest are all
in this one module, and all of them fail silently if broken —

  * three test-evidence states, never two ("unanalyzed" must never collapse
    into "untested", which would manufacture a finding for every submodule file);
  * tier B requires the citation to point at *source*, so a control whose only
    evidence is another ``.md`` is reported as doc-only rather than implemented;
  * tier C requires a test edge on that same source file;
  * tier D is UNKNOWN for every control and is never inferred;
  * determinism — nothing is stamped from the wall clock.

``main`` is exercised end-to-end against a stub driver; no live Neo4j needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _kg_common import fake_neo4j, load_kg_module

reports = load_kg_module("reports")

SNAPSHOT = {
    "head": "abcdef0123456789",
    "branch": "master",
    "ua_commit": "0123456789abcdef",
    "stale": True,
    "generated_at": "2026-08-09T00:00:00Z",
    "dirty": 3,
    "enumeration_scopes_skipped": 7,
}
COVERAGE = {"files": 200, "analyzed": 120, "in_submodules": 40}


def _hot(path: str, **over) -> dict:
    row = {
        "path": path,
        "package": "packages/gove-zone",
        "commits": 12,
        "contributors": 2,
        "churn": 300,
        "ua_covered": True,
        "sealed": False,
        "in_submodule": False,
        "test_edges": 1,
        "gates": 1,
        "adrs": 0,
    }
    row.update(over)
    return row


def _control(control: str, ev: list[dict], framework: str = "EU AI Act", docs: int = 1) -> dict:
    return {
        "control": control,
        "framework": framework,
        "mapping_docs": [f"docs/map{i}.md" for i in range(docs)],
        "ev": ev,
    }


def _ev(key: str, ext: str, ua: bool = True) -> dict:
    return {"key": key, "ext": ext, "ua": ua}


@pytest.fixture
def run_reports(tmp_path, monkeypatch):
    """Run ``reports.main()`` against a stub driver; return the two documents."""

    def _run(
        *,
        controls: list[dict] | None = None,
        tested: list[str] | None = None,
        hot: list[dict] | None = None,
        cplane: list[dict] | None = None,
        repos: list[dict] | None = None,
        resolutions: list[dict] | None = None,
        snapshot: dict | None = None,
        coverage: dict | None = None,
        out_dir: Path | None = None,
    ):
        out = out_dir or (tmp_path / "docs" / "governance" / "reports")
        monkeypatch.setattr(reports, "ROOT", tmp_path)
        monkeypatch.setattr(reports, "OUT_DIR", out)

        def responder(query: str) -> list[dict]:
            if "MATCH (s:Snapshot)" in query:
                return [snapshot or SNAPSHOT]
            if "AS in_submodules" in query:
                return [coverage or COVERAGE]
            if "LIMIT $limit" in query:
                return list(hot or [])
            if "acgs-control-plane" in query:
                return list(cplane or [])
            if "MATCH (c:Commit)" in query:
                return list(repos or [{"repo": ".", "commit_nodes": 400}])
            if "MATCH (c:Control)" in query:
                return list(controls or [])
            if "AS tested" in query:
                return [{"tested": list(tested or [])}]
            if "resolved_by" in query:
                return list(resolutions or [])
            return []

        captured = fake_neo4j(monkeypatch, responder)
        monkeypatch.setattr(sys, "argv", ["reports.py"])

        code = reports.main()
        return (
            code,
            (out / "cross-repo-hotspot-report.md").read_text(),
            (out / "compliance-evidence-tiers.md").read_text(),
            captured["driver"],
        )

    return _run


# --------------------------------------------------------------------------- #
# Markdown helper
# --------------------------------------------------------------------------- #
def test_md_table_renders_a_header_separator_and_rows():
    rendered = reports.md_table(["a", "b"], [[1, 2], ["x", "y"]])

    assert rendered.splitlines() == ["| a | b |", "|---|---|", "| 1 | 2 |", "| x | y |"]


def test_md_table_says_no_rows_instead_of_emitting_an_empty_table():
    assert reports.md_table(["a"], []) == "_No rows._\n"


def test_md_table_stringifies_non_string_cells():
    assert "| 1 | True |" in reports.md_table(["a", "b"], [[1, True]])


# --------------------------------------------------------------------------- #
# Test-evidence state: three states, never two
# --------------------------------------------------------------------------- #
def test_unanalyzed_file_is_reported_as_unknown_not_untested():
    """Collapsing 'unanalyzed' into 'untested' would manufacture a finding for
    every submodule file."""
    state = reports.test_evidence_state({"ua_covered": False, "test_edges": 0})

    assert state == "not analyzed — outside semantic snapshot"


def test_unanalyzed_wins_even_when_test_edges_exist():
    state = reports.test_evidence_state({"ua_covered": False, "test_edges": 4})

    assert state == "not analyzed — outside semantic snapshot"


def test_analyzed_file_with_edges_reports_the_count():
    assert (
        reports.test_evidence_state({"ua_covered": True, "test_edges": 3}) == "tested (3 edge(s))"
    )


def test_analyzed_file_without_edges_is_marked_analyzed():
    assert reports.test_evidence_state({"ua_covered": True, "test_edges": 0}) == (
        "no test edge (analyzed)"
    )


# --------------------------------------------------------------------------- #
# Governance coverage summary
# --------------------------------------------------------------------------- #
def test_governance_coverage_lists_every_observed_control():
    # The multiplication sign is what reports.py actually emits; asserting an
    # ASCII 'x' here would pass against a report no reader ever sees.
    assert reports.governance_coverage({"gates": 2, "sealed": True, "adrs": 1}) == (
        "CI×2, sealed, ADR×1"  # noqa: RUF001 - literal output of governance_coverage
    )


def test_governance_coverage_omits_absent_controls():
    assert reports.governance_coverage({"gates": 0, "sealed": True, "adrs": 0}) == "sealed"


def test_governance_coverage_reports_absence_as_absence_of_evidence():
    assert reports.governance_coverage({"gates": 0, "sealed": False, "adrs": 0}) == "none observed"


# --------------------------------------------------------------------------- #
# Evidence tiers
# --------------------------------------------------------------------------- #
def test_control_cited_with_source_evidence_reaches_tier_b(run_reports):
    _, _, tiers, _ = run_reports(
        controls=[_control("EU AI Act Art 12(1)", [_ev("packages/gove-zone/audit.py", ".py")])]
    )

    assert "| EU AI Act Art 12(1) | EU AI Act | B implemented |" in tiers


def test_control_whose_source_evidence_is_tested_reaches_tier_c(run_reports):
    _, _, tiers, _ = run_reports(
        controls=[_control("EU AI Act Art 12(1)", [_ev("packages/gove-zone/audit.py", ".py")])],
        tested=["packages/gove-zone/audit.py"],
    )

    assert "| EU AI Act Art 12(1) | EU AI Act | C tested |" in tiers


def test_control_evidenced_only_by_a_document_is_not_reported_as_implemented(run_reports):
    """The single easiest way to overclaim compliance is to count a doc citing
    another doc as an implementation."""
    _, _, tiers, _ = run_reports(
        controls=[_control("SOC 2 CC7.2", [_ev("docs/other.md", ".md")], framework="SOC 2")]
    )

    assert "| SOC 2 CC7.2 | SOC 2 | A referenced (evidence target is a document) |" in tiers
    assert "B implemented" not in tiers.split("## Per-control detail")[1]


def test_control_with_no_evidence_target_says_so(run_reports):
    _, _, tiers, _ = run_reports(controls=[_control("SOC 2 CC7.2", [], framework="SOC 2")])

    assert "| SOC 2 CC7.2 | SOC 2 | A referenced (no evidence target) |" in tiers


def test_config_only_evidence_is_labelled_configuration_not_document(run_reports):
    """A cited `.yml` is neither a `.md` target nor source code. Calling it a
    document contradicts the report's own definition of document evidence; it
    still stays below tier B because source code remains required."""
    _, _, tiers, _ = run_reports(
        controls=[
            _control(
                "SOC 2 CC7.2",
                [_ev(".github/workflows/ci.yml", ".yml")],
                framework="SOC 2",
            )
        ]
    )

    assert "| SOC 2 CC7.2 | SOC 2 | A referenced (evidence target is configuration) |" in tiers
    detail = tiers.split("## Per-control detail")[1]
    assert "evidence target is a document" not in detail
    assert "B implemented" not in detail


def test_evidence_rows_without_a_key_are_discarded(run_reports):
    """An OPTIONAL MATCH that found nothing yields a null-keyed collect entry;
    treating it as evidence would invent a citation."""
    _, _, tiers, _ = run_reports(
        controls=[
            _control("SOC 2 CC7.2", [{"key": None, "ext": None, "ua": False}], framework="SOC 2")
        ]
    )

    assert "| SOC 2 CC7.2 | SOC 2 | A referenced (no evidence target) |" in tiers


def test_tier_d_is_unknown_for_every_control(run_reports):
    _, _, tiers, _ = run_reports(
        controls=[
            _control("EU AI Act Art 12(1)", [_ev("a.py", ".py")]),
            _control("SOC 2 CC7.2", [_ev("b.py", ".py")], framework="SOC 2"),
        ],
        tested=["a.py", "b.py"],
    )

    assert "**UNKNOWN for every control.**" in tiers
    detail = tiers.split("## Per-control detail")[1]
    assert detail.count("| UNKNOWN |") == 2


def test_per_framework_summary_counts_each_tier(run_reports):
    _, _, tiers, _ = run_reports(
        controls=[
            _control("EU AI Act Art 12(1)", [_ev("a.py", ".py")]),
            _control("EU AI Act Art 14(4)", [_ev("b.py", ".py")]),
            _control("EU AI Act Art 15(1)", [_ev("docs/x.md", ".md")]),
            _control("EU AI Act Art 16(1)", [_ev("configs/policy.yaml", ".yaml")]),
            _control("EU AI Act Art 17(1)", []),
        ],
        tested=["a.py"],
    )

    summary = tiers.split("## Per-framework summary")[1].split("## Per-control detail")[0]
    # A=5, B implemented=2, C tested=1, D UNKNOWN,
    # config-only=1, doc-only=1, no evidence=1
    assert "| EU AI Act | 5 | 2 | 1 | UNKNOWN | 1 | 1 | 1 |" in summary


def test_detail_rows_are_sorted_by_framework_then_control(run_reports):
    _, _, tiers, _ = run_reports(
        controls=[
            _control("SOC 2 CC7.2", [], framework="SOC 2"),
            _control("EU AI Act Art 14(4)", []),
            _control("EU AI Act Art 12(1)", []),
        ]
    )

    detail = tiers.split("## Per-control detail")[1]
    order = [
        line.split("|")[1].strip()
        for line in detail.splitlines()
        if line.startswith("| EU") or line.startswith("| SOC")
    ]
    assert order == ["EU AI Act Art 12(1)", "EU AI Act Art 14(4)", "SOC 2 CC7.2"]


def test_resolution_method_table_explains_the_weakest_tier(run_reports):
    _, _, tiers, _ = run_reports(
        resolutions=[{"how": "path", "n": 10}, {"how": "basename", "n": 4}],
    )

    assert "| path | 10 | explicit repo-relative path in the citation — unambiguous |" in tiers
    assert "| basename | 4 | bare filename, unique across the workspace by luck |" in tiers


def test_unrecorded_resolution_methods_are_labelled_unknown(run_reports):
    _, _, tiers, _ = run_reports(resolutions=[{"how": "unrecorded", "n": 2}])

    assert "| unrecorded | 2 | unknown |" in tiers


def test_skipped_enumeration_count_is_reported_from_the_snapshot(run_reports):
    _, _, tiers, _ = run_reports()

    assert "7 such scopes were skipped" in tiers


# --------------------------------------------------------------------------- #
# Hotspot report
# --------------------------------------------------------------------------- #
def test_hotspot_rows_carry_the_three_state_evidence_column(run_reports):
    _, hotspot, _, _ = run_reports(
        hot=[
            _hot("packages/gove-zone/gateway.py", test_edges=2),
            _hot("packages/acgs-control-plane/app.py", ua_covered=False, test_edges=0),
        ]
    )

    assert "tested (2 edge(s))" in hotspot
    assert "not analyzed — outside semantic snapshot" in hotspot
    assert "1 of these 2 rows are outside the semantic snapshot" in hotspot


def test_control_plane_focus_section_counts_test_files_by_path_convention(run_reports):
    _, hotspot, _, _ = run_reports(
        cplane=[
            _hot("packages/acgs-control-plane/tests/test_app.py", commits=5, ua_covered=False),
            _hot("packages/acgs-control-plane/app.py", commits=9, ua_covered=False),
        ]
    )

    assert "2 of the 2 focus-area paths" not in hotspot
    assert "1 of the 2 focus-area paths are\n  themselves test files" in hotspot
    assert "carrying 5 commits" in hotspot


def test_provenance_names_the_commit_branch_and_staleness(run_reports):
    _, hotspot, tiers, _ = run_reports()

    for document in (hotspot, tiers):
        assert "parent commit `abcdef012345`" in document
        assert "on `master`" in document
        assert "3 uncommitted paths present" in document
        assert "STALE relative to HEAD" in document
        assert "120/200 tracked files analyzed" in document


def test_provenance_reports_a_current_semantic_layer_when_not_stale(run_reports):
    _, hotspot, _, _ = run_reports(snapshot={**SNAPSHOT, "stale": False})

    assert "is current:" in hotspot
    assert "STALE relative to HEAD" not in hotspot


def test_commit_node_distribution_lists_every_repo(run_reports):
    _, hotspot, _, _ = run_reports(
        repos=[
            {"repo": ".", "commit_nodes": 300},
            {"repo": "packages/acgs-lite", "commit_nodes": 100},
        ]
    )

    assert "| packages/acgs-lite | 100 |" in hotspot


# --------------------------------------------------------------------------- #
# Contract-level properties
# --------------------------------------------------------------------------- #
def test_reports_are_byte_identical_across_runs(run_reports, tmp_path):
    """Stated contract: same graph in, same bytes out. Nothing may be stamped
    from the wall clock — provenance comes from the (:Snapshot) node."""
    kwargs = dict(
        controls=[_control("EU AI Act Art 12(1)", [_ev("a.py", ".py")])],
        tested=["a.py"],
        hot=[_hot("a.py")],
        resolutions=[{"how": "path", "n": 1}],
    )
    _, first_hot, first_tiers, _ = run_reports(**kwargs, out_dir=tmp_path / "run1")
    _, second_hot, second_tiers, _ = run_reports(**kwargs, out_dir=tmp_path / "run2")

    assert first_hot == second_hot
    assert first_tiers == second_tiers


def test_main_creates_the_output_directory_and_closes_the_driver(run_reports, tmp_path, capsys):
    code, _, _, driver = run_reports(out_dir=tmp_path / "nested" / "reports")

    assert code == 0
    assert driver.closed is True
    out = capsys.readouterr().out
    assert "wrote nested/reports/cross-repo-hotspot-report.md" in out
    assert "wrote nested/reports/compliance-evidence-tiers.md" in out


def test_an_empty_graph_still_produces_both_reports(run_reports):
    code, hotspot, tiers, _ = run_reports()

    assert code == 0
    assert hotspot.startswith("# Cross-repo hotspot report")
    assert tiers.startswith("# Compliance evidence tiers")
    assert "_No rows._" in tiers
