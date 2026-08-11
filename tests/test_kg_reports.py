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

import re
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
COVERAGE = {"files": 200, "analyzed": 120, "in_submodules": 40, "analyzed_in_submodules": 0}


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
        "is_test": False,
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


@pytest.mark.parametrize("query", [reports.HOTSPOT_Q, reports.CONTROL_PLANE_Q])
def test_report_gate_counts_include_pr_only_workflows_and_exclude_push_only(query):
    """GATES edges carry their triggering events. Governance coverage is PR
    merge-gate evidence, so a push-only workflow must not increment it while a
    pull_request workflow must."""
    assert "[g:GATES]" in query
    assert "'pull_request' IN coalesce(g.events, [])" in query
    assert "'push' IN coalesce(g.events, [])" not in query


def _catalog_query(number: int) -> str:
    """One query block out of tools/kg/queries.cypher, by its Q-number."""
    catalog = (Path(reports.__file__).with_name("queries.cypher")).read_text()
    block = catalog.split(f"// --- Q{number}.", 1)[1]
    nxt = re.search(r"// --- Q\d+", block)
    return block[: nxt.start()] if nxt else block


def test_catalog_q1_and_q2_partition_gates_by_pull_request_event():
    """The interactive catalog must use the same PR-only interpretation as
    generated reports: Q1 includes PR gates; Q2 treats push-only edges as
    ungated for pull-request merge coverage."""
    catalog = (Path(reports.__file__).with_name("queries.cypher")).read_text()
    q1 = catalog.split("// --- Q1.", 1)[1].split("// --- Q2.", 1)[0]
    q2 = catalog.split("// --- Q2.", 1)[1].split("// --- Q3.", 1)[0]

    for query in (q1, q2):
        assert "[g:GATES]" in query
        assert "'pull_request' IN coalesce(g.events, [])" in query
        assert "'push' IN coalesce(g.events, [])" not in query


def test_catalog_q5_and_q13_ignore_test_edges_to_deleted_targets():
    """REGRESSION. When the semantic snapshot predates a test file's deletion,
    its TESTED_BY edge survives pointing at a target with present=false. Q5's
    unqualified `NOT (f)-[:TESTED_BY]->()` suppressed the source from the
    hotspot list on stale evidence alone, and Q13 counted the dead edge as
    test status. Both must restrict to live targets, like the generated
    reports (nodes without the flag, e.g. Symbols, stay countable)."""
    for query in (_catalog_query(5), _catalog_query(13)):
        assert "TESTED_BY]->()" not in query
        match = re.search(r"TESTED_BY]->\((\w+)", query)
        assert match, f"query no longer binds its TESTED_BY target:\n{query}"
        assert f"coalesce({match.group(1)}.present, true)" in query


def test_catalog_q14_traverses_every_advertised_structural_edge():
    """REGRESSION. Q14's heading (and the README) advertise a blast radius
    over every structural edge, but the allowlist held six relationship types:
    a file's tests (TESTED_BY), symbols (CONTAINS), callers (CALLS), and the
    rest of layer B's typed edges were silently absent from the result."""
    q14 = _catalog_query(14)
    traversal = re.search(r"\[:([A-Z_|]+)\*1\.\.2\]", q14)
    assert traversal, f"Q14 lost its multi-hop traversal:\n{q14}"
    rels = set(traversal.group(1).split("|"))

    structural = {
        "CONTAINS", "IMPORTS", "EXPORTS", "TESTED_BY", "DOCUMENTS", "DEPENDS_ON",
        "CONFIGURES", "CALLS", "INHERITS", "DEFINES_SCHEMA", "TRIGGERS", "DEPLOYS",
        "SERVES", "ROUTES", "IMPLEMENTS", "RELATED_TO",
    }  # fmt: skip
    governance = {"GATES", "DECIDES_ON", "SEALED_WITH"}
    assert rels >= structural | governance
    # Membership edges would pull in a whole Layer/tour at two hops.
    assert not rels & {"IN_LAYER", "HIGHLIGHTS", "IN_PACKAGE", "CO_CHANGED"}


def test_catalog_q15_rebuilds_steps_that_highlight_symbols_and_endpoints():
    """REGRESSION. build_semantic() mints HIGHLIGHTS edges to Symbols and
    Endpoints as well as Files, but Q15 matched `(f:File)` only, so a tour
    step whose highlights are all functions/classes/endpoints vanished from
    the rebuilt tour."""
    q15 = _catalog_query(15)
    match = re.search(r"\[:HIGHLIGHTS\]->\((\w+)\)", q15)
    assert match, f"Q15's HIGHLIGHTS target must not be label-restricted:\n{q15}"
    assert ":File)" not in q15.split("RETURN")[0]


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


def test_control_plane_focus_section_counts_test_files_by_the_graphs_classification(run_reports):
    """REGRESSION. A bare `test_` substring heuristic also matched source
    modules such as tenant_bootstrap_test_worker.py, overstating how many
    focus paths are tests and their combined commit count. The graph's own
    File.is_test classification is the single authority."""
    _, hotspot, _, _ = run_reports(
        cplane=[
            _hot(
                "packages/acgs-control-plane/tests/test_app.py",
                commits=5,
                ua_covered=False,
                is_test=True,
            ),
            _hot(
                "packages/acgs-control-plane/src/acgs_control_plane/"
                "tenant_bootstrap_test_worker.py",
                commits=9,
                ua_covered=False,
            ),
            _hot("packages/acgs-control-plane/app.py", commits=9, ua_covered=False),
        ]
    )

    assert "1 of the 3 focus-area paths are\n  themselves test files" in hotspot
    assert "carrying 5 commits" in hotspot


def test_semantic_refresh_guidance_names_real_commands_not_a_missing_doc(run_reports):
    """REGRESSION. The hotspot report pointed readers at
    SEMANTIC_REFRESH_PLAN_V1.md, a file that exists nowhere in the repo — the
    prescribed path for converting unknowns into observations led nowhere."""
    _, hotspot, _, _ = run_reports(
        cplane=[_hot("packages/acgs-control-plane/app.py", ua_covered=False)]
    )

    assert "SEMANTIC_REFRESH_PLAN_V1.md" not in hotspot
    assert "git submodule update --init" in hotspot
    assert "make reload" in hotspot


def test_control_plane_section_keeps_the_no_claim_wording_when_nothing_is_analyzed(run_reports):
    _, hotspot, _, _ = run_reports(
        cplane=[_hot("packages/acgs-control-plane/app.py", ua_covered=False, test_edges=0)]
    )

    assert "the semantic snapshot has never analyzed it" in hotspot
    assert "Every row above is `not analyzed — outside semantic snapshot`." in hotspot


def test_control_plane_section_derives_its_wording_from_analyzed_rows(run_reports):
    """REGRESSION. The section asserted every row was unanalyzed even when its
    own table reported analyzed/tested evidence for some rows."""
    _, hotspot, _, _ = run_reports(
        cplane=[
            _hot("packages/acgs-control-plane/app.py", ua_covered=True, test_edges=2),
            _hot("packages/acgs-control-plane/tenant.py", ua_covered=False, test_edges=0),
        ]
    )

    assert "the semantic snapshot covers 1 of these 2 focus-area paths" in hotspot
    assert "Every row above is" not in hotspot
    assert "1 of the 2 rows above are" in hotspot
    assert "The other 1\n  rows carry semantic analysis" in hotspot


def test_test_evidence_queries_ignore_deleted_targets():
    """REGRESSION. When the semantic snapshot predates a test file's deletion,
    the TESTED_BY edge survives pointing at a File marked present=false. The
    unfiltered edge counts classified the source as tested in both reports and
    could promote compliance evidence to Tier C on a test the extracted
    working tree no longer contains. Every test-evidence query must restrict
    to live targets (nodes without the flag, e.g. Symbols, stay countable)."""
    for query in (reports.HOTSPOT_Q, reports.CONTROL_PLANE_Q, reports.TESTED_Q):
        match = re.search(r"TESTED_BY]->\((\w+)\)", query)
        assert match, f"query no longer binds its TESTED_BY target:\n{query}"
        assert f"coalesce({match.group(1)}.present, true)" in query


def test_regenerate_guidance_isolates_uv_from_the_root_workspace(run_reports):
    """REGRESSION. Without --no-project, `uv run` discovers the root uv
    workspace and fails in a non-recursive checkout on uninitialized submodule
    members (packages/acgs-lite has no pyproject.toml there) before reports.py
    even starts — the documented regeneration path led to an error."""
    _, hotspot, tiers, _ = run_reports()

    for document in (hotspot, tiers):
        assert "uv run --no-project --with neo4j python reports.py" in document


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


def test_provenance_survives_a_missing_semantic_commit(run_reports):
    """REGRESSION. A fresh clone extracts no semantic layer, so
    Snapshot.ua_commit is null; slicing it raised TypeError before either
    report was written. The absence must render as an explicit state."""
    code, hotspot, tiers, _ = run_reports(
        snapshot={**SNAPSHOT, "ua_commit": None},
        coverage={"files": 200, "analyzed": 0, "in_submodules": 40, "analyzed_in_submodules": 0},
    )

    assert code == 0
    for document in (hotspot, tiers):
        assert "**absent**" in document
        assert "recorded no semantic snapshot" in document
        assert "0/200 tracked files analyzed" in document
        assert "STALE relative to HEAD" not in document


def test_provenance_reports_a_loaded_layer_without_metadata_as_stale_not_absent(run_reports):
    """REGRESSION companion to extract.semantic_snapshot_props(): when
    knowledge-graph.json was ingested but meta.json is missing, the layer IS
    loaded — labelling it absent would contradict every ua_covered fact in the
    same report. It renders as loaded-but-unverifiable, i.e. stale."""
    code, hotspot, tiers, _ = run_reports(
        snapshot={**SNAPSHOT, "ua_commit": None, "semantic_loaded": True},
    )

    assert code == 0
    for document in (hotspot, tiers):
        assert "**absent**" not in document
        assert "meta.json" in document
        assert "treated as STALE" in document


def test_provenance_derives_submodule_coverage_from_the_graph(run_reports):
    """REGRESSION. The provenance hard-coded 'all submodule files are
    unanalyzed', which becomes false the moment the semantic layer is
    refreshed with submodules initialized."""
    _, hotspot, _, _ = run_reports(
        coverage={"files": 200, "analyzed": 120, "in_submodules": 40, "analyzed_in_submodules": 15}
    )

    assert "15 of the 40 submodule files are analyzed" in hotspot
    assert "the other 25 are outside the snapshot" in hotspot


def test_provenance_reports_zero_submodule_coverage_as_none_analyzed(run_reports):
    _, hotspot, _, _ = run_reports()

    assert "None of the 40 submodule files are analyzed." in hotspot


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
