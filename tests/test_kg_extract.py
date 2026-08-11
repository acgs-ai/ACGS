"""Guards for ``tools/kg/extract.py`` — the knowledge-graph extractor.

``extract.py`` builds the multi-layer graph every governance report is computed
from. Its correctness is load-bearing in a specific way: the layers join only
because every one of them keys on the same repo-relative POSIX path. A silent
regression in path resolution does not crash — it produces a graph whose
compliance evidence quietly disappears, or (worse) one that invents evidence by
binding a bare basename to the wrong file.

These tests cover the pure decision logic: the graph accumulator's dedupe and
referential-integrity rules, path/test classification, the CI-glob translation,
control-id normalisation, and the three-tier token resolver including its
ambiguity guards. ``parse_history`` is exercised against a real throwaway git
repository because its rename and binary-numstat handling only exists to cope
with real ``git log --numstat`` output.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _kg_common import load_kg_module

extract = load_kg_module("extract")


@pytest.fixture(autouse=True)
def _clean_graph(monkeypatch):
    """``extract`` accumulates into module-level singletons; reset them so each
    test starts from an empty graph and cold caches."""
    monkeypatch.setattr(extract, "G", extract.Graph())
    monkeypatch.setattr(extract, "_BASENAME_INDEX", {})
    monkeypatch.setattr(extract, "_DOC_SCOPE", {})


def _files(*paths: str) -> None:
    for path in paths:
        extract.G.node("File", path, path=path)


# --------------------------------------------------------------------------- #
# Graph accumulator
# --------------------------------------------------------------------------- #
def test_node_merges_repeated_keys_instead_of_duplicating():
    extract.G.node("File", "a.py", language="Python")
    extract.G.node("File", "a.py", sealed=True)

    assert len(extract.G.nodes) == 1
    assert extract.G.nodes[("File", "a.py")]["props"] == {"language": "Python", "sealed": True}


def test_node_ignores_none_props_so_a_later_layer_cannot_erase_an_earlier_one():
    extract.G.node("File", "a.py", summary="from semantic layer")
    extract.G.node("File", "a.py", summary=None)

    assert extract.G.nodes[("File", "a.py")]["props"]["summary"] == "from semantic layer"


def test_node_accumulates_extra_labels_across_layers():
    extract.G.node("File", "a.py", ("Document",))
    extract.G.node("File", "a.py", ("Config",))

    assert extract.G.nodes[("File", "a.py")]["extra"] == {"Document", "Config"}


def test_rel_is_dropped_when_either_endpoint_is_missing():
    """Referential integrity: a relationship to a node that was never created
    would fail the MERGE in load.py, so it is refused at build time."""
    _files("a.py")

    assert extract.G.rel("IMPORTS", "File", "a.py", "File", "ghost.py") is None
    assert extract.G.rel("IMPORTS", "File", "ghost.py", "File", "a.py") is None
    assert extract.G.rels == {}


def test_rel_merges_repeats_and_keeps_non_none_props():
    _files("a.py", "b.py")
    extract.G.rel("IMPORTS", "File", "a.py", "File", "b.py", weight=1)
    extract.G.rel("IMPORTS", "File", "a.py", "File", "b.py", weight=None, count=2)

    assert len(extract.G.rels) == 1
    slot = extract.G.rels[("IMPORTS", "File", "a.py", "File", "b.py")]
    assert slot["props"] == {"weight": 1, "count": 2}


def test_has_reports_membership():
    _files("a.py")

    assert extract.G.has("File", "a.py")
    assert not extract.G.has("File", "b.py")
    assert not extract.G.has("Symbol", "a.py")


def test_dump_emits_sorted_extra_labels_for_deterministic_output():
    extract.G.node("File", "a.py", ("Service", "Config", "Document"))
    _files("b.py")
    extract.G.rel("LINKS_TO", "File", "a.py", "File", "b.py")

    dumped = extract.G.dump()

    node = next(n for n in dumped["nodes"] if n["key"] == "a.py")
    assert node["extra"] == ["Config", "Document", "Service"]
    assert dumped["rels"][0]["type"] == "LINKS_TO"


# --------------------------------------------------------------------------- #
# Path classification
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path",
    [
        "tests/test_thing.py",
        "packages/gove-zone/tests/test_policy.py",
        "src/test/helpers.py",
        "pkg/foo_test.py",
        "acgi-ai/src/App.test.tsx",
        "acgi-ai/src/App.spec.ts",
    ],
)
def test_is_test_path_recognises_every_convention_in_the_workspace(path):
    assert extract.is_test_path(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "src/gove_zone/policy.py",
        "docs/testing.md",
        "packages/latest/main.py",
        "contest/app.py",
    ],
)
def test_is_test_path_does_not_fire_on_substring_lookalikes(path):
    assert extract.is_test_path(path) is False


def test_is_test_path_matches_a_top_level_tests_directory():
    """The check prefixes a '/' precisely so a repo-root `tests/` still counts."""
    assert extract.is_test_path("tests/conftest.py") is True


# --------------------------------------------------------------------------- #
# File spine
# --------------------------------------------------------------------------- #
def test_build_spine_marks_an_unstaged_tracked_deletion_as_absent(tmp_path, monkeypatch):
    """REGRESSION. `git ls-files` still lists a tracked file whose unstaged
    deletion removed it from the working tree; hard-coding present=True let
    file_is_live() keep resolving citations to the deleted file, so compliance
    reports counted deleted source as live Tier B evidence."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    monkeypatch.setattr(extract, "run", lambda *a: "live.py\ngone.py\n")
    monkeypatch.setattr(extract, "initialized_submodules", lambda: [])
    (tmp_path / "live.py").write_text("x = 1\n")

    extract.build_spine()

    assert extract.G.nodes[("File", "live.py")]["props"]["present"] is True
    assert extract.G.nodes[("File", "gone.py")]["props"]["present"] is False


# --------------------------------------------------------------------------- #
# Semantic-layer reference mapping
# --------------------------------------------------------------------------- #
def test_ua_ref_prefers_the_file_spine_join_key():
    assert extract.ua_ref("ua-1", {"ua-1": "function"}, {"ua-1": "src/a.py"}) == (
        "File",
        "src/a.py",
    )


@pytest.mark.parametrize("ua_type", ["function", "class"])
def test_ua_ref_maps_code_nodes_to_symbols(ua_type):
    assert extract.ua_ref("ua-2", {"ua-2": ua_type}, {}) == ("Symbol", "ua-2")


def test_ua_ref_maps_endpoints():
    assert extract.ua_ref("ua-3", {"ua-3": "endpoint"}, {}) == ("Endpoint", "ua-3")


def test_ua_ref_returns_none_for_unmappable_types():
    assert extract.ua_ref("ua-4", {"ua-4": "concept"}, {}) is None
    assert extract.ua_ref("unknown", {}, {}) is None


def test_build_semantic_records_filesystem_presence_for_snapshot_only_paths(
    tmp_path, monkeypatch
):
    """REGRESSION. A semantic snapshot predating a file deletion minted a File
    node with present=True for a path that is neither tracked nor on disk, so
    a control citing deleted source could still be reported as implemented."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "live.py").write_text("x = 1\n")
    ua = tmp_path / "knowledge-graph.json"
    ua.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "n1", "type": "file", "filePath": "live.py", "name": "live.py"},
                    {"id": "n2", "type": "file", "filePath": "gone.py", "name": "gone.py"},
                ],
                "edges": [],
            }
        )
    )
    monkeypatch.setattr(extract, "UA_GRAPH", ua)

    extract.build_semantic("snap")

    assert extract.G.nodes[("File", "live.py")]["props"]["present"] is True
    assert extract.G.nodes[("File", "gone.py")]["props"]["present"] is False


def test_semantic_snapshot_props_ignores_metadata_when_the_graph_artifact_is_absent(
    tmp_path, monkeypatch
):
    """REGRESSION. meta.json can outlive a deleted knowledge-graph.json, and
    the snapshot recorded its commit — potentially even marking the layer
    current — although build_semantic() skipped and loaded no semantic nodes.
    Availability must be derived from the artifact actually ingested."""
    monkeypatch.setattr(extract, "UA_GRAPH", tmp_path / "knowledge-graph.json")
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"gitCommitHash": "abc", "analyzedFiles": 10}))
    monkeypatch.setattr(extract, "UA_META", meta)

    assert extract.semantic_snapshot_props("abc") == {"semantic_layer_loaded": False}


def test_semantic_snapshot_props_marks_a_graph_without_metadata_as_loaded_but_stale(
    tmp_path, monkeypatch
):
    """The converse gap: a present graph with missing metadata IS loaded, but
    its commit is unknown — it must publish as loaded and stale, not absent."""
    graph = tmp_path / "knowledge-graph.json"
    graph.write_text("{}")
    monkeypatch.setattr(extract, "UA_GRAPH", graph)
    monkeypatch.setattr(extract, "UA_META", tmp_path / "meta.json")

    props = extract.semantic_snapshot_props("abc")

    assert props["semantic_layer_loaded"] is True
    assert props["ua_commit"] is None
    assert props["semantic_layer_is_stale"] is True


def test_semantic_snapshot_props_publishes_metadata_alongside_the_loaded_graph(
    tmp_path, monkeypatch
):
    graph = tmp_path / "knowledge-graph.json"
    graph.write_text("{}")
    monkeypatch.setattr(extract, "UA_GRAPH", graph)
    meta = tmp_path / "meta.json"
    meta.write_text(
        json.dumps({"gitCommitHash": "abc", "lastAnalyzedAt": "2026-08-09", "analyzedFiles": 10})
    )
    monkeypatch.setattr(extract, "UA_META", meta)

    props = extract.semantic_snapshot_props("abc")

    assert props == {
        "semantic_layer_loaded": True,
        "ua_commit": "abc",
        "ua_analyzed_at": "2026-08-09",
        "ua_analyzed_files": 10,
        "semantic_layer_is_stale": False,
    }
    assert extract.semantic_snapshot_props("other")["semantic_layer_is_stale"] is True


# --------------------------------------------------------------------------- #
# CI path-gate globs
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("glob", "matches", "misses"),
    [
        ("tests/**", ["tests/a.py", "tests/deep/b.py"], ["src/a.py"]),
        ("**/*.yml", ["a.yml", "x/y/a.yml"], ["a.yaml"]),
        ("src/*.py", ["src/a.py"], ["src/deep/a.py", "src/a.pyi"]),
        ("a?.py", ["ab.py"], ["a/b.py", "abc.py"]),
        ("docs/plan.md", ["docs/plan.md"], ["docsXplan.md"]),
    ],
)
def test_glob_to_regex_translates_workflow_path_filters(glob, matches, misses):
    pattern = extract.glob_to_regex(glob)

    for path in matches:
        assert pattern.match(path), f"{glob!r} should match {path!r}"
    for path in misses:
        assert not pattern.match(path), f"{glob!r} should not match {path!r}"


def test_glob_to_regex_escapes_regex_metacharacters_in_literals():
    """A '.' in a workflow filter is a literal dot, not 'any character'."""
    pattern = extract.glob_to_regex("a.py")

    assert pattern.match("a.py")
    assert not pattern.match("axpy")


def test_glob_to_regex_is_fully_anchored():
    pattern = extract.glob_to_regex("src/a.py")

    assert not pattern.match("vendor/src/a.py")
    assert not pattern.match("src/a.py.bak")


def test_glob_to_regex_double_star_prefix_also_matches_the_root_level():
    assert extract.glob_to_regex("**/x.py").match("x.py")


def test_negative_path_filters_exclude_explicitly_negated_paths():
    """REGRESSION. `!` patterns were discarded before matching, so files a
    workflow explicitly excludes (e.g. `acgi-ai/infra/**`) still received
    GATES edges and the governance reports claimed CI coverage that will
    never run for those changes."""
    filters = extract.compile_path_filters(
        ["acgi-ai/**", "!acgi-ai/infra/**", "!acgi-ai/DEPLOY.md"]
    )

    assert extract.match_path_filters("acgi-ai/src/App.tsx", filters) is True
    assert extract.match_path_filters("acgi-ai/infra/main.tf", filters) is False
    assert extract.match_path_filters("acgi-ai/DEPLOY.md", filters) is False


def test_path_filters_are_evaluated_in_order_with_the_last_match_winning():
    """GitHub Actions semantics: a positive pattern after a negative one
    re-includes the path."""
    filters = extract.compile_path_filters(["src/**", "!src/vendor/**", "src/vendor/keep.py"])

    assert extract.match_path_filters("src/vendor/keep.py", filters) is True
    assert extract.match_path_filters("src/vendor/other.py", filters) is False
    assert extract.match_path_filters("unrelated.py", filters) is False


def test_build_workflows_applies_negative_filters_when_minting_gates_edges(
    tmp_path, monkeypatch
):
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "marketing.yml").write_text(
        "name: marketing\n"
        "on:\n"
        "  push:\n"
        "    paths:\n"
        "      - 'acgi-ai/**'\n"
        "      - '!acgi-ai/infra/**'\n"
        "jobs:\n"
        "  build:\n"
        "    steps: []\n"
    )
    _files(".github/workflows/marketing.yml", "acgi-ai/src/App.tsx", "acgi-ai/infra/main.tf")

    extract.build_workflows(["acgi-ai/src/App.tsx", "acgi-ai/infra/main.tf"])

    assert ("GATES", "Workflow", "marketing", "File", "acgi-ai/src/App.tsx") in extract.G.rels
    assert (
        "GATES",
        "Workflow",
        "marketing",
        "File",
        "acgi-ai/infra/main.tf",
    ) not in extract.G.rels


def test_build_workflows_preserves_the_triggering_event_on_each_gates_edge(
    tmp_path, monkeypatch
):
    """REGRESSION. Push and pull_request filter lists were collapsed with
    any(), so a deploy workflow whose push filter matches ordinary source
    paths was reported as PR coverage for those paths."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "name: deploy\n"
        "on:\n"
        "  push:\n"
        "    paths:\n"
        "      - 'packages/analyzer/**'\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'deploy/**'\n"
        "jobs:\n"
        "  build:\n"
        "    steps: []\n"
    )
    _files(".github/workflows/deploy.yml", "packages/analyzer/main.py", "deploy/chart.yaml")

    extract.build_workflows(["packages/analyzer/main.py", "deploy/chart.yaml"])

    push_gate = extract.G.rels[
        ("GATES", "Workflow", "deploy", "File", "packages/analyzer/main.py")
    ]
    pr_gate = extract.G.rels[("GATES", "Workflow", "deploy", "File", "deploy/chart.yaml")]
    assert push_gate["props"]["events"] == ["push"]
    assert pr_gate["props"]["events"] == ["pull_request"]


def test_build_workflows_publishes_each_events_filter_list_in_declaration_order(
    tmp_path, monkeypatch
):
    """REGRESSION. Workflow.path_filters is a sorted union across events, so
    when push and pull_request declare different filters the published catalog
    lost both the event association and the pattern order (order decides which
    `!` exclusion wins). Each event's list must also ship verbatim."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "name: deploy\n"
        "on:\n"
        "  push:\n"
        "    paths:\n"
        "      - 'packages/analyzer/**'\n"
        "      - '!packages/analyzer/docs/**'\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'deploy/**'\n"
        "jobs:\n"
        "  build:\n"
        "    steps: []\n"
    )
    _files(".github/workflows/deploy.yml")

    extract.build_workflows([])

    props = extract.G.nodes[("Workflow", "deploy")]["props"]
    assert props["path_filters_push"] == [
        "packages/analyzer/**",
        "!packages/analyzer/docs/**",
    ]
    assert props["path_filters_pull_request"] == ["deploy/**"]


# --------------------------------------------------------------------------- #
# Compliance control ids
# --------------------------------------------------------------------------- #
def _match(framework: str, text: str) -> re.Match:
    pattern = dict(extract.CONTROL_PATTERNS)[framework]
    found = pattern.search(text)
    assert found is not None, f"{framework} pattern did not match {text!r}"
    return found


def test_control_id_normalises_eu_ai_act_articles_with_a_literal():
    assert extract.control_id("EU AI Act", _match("EU AI Act", "Art. 14(4)(d)")) == (
        "EU AI Act Art 14(4)(d)"
    )


def test_control_id_normalises_eu_ai_act_articles_without_a_literal():
    assert extract.control_id("EU AI Act", _match("EU AI Act", "Article 12(1)")) == (
        "EU AI Act Art 12(1)"
    )


def test_control_id_normalises_nist_functions_to_a_single_separator():
    """`MAP 2.3`, `MAP-2.3` and `MAP.2.3` are the same control."""
    ids = {
        extract.control_id("NIST AI RMF", _match("NIST AI RMF", text))
        for text in ("MAP 2.3", "MAP-2.3", "MAP.2.3")
    }

    assert ids == {"NIST AI RMF MAP-2.3"}


@pytest.mark.parametrize(
    ("framework", "text", "expected"),
    [
        ("ISO/IEC 42001", "Annex A.6.2.6", "ISO/IEC 42001 A.6.2.6"),
        ("SOC 2", "CC7.2", "SOC 2 CC7.2"),
        ("HIPAA", "§ 164.312(a)", "HIPAA 164.312(a)"),
    ],
)
def test_control_id_prefixes_single_group_frameworks(framework, text, expected):
    assert extract.control_id(framework, _match(framework, text)) == expected


# --------------------------------------------------------------------------- #
# Link resolution
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "target",
    ["http://example.com/a.py", "https://example.com/a.py", "mailto:hello@acgs.ai"],
)
def test_resolve_link_ignores_external_targets(target):
    _files("a.py")

    assert extract.resolve_link("docs/x.md", target) is None


def test_resolve_link_strips_anchors_and_whitespace():
    _files("docs/plan.md")

    assert extract.resolve_link("docs/x.md", "docs/plan.md#phase-2 ") == "docs/plan.md"


def test_resolve_link_returns_none_for_a_bare_anchor():
    assert extract.resolve_link("docs/x.md", "#section") is None


def test_resolve_link_prefers_repo_root_relative_over_doc_relative():
    """Repo-root-relative is the dominant citation style here; resolving it
    against the citing document's directory would yield `docs/packages/...`."""
    _files("packages/gove-zone/src/gove_zone/receipt.py")

    assert (
        extract.resolve_link("docs/compliance.md", "packages/gove-zone/src/gove_zone/receipt.py")
        == "packages/gove-zone/src/gove_zone/receipt.py"
    )


def test_resolve_link_falls_back_to_doc_relative():
    _files("docs/adr/0001-thing.md")

    assert extract.resolve_link("docs/index.md", "adr/0001-thing.md") == "docs/adr/0001-thing.md"


def test_resolve_link_normalises_parent_traversal():
    _files("scripts/build.py")

    assert extract.resolve_link("docs/index.md", "../scripts/build.py") == "scripts/build.py"


def test_resolve_link_treats_a_leading_slash_as_repo_root():
    _files("Makefile")

    assert extract.resolve_link("docs/deep/x.md", "/Makefile") == "Makefile"


def test_resolve_link_normalises_windows_separators():
    _files("docs/plan.md")

    assert extract.resolve_link("docs/x.md", "docs\\plan.md") == "docs/plan.md"


def test_resolve_link_returns_none_when_the_target_is_not_tracked():
    _files("a.py")

    assert extract.resolve_link("docs/x.md", "does/not/exist.py") is None


def test_resolve_link_excludes_files_recorded_as_absent():
    """A semantic-only node for a deleted path must not resolve as live
    evidence: it is neither tracked nor on disk."""
    extract.G.node("File", "gone.py", path="gone.py", present=False)

    assert extract.resolve_link("docs/x.md", "gone.py") is None


# --------------------------------------------------------------------------- #
# Token resolution (path / basename / doc-scope tiers)
# --------------------------------------------------------------------------- #
def test_resolve_token_reports_an_explicit_path_as_the_strongest_tier():
    _files("packages/gove-zone/src/gove_zone/receipt.py")

    assert extract.resolve_token("docs/x.md", "packages/gove-zone/src/gove_zone/receipt.py") == (
        "packages/gove-zone/src/gove_zone/receipt.py",
        None,
        "path",
    )


def test_resolve_token_extracts_a_trailing_line_number():
    _files("src/receipt.py")

    assert extract.resolve_token("docs/x.md", "src/receipt.py:139") == (
        "src/receipt.py",
        139,
        "path",
    )


def test_code_token_captures_the_line_suffix_inside_the_token():
    """REGRESSION. The `:line` suffix sat outside the capture group, so
    findall() returned only `receipt.py` and every EVIDENCED_BY.cited_line
    was None; range citations failed to match at all."""
    text = "see `receipt.py:141`, `receipt.py:132\u2013133`, `plain.py:10-12` and `audit.py`"

    assert extract.CODE_TOKEN.findall(text) == [
        "receipt.py:141",
        "receipt.py:132\u2013133",
        "plain.py:10-12",
        "audit.py",
    ]


@pytest.mark.parametrize("token", ["src/receipt.py:132\u2013133", "src/receipt.py:132-133"])
def test_resolve_token_reads_a_line_range_as_its_starting_line(token):
    _files("src/receipt.py")

    assert extract.resolve_token("docs/x.md", token) == ("src/receipt.py", 132, "path")


def test_resolve_token_gives_up_on_an_unresolvable_explicit_path():
    """A token containing '/' is a path claim; falling back to basename lookup
    would resolve it to an unrelated file."""
    _files("src/receipt.py")

    assert extract.resolve_token("docs/x.md", "other/receipt.py") == (None, None, None)


def test_resolve_token_accepts_a_basename_that_is_unique_in_the_workspace():
    _files("packages/gove-zone/src/gove_zone/receipt.py")

    assert extract.resolve_token("docs/x.md", "receipt.py") == (
        "packages/gove-zone/src/gove_zone/receipt.py",
        None,
        "basename",
    )


def test_resolve_token_carries_the_line_number_through_a_basename_hit():
    _files("src/receipt.py")

    assert extract.resolve_token("docs/x.md", "receipt.py:42")[1] == 42


def test_resolve_token_basename_lookup_skips_absent_semantic_only_files():
    """An absent snapshot-only node neither wins the basename lookup nor
    poisons it into ambiguity: only live files count as candidates."""
    extract.G.node("File", "old/receipt.py", path="old/receipt.py", present=False)
    _files("packages/gove-zone/receipt.py")

    assert extract.resolve_token("docs/x.md", "receipt.py") == (
        "packages/gove-zone/receipt.py",
        None,
        "basename",
    )


def test_ambiguous_basename_is_dropped_without_document_context(tmp_path, monkeypatch):
    """Three `receipt.py` files and nothing to disambiguate: recording a
    citation here would invent evidence."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    _files("a/receipt.py", "b/receipt.py", "c/receipt.py")

    assert extract.resolve_token("docs/x.md", "receipt.py") == (None, None, None)


def test_ambiguous_basename_is_disambiguated_by_an_exact_path_named_elsewhere(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("This control is implemented in `packages/gove-zone/receipt.py`.\n")
    _files("packages/gove-zone/receipt.py", "packages/acgs-lite/receipt.py")

    assert extract.resolve_token("docs/compliance.md", "receipt.py") == (
        "packages/gove-zone/receipt.py",
        None,
        "basename-docscope",
    )


def test_ambiguous_basename_falls_back_to_the_package_the_document_is_about(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("See `packages/gove-zone/policy.py` for the enforcement path.\n")
    _files(
        "packages/gove-zone/policy.py",
        "packages/gove-zone/src/receipt.py",
        "packages/acgs-lite/receipt.py",
    )

    assert extract.resolve_token("docs/compliance.md", "receipt.py") == (
        "packages/gove-zone/src/receipt.py",
        None,
        "basename-docscope",
    )


def test_ambiguity_that_survives_doc_scope_is_still_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance.md"
    doc.parent.mkdir(parents=True)
    doc.write_text(
        "Both `packages/gove-zone/a/receipt.py` and `packages/gove-zone/b/receipt.py`.\n"
    )
    _files("packages/gove-zone/a/receipt.py", "packages/gove-zone/b/receipt.py")

    assert extract.resolve_token("docs/compliance.md", "receipt.py") == (None, None, None)


def test_basename_index_drops_nothing_and_is_cached():
    _files("a/x.py", "b/x.py", "only.py")

    index = extract.basename_index()

    assert index["x.py"] == ["a/x.py", "b/x.py"]
    assert index["only.py"] == ["only.py"]
    assert extract.basename_index() is index


def test_doc_scope_collects_both_backticked_paths_and_markdown_links(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "x.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("Code at `src/a.py` and the [plan](docs/plan.md).\n")
    _files("src/a.py", "docs/plan.md")

    assert extract.doc_scope("docs/x.md") == {"src/a.py", "docs/plan.md"}


def test_doc_scope_of_a_missing_file_is_empty_and_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)

    assert extract.doc_scope("docs/gone.md") == set()
    assert "docs/gone.md" in extract._DOC_SCOPE


# --------------------------------------------------------------------------- #
# Git history parsing
# --------------------------------------------------------------------------- #
def _git(repo, *args: str) -> None:
    # Resolve git from the ambient PATH but run it under a scrubbed environment:
    # hardcoding a PATH here would break on a runner whose git lives elsewhere,
    # while inheriting the environment would let the developer's global git
    # config change what these tests observe.
    git_bin = shutil.which("git")
    assert git_bin, "git is required for the history-parsing tests"
    subprocess.run(
        [git_bin, *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(repo),
            "GIT_AUTHOR_NAME": "Test Author",
            "GIT_AUTHOR_EMAIL": "author@example.com",
            "GIT_COMMITTER_NAME": "Test Author",
            "GIT_COMMITTER_EMAIL": "author@example.com",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        },
    )


@pytest.fixture
def git_repo(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.py").write_text("one\ntwo\n")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-qm", "first commit")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    return repo


def test_parse_history_reads_commit_metadata_and_numstat(git_repo):
    commits = extract.parse_history("repo")

    assert len(commits) == 1
    commit = commits[0]
    assert commit["subject"] == "first commit"
    assert commit["author"] == "Test Author"
    assert commit["email"] == "author@example.com"
    assert commit["repo"] == "repo"
    assert commit["files"] == {"a.py": (2, 0)}
    assert isinstance(commit["ts"], int)


def test_parse_history_prefixes_submodule_paths_onto_the_parent_spine(git_repo):
    """Submodules are separate histories; without the prefix every submodule
    fact would key on a path the parent spine does not contain."""
    commits = extract.parse_history("repo", prefix="packages/thing/")

    assert commits[0]["files"] == {"packages/thing/a.py": (2, 0)}


def test_parse_history_follows_renames_to_the_new_path(git_repo):
    _git(git_repo, "mv", "a.py", "b.py")
    _git(git_repo, "commit", "-qm", "rename")

    latest = extract.parse_history("repo")[0]

    assert latest["subject"] == "rename"
    assert list(latest["files"]) == ["b.py"]


def test_parse_history_follows_directory_renames(git_repo):
    (git_repo / "pkg").mkdir()
    _git(git_repo, "mv", "a.py", "pkg/a.py")
    _git(git_repo, "commit", "-qm", "move into pkg")

    latest = extract.parse_history("repo")[0]

    assert list(latest["files"]) == ["pkg/a.py"]


def test_parse_history_attributes_pre_rename_commits_to_the_live_path(git_repo):
    """REGRESSION. Rewriting only the rename commit's numstat path left every
    older commit keyed on the origin path, which build_history() drops because
    it is absent from the live spine: the advertised full-history churn and
    commit counts silently excluded everything before a rename."""
    (git_repo / "a.py").write_text("one\ntwo\nthree\n")
    _git(git_repo, "commit", "-aqm", "grow")
    _git(git_repo, "mv", "a.py", "b.py")
    _git(git_repo, "commit", "-qm", "rename")

    commits = extract.parse_history("repo")

    assert len(commits) == 3
    assert all(list(c["files"]) == ["b.py"] for c in commits)


def test_parse_history_collapses_chained_renames_onto_the_final_path(git_repo):
    _git(git_repo, "mv", "a.py", "b.py")
    _git(git_repo, "commit", "-qm", "first rename")
    _git(git_repo, "mv", "b.py", "c.py")
    _git(git_repo, "commit", "-qm", "second rename")

    commits = extract.parse_history("repo")

    assert all(list(c["files"]) == ["c.py"] for c in commits)


def test_parse_history_carries_directory_rename_ancestry(git_repo):
    (git_repo / "pkg").mkdir()
    _git(git_repo, "mv", "a.py", "pkg/a.py")
    _git(git_repo, "commit", "-qm", "move into pkg")

    oldest = extract.parse_history("repo")[-1]

    assert oldest["subject"] == "first commit"
    assert list(oldest["files"]) == ["pkg/a.py"]


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("old.py => new.py", ("old.py", "new.py")),
        ("a/{old => new}/c.py", ("a/old/c.py", "a/new/c.py")),
        ("dir/{ => sub}/f.py", ("dir/f.py", "dir/sub/f.py")),
        ("dir/{sub => }/f.py", ("dir/sub/f.py", "dir/f.py")),
    ],
)
def test_split_rename_reconstructs_both_sides_of_every_numstat_shape(record, expected):
    assert extract.split_rename(record) == expected


def test_parse_history_records_binary_numstat_as_zero_churn(git_repo):
    (git_repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01\x02")
    _git(git_repo, "add", "logo.png")
    _git(git_repo, "commit", "-qm", "add binary")

    latest = extract.parse_history("repo")[0]

    assert latest["files"]["logo.png"] == (0, 0)


def test_parse_history_returns_empty_for_a_non_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "not-a-repo").mkdir()

    assert extract.parse_history("not-a-repo") == []


def test_initialized_submodules_skips_uninitialised_gitlinks(monkeypatch):
    """A leading '-' in `git submodule status` means registered but empty."""
    monkeypatch.setattr(
        extract,
        "run",
        lambda *a: (
            " abc123 packages/acgs-lite (v2.10.1)\n"
            "-def456 packages/ACGS-agency-agents\n"
            "+789abc packages/Acgs-Swarm (heads/main)\n"
        ),
    )

    assert extract.initialized_submodules() == ["packages/acgs-lite", "packages/Acgs-Swarm"]


def test_initialized_submodules_tolerates_a_git_failure(monkeypatch):
    def _boom(*args: str) -> str:
        raise subprocess.CalledProcessError(128, args)

    monkeypatch.setattr(extract, "run", _boom)

    assert extract.initialized_submodules() == []


def test_build_history_counts_contributors_by_the_graphs_stable_author_key():
    """REGRESSION. author_count accumulated display names while Author nodes
    key on email, so one identity that changed its name (hello@acgs.ai has
    commits as both MartinLyu and dislovelhl) counted as two contributors,
    inflating the count and hiding the file from the single-author bus-factor
    query (Q11)."""
    _files("packages/gove-zone/src/gove_zone/sandbox.py")
    commit = {
        "sha": "a" * 40,
        "ts": 1_700_000_000,
        "subject": "x",
        "repo": ".",
        "files": {"packages/gove-zone/src/gove_zone/sandbox.py": (1, 0)},
    }

    extract.build_history(
        [
            {**commit, "author": "MartinLyu", "email": "hello@acgs.ai"},
            {**commit, "sha": "b" * 40, "author": "dislovelhl", "email": "hello@acgs.ai"},
        ]
    )

    props = extract.G.nodes[("File", "packages/gove-zone/src/gove_zone/sandbox.py")]["props"]
    assert props["commit_count"] == 2
    assert props["author_count"] == 1


# --------------------------------------------------------------------------- #
# Dirty-path snapshot parsing
# --------------------------------------------------------------------------- #
def test_porcelain_paths_selects_the_destination_of_a_rename():
    """REGRESSION. Slicing the space-separated v1 line at character three
    turned a rename record into `old.py -> new.py`, a key matching no File
    node, so the renamed destination never received dirty_at_extract and Q7
    silently omitted ADRs governing that changed file."""
    raw = "R  new.py\0old.py\0 M other.py\0?? untracked.txt\0"

    assert extract.porcelain_paths(raw) == ["new.py", "other.py", "untracked.txt"]


def test_porcelain_paths_reads_nul_terminated_paths_with_spaces_unquoted():
    raw = "?? some dir/a file.txt\0M  src/plain.py\0"

    assert extract.porcelain_paths(raw) == ["some dir/a file.txt", "src/plain.py"]


def test_porcelain_paths_handles_copies_and_empty_output():
    assert extract.porcelain_paths("") == []
    assert extract.porcelain_paths("C  copy.py\0original.py\0") == ["copy.py"]


def test_collect_dirty_paths_descends_into_initialized_submodules(monkeypatch):
    """REGRESSION. The parent porcelain reports a change inside a submodule
    only as the gitlink path, so the inner file never received
    dirty_at_extract and Q7 omitted ADRs governing that change."""
    monkeypatch.setattr(extract, "run", lambda *a: " M packages/acgs-lite\0 M top.py\0")
    monkeypatch.setattr(extract, "initialized_submodules", lambda: ["packages/acgs-lite"])

    class _Proc:
        returncode = 0
        stdout = " M src/receipt.py\0R  new.py\0old.py\0"

    monkeypatch.setattr(extract.subprocess, "run", lambda *a, **k: _Proc())

    assert extract.collect_dirty_paths() == [
        "packages/acgs-lite",
        "top.py",
        "packages/acgs-lite/src/receipt.py",
        "packages/acgs-lite/new.py",
    ]


def test_collect_dirty_paths_tolerates_a_failing_submodule_status(monkeypatch):
    monkeypatch.setattr(extract, "run", lambda *a: " M top.py\0")
    monkeypatch.setattr(extract, "initialized_submodules", lambda: ["packages/acgs-lite"])

    class _Proc:
        returncode = 128
        stdout = ""

    monkeypatch.setattr(extract.subprocess, "run", lambda *a, **k: _Proc())

    assert extract.collect_dirty_paths() == ["top.py"]


# --------------------------------------------------------------------------- #
# Topology
# --------------------------------------------------------------------------- #
def test_build_topology_assigns_a_gitlink_file_to_its_own_submodule_package(
    tmp_path, monkeypatch
):
    """REGRESSION. A submodule gitlink's File key equals the package path with
    no trailing segment, so the prefix-only predicate assigned every gitlink —
    and its pointer-change history — to the workspace root package."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / ".gitmodules").write_text(
        '[submodule "acgs-lite"]\n'
        "\tpath = packages/acgs-lite\n"
        "\turl = git@example.com:acgs-lite.git\n"
    )
    monkeypatch.setattr(extract, "run", lambda *a: "-abc123 packages/acgs-lite\n")
    _files("packages/acgs-lite")

    extract.build_topology([])

    assert (
        extract.G.nodes[("File", "packages/acgs-lite")]["props"]["package"]
        == "packages/acgs-lite"
    )
    assert (
        "IN_PACKAGE",
        "File",
        "packages/acgs-lite",
        "Package",
        "packages/acgs-lite",
    ) in extract.G.rels


# --------------------------------------------------------------------------- #
# Sealed constitutional-hash markers
# --------------------------------------------------------------------------- #
def test_hash_marker_is_imported_from_the_gate():
    """The extractor must share the gate's marker syntax, never keep a
    narrower copy that drifts the day the gate changes."""
    import verify_constitutional_hashes

    assert extract.HASH_MARKER is verify_constitutional_hashes.MARKER_RE


def test_build_sealed_accepts_the_gate_marker_syntax_including_uppercase_hex(
    tmp_path, monkeypatch
):
    """REGRESSION. A local lowercase-only regex recorded files the real
    constitutional-hash gate accepts — uppercase markers are pinned valid by
    tests/test_verify_constitutional_hashes.py — as unsealed, so Q3 and the
    governance reports silently omitted them."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "sealed.md").write_text("Constitutional Hash: `DEADBEEFCAFEBABE`\n")
    _files("sealed.md")

    extract.build_sealed(["sealed.md"])

    props = extract.G.nodes[("File", "sealed.md")]["props"]
    assert props["sealed"] is True
    assert props["sealed_hash"] == "DEADBEEFCAFEBABE"
    assert ("SEALED_WITH", "File", "sealed.md", "Hash", "DEADBEEFCAFEBABE") in extract.G.rels


def _lock(tmp_path, hashes: dict[str, str]) -> None:
    lock_dir = tmp_path / "docs"
    lock_dir.mkdir(exist_ok=True)
    (lock_dir / "constitutional-hashes.lock").write_text(json.dumps({"hashes": hashes}))


def test_build_sealed_keeps_the_live_marker_when_the_lock_pins_a_different_hash(
    tmp_path, monkeypatch
):
    """REGRESSION. When a checked-out sealed file's marker differs from
    docs/constitutional-hashes.lock — the exact drift this graph exists to
    expose — the lock pass overwrote the live marker in sealed_hash, so Q3
    displayed the pinned value while sealed_source still said working-tree.
    The observed and pinned values must stay separate, with the mismatch
    recorded."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "sealed.md").write_text("Constitutional Hash: `deadbeefcafebabe`\n")
    _lock(tmp_path, {"sealed.md": "0123456789abcdef"})
    _files("sealed.md")

    extract.build_sealed(["sealed.md"])

    props = extract.G.nodes[("File", "sealed.md")]["props"]
    assert props["sealed_hash"] == "deadbeefcafebabe"
    assert props["sealed_source"] == "working-tree"
    assert props["pinned_hash"] == "0123456789abcdef"
    assert props["hash_drift"] is True
    assert ("SEALED_WITH", "File", "sealed.md", "Hash", "deadbeefcafebabe") in extract.G.rels
    assert ("SEALED_WITH", "File", "sealed.md", "Hash", "0123456789abcdef") in extract.G.rels


def test_build_sealed_records_no_drift_when_lock_and_marker_agree(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "sealed.md").write_text("Constitutional Hash: `deadbeefcafebabe`\n")
    _lock(tmp_path, {"sealed.md": "deadbeefcafebabe"})
    _files("sealed.md")

    extract.build_sealed(["sealed.md"])

    props = extract.G.nodes[("File", "sealed.md")]["props"]
    assert props["sealed_hash"] == "deadbeefcafebabe"
    assert props["pinned_hash"] == "deadbeefcafebabe"
    assert props["hash_drift"] is False


def test_build_sealed_seals_a_marker_less_file_from_the_lock_pin(tmp_path, monkeypatch):
    """With no live marker observed, the pin is the only hash — and the source
    must say so instead of implying the value was seen in the working tree."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "plain.md").write_text("no marker here\n")
    _lock(tmp_path, {"plain.md": "0123456789abcdef"})
    _files("plain.md")

    extract.build_sealed(["plain.md"])

    props = extract.G.nodes[("File", "plain.md")]["props"]
    assert props["sealed"] is True
    assert props["sealed_hash"] == "0123456789abcdef"
    assert props["sealed_source"] == "hash-lock"
    assert props["pinned_hash"] == "0123456789abcdef"
    assert "hash_drift" not in props


# --------------------------------------------------------------------------- #
# ADR layer
# --------------------------------------------------------------------------- #
def test_build_adrs_extracts_title_status_and_date(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0007-thing.md").write_text(
        "# 0007. A governed thing\n\n## Status\n\nAccepted\n\n## Date\n\n2026-08-09\n"
    )
    _files("docs/adr/0007-thing.md")

    extract.build_adrs()

    node = extract.G.nodes[("ADR", "ADR-0007")]["props"]
    assert node["title"] == "0007. A governed thing"
    assert node["status"] == "Accepted"
    assert node["date"] == "2026-08-09"
    assert ("DOCUMENTED_IN", "ADR", "ADR-0007", "File", "docs/adr/0007-thing.md") in extract.G.rels


def test_build_adrs_records_supersession_in_one_direction(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0001-old.md").write_text(
        "# 0001. Old\n\n## Status\n\nSuperseded by ADR-0002\n\n## Context\n\nx\n"
    )
    (adr_dir / "0002-new.md").write_text(
        "# 0002. New\n\n## Status\n\nAccepted\n\nSupersedes ADR-0001\n"
    )
    _files("docs/adr/0001-old.md", "docs/adr/0002-new.md")

    extract.build_adrs()

    assert extract.G.nodes[("ADR", "ADR-0001")]["props"]["status"] == "Superseded"
    assert ("SUPERSEDES", "ADR", "ADR-0002", "ADR", "ADR-0001") in extract.G.rels
    assert ("SUPERSEDES", "ADR", "ADR-0001", "ADR", "ADR-0002") not in extract.G.rels


@pytest.mark.parametrize(
    "tail",
    [
        "## Status\n\nAccepted\n",  # trailing newline, no blank line
        "## Status\n\nAccepted",  # no trailing newline at all
        "## Status\n\nAccepted\n\n",  # blank line, then EOF
    ],
)
def test_build_adrs_reads_a_status_section_that_ends_the_file(tmp_path, monkeypatch, tail):
    """REGRESSION. A section terminates at a blank line, the next heading, or
    end of file. The third alternative was missing, so an ADR whose Status was
    its last section parsed as "Unknown" — a silent field loss, not an error.
    Real ADRs in docs/adr/ always have sections after Status, which is why it
    never surfaced; a generator emitting Status last would have hit it.
    """
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0009-eof.md").write_text(f"# 0009. Ends at status\n\n{tail}")
    _files("docs/adr/0009-eof.md")

    extract.build_adrs()

    assert extract.G.nodes[("ADR", "ADR-0009")]["props"]["status"] == "Accepted"


@pytest.mark.parametrize(
    "body",
    [
        "## Status\n\n## Context\n\nProposed alternatives were weighed.\n",  # empty section
        "## Status\n   \n## Context\n\nProposed alternatives were weighed.\n",  # whitespace only
    ],
)
def test_build_adrs_does_not_fabricate_status_text_from_the_next_heading(
    tmp_path, monkeypatch, body
):
    """REGRESSION. An empty Status section runs straight into the next heading,
    so the capture held that heading's text and it was published verbatim as
    ``ADR.status_text``. The derived ``status`` was "Unknown" either way — the
    corruption was in the text field, i.e. fabricated metadata rather than a
    wrong verdict. Note the neighbouring section deliberately contains the word
    "Proposed": had the heading text been captured, the status keyword scan
    would have had live text to match against.
    """
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0011-empty.md").write_text(f"# 0011. Empty status\n\n{body}")
    _files("docs/adr/0011-empty.md")

    extract.build_adrs()

    props = extract.G.nodes[("ADR", "ADR-0011")]["props"]
    assert props["status"] == "Unknown"
    assert props["status_text"] == "Unknown"
    assert "##" not in props["status_text"]
    assert "Context" not in props["status_text"]


def test_build_adrs_does_not_swallow_the_following_section_into_status(tmp_path, monkeypatch):
    """The end-of-file alternative must not make the match greedy: a Status
    followed by another heading still stops at that heading."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0010-x.md").write_text(
        "# 0010. X\n\n## Status\n\nAccepted\n## Context\n\nProposed alternatives were weighed.\n"
    )
    _files("docs/adr/0010-x.md")

    extract.build_adrs()

    props = extract.G.nodes[("ADR", "ADR-0010")]["props"]
    assert props["status"] == "Accepted"
    assert "alternatives" not in props["status_text"]


def test_build_adrs_reads_a_list_style_status(tmp_path, monkeypatch):
    """REGRESSION. ADRs using the repository's list-style metadata (e.g.
    docs/adr/0008: `- Status: Accepted`) were recorded as Unknown because only
    a `## Status` heading was recognised, so Q7/Q7b misreported them."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0008-authz.md").write_text(
        "# 0008. Kernel-side principal authz enforcement\n\n"
        "- Status: Accepted\n"
        "- Date: 2026-08-09\n\n"
        "## Context\n\nx\n"
    )
    _files("docs/adr/0008-authz.md")

    extract.build_adrs()

    props = extract.G.nodes[("ADR", "ADR-0008")]["props"]
    assert props["status"] == "Accepted"
    assert props["status_text"] == "Accepted"


def test_build_adrs_reads_a_list_style_date(tmp_path, monkeypatch):
    """REGRESSION. The list-style metadata block pairs `- Status:` with
    `- Date:` (docs/adr/0008: `- Date: 2026-06-23`), but only a `## Date`
    heading was recognised: the corrected status was extracted while the date
    from the very same block was silently dropped."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0008-authz.md").write_text(
        "# 0008. Kernel-side principal authz enforcement\n\n"
        "- Status: Accepted\n"
        "- Date: 2026-06-23\n\n"
        "## Context\n\nx\n"
    )
    _files("docs/adr/0008-authz.md")

    extract.build_adrs()

    assert extract.G.nodes[("ADR", "ADR-0008")]["props"]["date"] == "2026-06-23"


def test_build_adrs_defaults_unknown_status(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0003-x.md").write_text("# 0003. X\n\nNo status heading at all.\n")
    _files("docs/adr/0003-x.md")

    extract.build_adrs()

    assert extract.G.nodes[("ADR", "ADR-0003")]["props"]["status"] == "Unknown"


def test_build_adrs_is_a_noop_without_an_adr_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)

    extract.build_adrs()

    assert extract.G.nodes == {}


# --------------------------------------------------------------------------- #
# Control evidence binding
# --------------------------------------------------------------------------- #
def test_build_controls_binds_a_control_to_the_code_cited_beside_it(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("| Art. 12(1) | implemented in `packages/gove-zone/audit.py` |\n")
    _files("docs/compliance-mapping.md", "packages/gove-zone/audit.py")

    extract.build_controls()

    cid = "EU AI Act Art 12(1)"
    assert extract.G.nodes[("Control", cid)]["props"]["framework"] == "EU AI Act"
    assert ("MAPS_TO", "File", "docs/compliance-mapping.md", "Control", cid) in extract.G.rels
    evidence = extract.G.rels[
        ("EVIDENCED_BY", "Control", cid, "File", "packages/gove-zone/audit.py")
    ]
    assert evidence["props"]["resolved_by"] == "path"
    assert extract.CONTROL_STATS["evidence_links"] == 1


def test_build_controls_preserves_the_cited_line_on_the_evidence_edge(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("| Art. 12(1) | implemented in `packages/gove-zone/audit.py:141` |\n")
    _files("docs/compliance-mapping.md", "packages/gove-zone/audit.py")

    extract.build_controls()

    evidence = extract.G.rels[
        ("EVIDENCED_BY", "Control", "EU AI Act Art 12(1)", "File", "packages/gove-zone/audit.py")
    ]
    assert evidence["props"]["cited_line"] == 141


def test_build_controls_records_a_bare_basename_resolution_as_weaker_evidence(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("| CC7.2 | see `audit.py` |\n")
    _files("docs/compliance-mapping.md", "packages/gove-zone/audit.py")

    extract.build_controls()

    evidence = extract.G.rels[
        ("EVIDENCED_BY", "Control", "SOC 2 CC7.2", "File", "packages/gove-zone/audit.py")
    ]
    assert evidence["props"]["resolved_by"] == "basename"
    assert extract.CONTROL_STATS["evidence_by_basename"] == 1


def test_build_controls_refuses_to_bind_evidence_from_an_enumeration(tmp_path, monkeypatch):
    """A sentence listing many control ids is an index, not a binding: citations
    are still recorded, evidence is not."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text(
        "Controls A.2.2, A.3.2 and A.6.2.6 are listed in `packages/gove-zone/audit.py`.\n"
    )
    _files("docs/compliance-mapping.md", "packages/gove-zone/audit.py")

    extract.build_controls()

    assert extract.CONTROL_STATS["enumeration_scopes_skipped"] == 1
    assert extract.CONTROL_STATS["evidence_links"] == 0
    assert any(key[0] == "MAPS_TO" for key in extract.G.rels)
    assert not any(key[0] == "EVIDENCED_BY" for key in extract.G.rels)


def test_build_controls_ignores_documents_without_a_mapping_hint(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "notes.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("Art. 12(1) mentioned in passing.\n")
    _files("docs/notes.md")

    extract.build_controls()

    assert not any(label == "Control" for label, _ in extract.G.nodes)


def test_build_controls_never_binds_a_document_as_its_own_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("| CC7.2 | described in `docs/compliance-mapping.md` |\n")
    _files("docs/compliance-mapping.md")

    extract.build_controls()

    assert not any(key[0] == "EVIDENCED_BY" for key in extract.G.rels)
