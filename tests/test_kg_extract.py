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
    monkeypatch.setattr(extract, "SEALED_STATS", {})


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


def test_build_spine_records_an_initialized_gitlink_as_present(tmp_path, monkeypatch):
    """REGRESSION. A gitlink's checkout is a directory, so Path.is_file()
    recorded every initialized submodule pointer as present=false;
    file_is_live() then rejected it and build_history() silently dropped its
    aggregate pointer-change statistics even though build_topology()
    explicitly assigns the gitlink and its history to the submodule package.
    Gitlink mode (160000) must be detected from the index and presence tested
    as a directory."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)

    def fake_run(*args):
        if args == ("git", "ls-files", "-s"):
            return (
                "100644 aaaa 0\tlive.py\n"
                "160000 bbbb 0\tpackages/swarm\n"
                "160000 cccc 0\tpackages/removed\n"
            )
        return "live.py\npackages/swarm\npackages/removed\n"

    monkeypatch.setattr(extract, "run", fake_run)
    monkeypatch.setattr(extract, "initialized_submodules", lambda: [])
    (tmp_path / "live.py").write_text("x = 1\n")
    (tmp_path / "packages" / "swarm").mkdir(parents=True)

    extract.build_spine()

    gitlink = extract.G.nodes[("File", "packages/swarm")]["props"]
    assert gitlink["is_gitlink"] is True
    assert gitlink["present"] is True
    assert extract.file_is_live("packages/swarm") is True
    # Presence is still derived, never assumed: a gitlink whose directory was
    # removed from the working tree stays absent.
    assert extract.G.nodes[("File", "packages/removed")]["props"]["present"] is False
    # Ordinary files keep the regular-file test.
    assert extract.G.nodes[("File", "live.py")]["props"]["is_gitlink"] is False


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


def test_build_semantic_records_filesystem_presence_for_snapshot_only_paths(tmp_path, monkeypatch):
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
        "semantic_dirty_paths": [],
        "semantic_uncovered_paths": [],
    }
    assert extract.semantic_snapshot_props("other")["semantic_layer_is_stale"] is True


def test_semantic_snapshot_props_marks_dirty_analyzed_files_as_stale(tmp_path, monkeypatch):
    """REGRESSION. A layer generated at the current HEAD still passed the
    commit-equality check after a tracked source file was edited in the
    working tree, so reports called the layer "current" and counted the dirty
    file as analyzed although its summaries and TESTED_BY edges describe the
    committed version. A dirty path with semantic coverage must mark the
    layer stale; dirt the graph never analyzed must not."""
    graph = tmp_path / "knowledge-graph.json"
    graph.write_text(
        json.dumps({"nodes": [{"id": "n1", "type": "file", "filePath": "src/a.py"}], "edges": []})
    )
    monkeypatch.setattr(extract, "UA_GRAPH", graph)
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"gitCommitHash": "abc"}))
    monkeypatch.setattr(extract, "UA_META", meta)

    uncovered = extract.semantic_snapshot_props("abc", ["docs/notes.md"])
    covered = extract.semantic_snapshot_props("abc", ["src/a.py", "docs/notes.md"])

    assert uncovered["semantic_layer_is_stale"] is False
    assert uncovered["semantic_dirty_paths"] == []
    assert covered["semantic_layer_is_stale"] is True
    assert covered["semantic_dirty_paths"] == ["src/a.py"]


def test_semantic_snapshot_props_marks_uncovered_dirty_tracked_code_as_stale(tmp_path, monkeypatch):
    """REGRESSION. Staleness only intersected dirty paths with paths already
    in the snapshot, so a staged new file (or the destination of `git mv`)
    was dirty but absent from `analyzed` and the layer still published
    `semantic_layer_is_stale=False` although the live tracked tree contained
    code the layer never covered. A dirty tracked path of an analyzed file
    type that lacks semantic coverage must mark the layer stale."""
    graph = tmp_path / "knowledge-graph.json"
    graph.write_text(
        json.dumps({"nodes": [{"id": "n1", "type": "file", "filePath": "src/a.py"}], "edges": []})
    )
    monkeypatch.setattr(extract, "UA_GRAPH", graph)
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"gitCommitHash": "abc"}))
    monkeypatch.setattr(extract, "UA_META", meta)

    tracked = ["src/a.py", "src/new.py", "docs/notes.md"]
    props = extract.semantic_snapshot_props("abc", ["src/new.py"], tracked)

    assert props["semantic_layer_is_stale"] is True
    assert props["semantic_uncovered_paths"] == ["src/new.py"]
    assert props["semantic_dirty_paths"] == []


def test_semantic_snapshot_props_ignores_uncovered_dirt_the_analyzer_never_processes(
    tmp_path, monkeypatch
):
    """The uncovered-dirt check is scoped to extensions the snapshot
    demonstrably analyzes: a dirty tracked doc or an untracked scratch file
    says nothing about the semantic layer's currency."""
    graph = tmp_path / "knowledge-graph.json"
    graph.write_text(
        json.dumps({"nodes": [{"id": "n1", "type": "file", "filePath": "src/a.py"}], "edges": []})
    )
    monkeypatch.setattr(extract, "UA_GRAPH", graph)
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"gitCommitHash": "abc"}))
    monkeypatch.setattr(extract, "UA_META", meta)

    doc_dirt = extract.semantic_snapshot_props(
        "abc", ["docs/notes.md"], ["src/a.py", "docs/notes.md"]
    )
    untracked_dirt = extract.semantic_snapshot_props("abc", ["scratch.py"], ["src/a.py"])

    assert doc_dirt["semantic_layer_is_stale"] is False
    assert doc_dirt["semantic_uncovered_paths"] == []
    assert untracked_dirt["semantic_layer_is_stale"] is False
    assert untracked_dirt["semantic_uncovered_paths"] == []


def test_semantic_snapshot_props_treats_a_dirty_gitlink_as_invalidating_descendants(
    tmp_path, monkeypatch
):
    """REGRESSION. An initialized submodule checked out at a different commit
    while the parent HEAD is unchanged is reported by porcelain only as the
    dirty gitlink path (e.g. `packages/acgs-control-plane`). The exact-path
    intersection missed it, and the uncovered check ignored it because a
    gitlink has no analyzed extension, so the layer published as current
    although summaries and TESTED_BY edges for analyzed files beneath the
    submodule can describe another revision. A dirty path must invalidate its
    analyzed descendants; a mere name prefix without the `/` boundary must
    not."""
    graph = tmp_path / "knowledge-graph.json"
    graph.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "n1", "type": "file", "filePath": "src/a.py"},
                    {
                        "id": "n2",
                        "type": "file",
                        "filePath": "packages/acgs-control-plane/src/app.py",
                    },
                ],
                "edges": [],
            }
        )
    )
    monkeypatch.setattr(extract, "UA_GRAPH", graph)
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"gitCommitHash": "abc"}))
    monkeypatch.setattr(extract, "UA_META", meta)
    tracked = ["src/a.py", "packages/acgs-control-plane"]

    dirty_gitlink = extract.semantic_snapshot_props("abc", ["packages/acgs-control-plane"], tracked)
    name_prefix_only = extract.semantic_snapshot_props("abc", ["packages/acgs-control"], tracked)

    assert dirty_gitlink["semantic_layer_is_stale"] is True
    assert dirty_gitlink["semantic_dirty_paths"] == ["packages/acgs-control-plane/src/app.py"]
    assert dirty_gitlink["semantic_uncovered_paths"] == []
    assert name_prefix_only["semantic_layer_is_stale"] is False
    assert name_prefix_only["semantic_dirty_paths"] == []


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


def test_build_workflows_applies_negative_filters_when_minting_gates_edges(tmp_path, monkeypatch):
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

    wkey = ".github/workflows/marketing.yml"
    assert ("GATES", "Workflow", wkey, "File", "acgi-ai/src/App.tsx") in extract.G.rels
    assert (
        "GATES",
        "Workflow",
        wkey,
        "File",
        "acgi-ai/infra/main.tf",
    ) not in extract.G.rels


def test_build_workflows_preserves_the_triggering_event_on_each_gates_edge(tmp_path, monkeypatch):
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

    wkey = ".github/workflows/deploy.yml"
    push_gate = extract.G.rels[("GATES", "Workflow", wkey, "File", "packages/analyzer/main.py")]
    pr_gate = extract.G.rels[("GATES", "Workflow", wkey, "File", "deploy/chart.yaml")]
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

    props = extract.G.nodes[("Workflow", ".github/workflows/deploy.yml")]["props"]
    assert props["path_filters_push"] == [
        "packages/analyzer/**",
        "!packages/analyzer/docs/**",
    ]
    assert props["path_filters_pull_request"] == ["deploy/**"]


def test_build_workflows_does_not_gate_submodule_internal_paths(tmp_path, monkeypatch):
    """REGRESSION. build_spine() appends every initialized submodule's inner
    paths to the tracked list, and matching them against the parent
    repository's workflow filters minted GATES edges for files a parent PR
    can never change (only the gitlink moves). Those edges suppressed the
    inner files from Q2 and reported false CI×N coverage. The gitlink itself
    is an ordinary parent-tracked path and must keep matching."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "swarm.yml").write_text(
        "name: swarm\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'packages/swarm'\n"
        "      - 'packages/swarm/**'\n"
        "jobs:\n"
        "  test:\n"
        "    steps: []\n"
    )
    _files(".github/workflows/swarm.yml")
    extract.G.node("File", "packages/swarm", path="packages/swarm", in_submodule=False)
    extract.G.node(
        "File",
        "packages/swarm/src/main.py",
        path="packages/swarm/src/main.py",
        in_submodule=True,
    )

    extract.build_workflows(["packages/swarm", "packages/swarm/src/main.py"])

    wkey = ".github/workflows/swarm.yml"
    assert ("GATES", "Workflow", wkey, "File", "packages/swarm") in extract.G.rels
    assert (
        "GATES",
        "Workflow",
        wkey,
        "File",
        "packages/swarm/src/main.py",
    ) not in extract.G.rels


def test_build_workflows_marks_coverage_conditional_when_every_job_carries_an_if(
    tmp_path, monkeypatch
):
    """REGRESSION. A job-level `if:` can skip the job even when the trigger
    paths match (tests-root.yml skips its sole job on fork PRs), yet only the
    trigger paths were inspected, so the GATES edge was indistinguishable from
    unconditional coverage and Q1/Q2 and the generated report counted matching
    fork changes as executed PR gating."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "tests.yml").write_text(
        "name: tests\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'src/**'\n"
        "jobs:\n"
        "  test:\n"
        "    if: github.event.pull_request.head.repo.full_name == github.repository\n"
        "    steps: []\n"
    )
    _files(".github/workflows/tests.yml", "src/main.py")

    extract.build_workflows(["src/main.py"])

    wkey = ".github/workflows/tests.yml"
    props = extract.G.nodes[("Workflow", wkey)]["props"]
    assert props["conditional_jobs"] == ["test"]
    assert props["all_jobs_conditional"] is True
    gate = extract.G.rels[("GATES", "Workflow", wkey, "File", "src/main.py")]
    assert gate["props"]["conditional"] is True
    assert gate["props"]["conditional_events"] == ["pull_request"]


def test_build_workflows_keeps_gates_unconditional_while_any_job_always_runs(tmp_path, monkeypatch):
    """One unconditional job is enough for the workflow to gate every matching
    change; only the fully conditional case may be marked."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "name: ci\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'src/**'\n"
        "jobs:\n"
        "  lint:\n"
        "    steps: []\n"
        "  test:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    steps: []\n"
    )
    _files(".github/workflows/ci.yml", "src/main.py")

    extract.build_workflows(["src/main.py"])

    wkey = ".github/workflows/ci.yml"
    props = extract.G.nodes[("Workflow", wkey)]["props"]
    assert props["conditional_jobs"] == ["test"]
    assert props["all_jobs_conditional"] is False
    gate = extract.G.rels[("GATES", "Workflow", wkey, "File", "src/main.py")]
    assert gate["props"]["conditional"] is False
    assert gate["props"]["conditional_events"] == []


def test_build_workflows_treats_event_matched_if_as_guaranteed_for_that_event(
    tmp_path, monkeypatch
):
    """REGRESSION. Conditions were counted syntactically: when a workflow's
    event-specific jobs all declare an `if:`, every GATES edge was marked
    conditional even though one condition is guaranteed by the matching event.
    saas-beta-p0-evidence.yml is the live shape — `hosted-contract` uses
    `if: github.event_name == 'pull_request'` and therefore always runs for a
    matching PR, while `exact-proof` is manual-only — yet Q1/Q2 discarded the
    real hosted PR gate."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "evidence.yml").write_text(
        "name: evidence\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'src/**'\n"
        "  workflow_dispatch: {}\n"
        "jobs:\n"
        "  hosted-contract:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    steps: []\n"
        "  exact-proof:\n"
        "    if: github.event_name == 'workflow_dispatch' &&\n"
        "      github.event.pull_request.head.repo.full_name == github.repository\n"
        "    steps: []\n"
    )
    _files(".github/workflows/evidence.yml", "src/main.py")

    extract.build_workflows(["src/main.py"])

    wkey = ".github/workflows/evidence.yml"
    props = extract.G.nodes[("Workflow", wkey)]["props"]
    assert props["all_jobs_conditional"] is True  # syntactic summary, unchanged
    gate = extract.G.rels[("GATES", "Workflow", wkey, "File", "src/main.py")]
    assert gate["props"]["conditional"] is False
    assert gate["props"]["conditional_events"] == []


def test_build_workflows_classifies_conditions_per_edge_event(tmp_path, monkeypatch):
    """A push+pull_request edge whose only job is PR-gated is unconditional
    for pull_request runs but conditional for push runs, so the edge must
    publish the per-event verdict instead of one collapsed boolean."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "mixed.yml").write_text(
        "name: mixed\n"
        "on:\n"
        "  push:\n"
        "    paths:\n"
        "      - 'src/**'\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'src/**'\n"
        "jobs:\n"
        "  test:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    steps: []\n"
    )
    _files(".github/workflows/mixed.yml", "src/main.py")

    extract.build_workflows(["src/main.py"])

    wkey = ".github/workflows/mixed.yml"
    gate = extract.G.rels[("GATES", "Workflow", wkey, "File", "src/main.py")]
    assert gate["props"]["events"] == ["pull_request", "push"]
    assert gate["props"]["conditional_events"] == ["push"]
    assert gate["props"]["conditional"] is False


def test_build_workflows_keys_nodes_by_path_so_same_named_files_stay_distinct(
    tmp_path, monkeypatch
):
    """REGRESSION. The display `name:` was the graph key, so two workflow
    files sharing a name collapsed into one node: the second file overwrote
    the first's path, jobs, and filters, and both files' GATES edges were
    attributed to a single workflow, undercounting distinct gates in Q1/Q2.
    The repo-relative path is the stable key; `name` is display-only."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "tests-a.yml").write_text(
        "name: tests\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'a/**'\n"
        "jobs:\n"
        "  alpha:\n"
        "    steps: []\n"
    )
    (wf_dir / "tests-b.yml").write_text(
        "name: tests\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'b/**'\n"
        "jobs:\n"
        "  beta:\n"
        "    steps: []\n"
    )
    _files(".github/workflows/tests-a.yml", ".github/workflows/tests-b.yml", "a/x.py", "b/y.py")

    extract.build_workflows(["a/x.py", "b/y.py"])

    a_key, b_key = ".github/workflows/tests-a.yml", ".github/workflows/tests-b.yml"
    a_props = extract.G.nodes[("Workflow", a_key)]["props"]
    b_props = extract.G.nodes[("Workflow", b_key)]["props"]
    assert a_props["name"] == b_props["name"] == "tests"
    assert a_props["path"] == a_key
    assert b_props["path"] == b_key
    assert a_props["jobs"] == ["alpha"]
    assert b_props["jobs"] == ["beta"]
    assert ("GATES", "Workflow", a_key, "File", "a/x.py") in extract.G.rels
    assert ("GATES", "Workflow", b_key, "File", "b/y.py") in extract.G.rels
    assert ("GATES", "Workflow", a_key, "File", "b/y.py") not in extract.G.rels
    assert ("GATES", "Workflow", b_key, "File", "a/x.py") not in extract.G.rels


def test_build_workflows_skips_workflow_files_that_are_not_live(tmp_path, monkeypatch):
    """REGRESSION. GitHub runs workflows from the commit's tree, but the
    filesystem glob also found an untracked local draft (no File node) and an
    index-removed workflow left on disk (tracked=false), minting Workflow and
    GATES edges that Q1/Q2, the verifier, and the reports presented as real
    CI coverage for tracked source, hiding genuinely ungated files."""
    pytest.importorskip("yaml")
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    body = (
        "name: local-only\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - 'src/**'\n"
        "jobs:\n"
        "  test:\n"
        "    steps: []\n"
    )
    (wf_dir / "draft.yml").write_text(body)  # untracked: never entered the spine
    (wf_dir / "removed.yml").write_text(body)  # removed from the index, left on disk
    _files("src/main.py")
    extract.G.node(
        "File",
        ".github/workflows/removed.yml",
        path=".github/workflows/removed.yml",
        present=True,
        tracked=False,
    )

    extract.build_workflows(["src/main.py"])

    assert ("Workflow", ".github/workflows/draft.yml") not in extract.G.nodes
    assert ("Workflow", ".github/workflows/removed.yml") not in extract.G.nodes
    assert not any(key[0] == "GATES" for key in extract.G.rels)


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


def test_top_level_eu_articles_are_recognised_controls():
    """REGRESSION. The EU pattern required a parenthesized paragraph, so the
    `Art. 19` rows already present in the compliance readiness report never
    became Control nodes and the per-framework totals undercounted."""
    assert extract.control_id("EU AI Act", _match("EU AI Act", "Art. 19")) == ("EU AI Act Art 19")


def test_top_level_nist_categories_are_recognised_controls():
    """REGRESSION companion: the NIST pattern required a decimal subcategory,
    dropping the `GOVERN 1` / `MAP 1` / `MEASURE 2` / `MANAGE 2` rows the
    crosswalk actually uses."""
    ids = {
        extract.control_id("NIST AI RMF", _match("NIST AI RMF", text))
        for text in ("GOVERN 1", "GOVERN-1", "MAP 1", "MEASURE 2", "MANAGE 2")
    }

    assert ids == {
        "NIST AI RMF GOVERN-1",
        "NIST AI RMF MAP-1",
        "NIST AI RMF MEASURE-2",
        "NIST AI RMF MANAGE-2",
    }


def test_detailed_citations_do_not_also_mint_their_top_level_parents():
    """`Art. 12(1)` is one control, not `Art 12(1)` plus `Art 12`; likewise
    `GOVERN 1.5` must not also produce `GOVERN-1`."""
    eu = dict(extract.CONTROL_PATTERNS)["EU AI Act"]
    nist = dict(extract.CONTROL_PATTERNS)["NIST AI RMF"]

    eu_ids = {extract.control_id("EU AI Act", m) for m in eu.finditer("see Art. 12(1) here")}
    nist_ids = {extract.control_id("NIST AI RMF", m) for m in nist.finditer("see GOVERN 1.5 here")}

    assert eu_ids == {"EU AI Act Art 12(1)"}
    assert nist_ids == {"NIST AI RMF GOVERN-1.5"}


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


def test_markdown_links_resolve_relative_to_the_source_document_first():
    """REGRESSION. Markdown resolves an unprefixed relative link against the
    linking document's directory, but resolve_link tried repo-root first, so
    `[x](COMPARISON.md)` in docs/AGENT_STACK_GOVERNANCE.md bound to the
    distinct root COMPARISON.md whenever both existed — leaving the intended
    docs/COMPARISON.md orphaned in Q8 and inflating the root file's Q12
    authority. Tokens from link syntax must resolve doc-relative first."""
    _files("COMPARISON.md", "docs/COMPARISON.md")

    assert (
        extract.resolve_link("docs/AGENT_STACK_GOVERNANCE.md", "COMPARISON.md", markdown_link=True)
        == "docs/COMPARISON.md"
    )
    # Backticked path tokens keep the repo-root-relative dominant style.
    assert (
        extract.resolve_link("docs/AGENT_STACK_GOVERNANCE.md", "COMPARISON.md") == "COMPARISON.md"
    )


def test_markdown_links_still_fall_back_to_repo_root():
    """Many docs write repo-root-relative paths inside link syntax; when the
    doc-relative candidate does not exist, the root candidate must still
    resolve."""
    _files("packages/gove-zone/src/gove_zone/receipt.py")

    assert (
        extract.resolve_link(
            "docs/compliance.md",
            "packages/gove-zone/src/gove_zone/receipt.py",
            markdown_link=True,
        )
        == "packages/gove-zone/src/gove_zone/receipt.py"
    )


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


def test_resolve_link_excludes_untracked_files_that_still_exist_on_disk():
    """REGRESSION. A semantic snapshot can retain a path that was removed
    from the Git index but still exists on disk (tracked=False,
    present=True); file_is_live() keyed on presence alone, so resolve_token()
    bound compliance citations to it and build_controls() could promote
    controls to Tier B/C using code that will not exist in a checkout.
    Repository evidence must be present AND tracked."""
    extract.G.node("File", "untracked.py", path="untracked.py", present=True, tracked=False)

    assert extract.file_is_live("untracked.py") is False
    assert extract.resolve_link("docs/x.md", "untracked.py") is None
    assert extract.resolve_token("docs/x.md", "untracked.py") == (None, None, None)


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
# Document links
# --------------------------------------------------------------------------- #
def test_doc_links_resolve_bare_root_document_citations(tmp_path, monkeypatch):
    """REGRESSION. CLAUDE.md cites `CONCEPTS.md` as a bare backticked filename:
    PATH_TOKEN requires a slash and MD_LINK requires link syntax, so no
    LINKS_TO edge was created, Q8 reported CONCEPTS.md as orphaned, and Q12
    undercounted its authority. CODE_TOKEN already recognises the token; the
    optional `:line` suffix must be stripped before resolving."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "CLAUDE.md").write_text(
        "Read `CONCEPTS.md` first, then `docs/plan.md:12` for the phases.\n"
    )
    _files("CLAUDE.md", "CONCEPTS.md", "docs/plan.md")

    extract.build_doc_links()

    assert ("LINKS_TO", "File", "CLAUDE.md", "File", "CONCEPTS.md") in extract.G.rels
    assert ("LINKS_TO", "File", "CLAUDE.md", "File", "docs/plan.md") in extract.G.rels


def test_doc_links_bind_markdown_links_to_the_doc_relative_target(tmp_path, monkeypatch):
    """REGRESSION. A nested document's unprefixed relative Markdown link
    (`[c](COMPARISON.md)` in docs/) was bound to the same-named root file
    whenever both existed, because every token was resolved repo-root first
    regardless of syntax. The LINKS_TO edge must follow Markdown semantics;
    a backticked citation of the same bare name keeps the root binding."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "guide.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("See the [comparison](COMPARISON.md) and `README.md`.\n")
    _files("docs/guide.md", "COMPARISON.md", "docs/COMPARISON.md", "README.md", "docs/README.md")

    extract.build_doc_links()

    assert ("LINKS_TO", "File", "docs/guide.md", "File", "docs/COMPARISON.md") in extract.G.rels
    assert ("LINKS_TO", "File", "docs/guide.md", "File", "COMPARISON.md") not in extract.G.rels
    # The backticked bare filename is not link syntax: repo-root still wins.
    assert ("LINKS_TO", "File", "docs/guide.md", "File", "README.md") in extract.G.rels


def test_doc_links_do_not_link_a_document_to_itself(tmp_path, monkeypatch):
    """A README naming its own filename (`README.md` says "this README.md")
    must not mint a self-edge now that bare filename tokens resolve."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "README.md").write_text("This `README.md` covers `CONCEPTS.md`.\n")
    _files("README.md", "CONCEPTS.md")

    extract.build_doc_links()

    assert ("LINKS_TO", "File", "README.md", "File", "README.md") not in extract.G.rels
    assert ("LINKS_TO", "File", "README.md", "File", "CONCEPTS.md") in extract.G.rels


def test_doc_links_skip_source_documents_that_are_not_live(tmp_path, monkeypatch):
    """REGRESSION. A Markdown file removed from the index but left on disk
    keeps a semantic-retained node with tracked=false, and only the on-disk
    check gated the scan, so its citations minted LINKS_TO edges from a
    document that will not exist in a checkout — suppressing live targets
    from Q8's orphan report and inflating their Q12 authority. The source
    must pass the same file_is_live() predicate build_controls() applies to
    mapping documents."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "GHOST.md").write_text("See `CONCEPTS.md` for details.\n")
    _files("CONCEPTS.md")
    extract.G.node("File", "GHOST.md", path="GHOST.md", present=True, tracked=False)

    extract.build_doc_links()

    assert ("LINKS_TO", "File", "GHOST.md", "File", "CONCEPTS.md") not in extract.G.rels


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


def test_parse_history_aborts_when_git_history_cannot_be_read(tmp_path, monkeypatch):
    """REGRESSION. A nonzero `git log` exit (partial/filtered checkout, missing
    historical object) silently returned [], so extraction still succeeded and
    published a graph with zero churn, contributor, Commit, and TOUCHED
    evidence as if that were the real history."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "not-a-repo").mkdir()

    with pytest.raises(RuntimeError, match="git log failed for repo 'not-a-repo'"):
        extract.parse_history("not-a-repo")


def test_parse_history_rejects_a_shallow_clone(git_repo, tmp_path):
    """REGRESSION. In a shallow clone `git log` exits 0 with only the
    retained history, so churn, contributor counts, hotspots, co-change
    edges, and commit counts were silently computed from a truncated sample
    while the generated report claimed they cover full history. The
    check runs once per repo, covering the parent and every initialized
    submodule alike."""
    (git_repo / "a.py").write_text("one\ntwo\nthree\n")
    _git(git_repo, "commit", "-aqm", "second commit")
    _git(tmp_path, "clone", "-q", "--depth", "1", f"file://{git_repo}", "shallow")

    with pytest.raises(RuntimeError, match="shallow clone"):
        extract.parse_history("shallow")


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


def test_build_history_namespaces_commit_nodes_by_repository():
    """REGRESSION. Commit nodes were keyed on the short SHA alone, but two
    initialized repositories can share a commit object (a forked or split
    history), so parse_history() entries with the same SHA and different
    repos collapsed into one node: the later G.node() overwrote repo,
    file_count, and churn while both repositories' TOUCHED edges stayed
    unioned on it, and REPO_Q described neither repository correctly. The
    repository plus the full SHA is the graph identity."""
    _files("kernel.py", "packages/fork/kernel.py")
    sha = "c" * 40
    base = {"ts": 1_700_000_000, "author": "A", "email": "a@example.com", "subject": "x"}
    commits = [
        {**base, "sha": sha, "repo": ".", "files": {"kernel.py": (3, 1)}},
        {
            **base,
            "sha": sha,
            "repo": "packages/fork",
            "files": {"packages/fork/kernel.py": (7, 2)},
        },
    ]

    extract.build_history(commits)

    parent = extract.G.nodes[("Commit", f".:{sha}")]["props"]
    fork = extract.G.nodes[("Commit", f"packages/fork:{sha}")]["props"]
    assert parent["repo"] == "." and parent["churn"] == 4
    assert fork["repo"] == "packages/fork" and fork["churn"] == 9
    assert ("TOUCHED", "Commit", f".:{sha}", "File", "kernel.py") in extract.G.rels
    assert (
        "TOUCHED",
        "Commit",
        f".:{sha}",
        "File",
        "packages/fork/kernel.py",
    ) not in extract.G.rels
    assert (
        "TOUCHED",
        "Commit",
        f"packages/fork:{sha}",
        "File",
        "packages/fork/kernel.py",
    ) in extract.G.rels


def test_build_history_normalizes_hotspots_over_live_files_only():
    """REGRESSION. A deleted historical path with the repository's largest
    churn set max_churn even though the scoring loop skips it (no live File
    node), so every live file's hotspot was scaled down by an unreachable
    file and Q5's fixed `hotspot > 0.05` predicate could miss the actual
    current hotspots."""
    _files("live.py")
    commit = {
        "sha": "a" * 40,
        "ts": 1_700_000_000,
        "author": "A",
        "email": "a@example.com",
        "subject": "x",
        "repo": ".",
        "files": {"live.py": (5, 5), "deleted-long-ago.py": (500, 500)},
    }

    extract.build_history([commit])

    assert extract.G.nodes[("File", "live.py")]["props"]["hotspot"] == 1.0


def test_build_history_normalizes_hotspots_over_live_tracked_nodes_only():
    """REGRESSION. build_semantic() deliberately retains a File node for a
    path deleted after the snapshot (present=false, possibly tracked=false),
    so the node-existence check alone still let that dead node's churn set
    max_churn, scaling every live file's hotspot down until Q5's fixed
    `hotspot > 0.05` predicate missed the actual current hotspots. The
    denominator and the scoring loop must share the live-and-tracked
    predicate, so the dead node receives no hotspot either."""
    _files("live.py")
    extract.G.node("File", "stale.py", path="stale.py", present=False, tracked=False)
    commit = {
        "sha": "a" * 40,
        "ts": 1_700_000_000,
        "author": "A",
        "email": "a@example.com",
        "subject": "x",
        "repo": ".",
        "files": {"live.py": (5, 5), "stale.py": (500, 500)},
    }

    extract.build_history([commit])

    assert extract.G.nodes[("File", "live.py")]["props"]["hotspot"] == 1.0
    assert "hotspot" not in extract.G.nodes[("File", "stale.py")]["props"]


def test_build_history_mints_co_change_edges_only_between_live_tracked_files():
    """REGRESSION. CO_CHANGED endpoints were gated on node existence alone,
    but build_semantic() deliberately retains a File node for a deleted or
    index-removed path (present/tracked record the truth), so dead paths kept
    receiving co-change edges. Q4 filters neither present nor tracked, so
    architecture-erosion results reported package coupling through files
    absent from a checkout. Endpoints must pass the same live-and-tracked
    predicate as hotspot scoring."""
    _files("live_a.py", "live_b.py")
    extract.G.node("File", "stale.py", path="stale.py", present=False, tracked=False)
    commits = [
        {
            "sha": f"{i:040x}",
            "ts": 1_700_000_000 + i,
            "author": "A",
            "email": "a@example.com",
            "subject": "x",
            "repo": ".",
            "files": {"live_a.py": (1, 0), "live_b.py": (1, 0), "stale.py": (1, 0)},
        }
        for i in range(extract.COCHANGE_MIN_COUNT)
    ]

    extract.build_history(commits)

    assert ("CO_CHANGED", "File", "live_a.py", "File", "live_b.py") in extract.G.rels
    assert ("CO_CHANGED", "File", "live_a.py", "File", "stale.py") not in extract.G.rels
    assert ("CO_CHANGED", "File", "live_b.py", "File", "stale.py") not in extract.G.rels


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
def test_build_topology_assigns_a_gitlink_file_to_its_own_submodule_package(tmp_path, monkeypatch):
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
        extract.G.nodes[("File", "packages/acgs-lite")]["props"]["package"] == "packages/acgs-lite"
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


def test_build_sealed_accepts_the_gate_marker_syntax_including_uppercase_hex(tmp_path, monkeypatch):
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


def test_build_sealed_reports_a_missing_live_marker_as_drift(tmp_path, monkeypatch):
    """REGRESSION. When a tracked file stays pinned in the lock but its
    working-tree marker has been removed, the lock pass restored the pin into
    sealed_hash, so Q3 showed the file as sealed with no hash_drift, hiding
    exactly the marker-removal drift the graph exists to expose. The absent
    observation must stay absent (no sealed_hash) and the file must be
    flagged as drifted."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    (tmp_path / "plain.md").write_text("no marker here\n")
    _lock(tmp_path, {"plain.md": "0123456789abcdef"})
    _files("plain.md")

    extract.build_sealed(["plain.md"])

    props = extract.G.nodes[("File", "plain.md")]["props"]
    assert props["sealed"] is True
    assert "sealed_hash" not in props
    assert props["sealed_source"] == "hash-lock"
    assert props["pinned_hash"] == "0123456789abcdef"
    assert props["hash_drift"] is True
    assert ("SEALED_WITH", "File", "plain.md", "Hash", "0123456789abcdef") in extract.G.rels


def test_build_sealed_waives_an_absent_lock_entry_for_an_uninitialized_submodule(
    tmp_path, monkeypatch
):
    """A lock entry naming a path inside a submodule that is genuinely not
    checked out here says nothing about the seal: it is counted on the
    Package node, never published as missing."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    monkeypatch.setattr(extract, "run", lambda *a: "-deadbeef packages/acgs-lite\n")
    _lock(tmp_path, {"packages/acgs-lite/rust/src/lib.rs": "0123456789abcdef"})
    extract.G.node("Package", "packages/acgs-lite", path="packages/acgs-lite")

    extract.build_sealed([])

    assert extract.G.nodes[("Package", "packages/acgs-lite")]["props"]["sealed_files_absent"] == 1
    assert extract.SEALED_STATS == {}


def test_build_sealed_reports_a_lock_entry_missing_from_an_initialized_submodule(
    tmp_path, monkeypatch
):
    """REGRESSION. A lock entry absent from the File spine was attributed to
    its package by prefix and counted as sealed_files_absent without checking
    whether that package is an uninitialized submodule, so a sealed file
    removed from an *initialized* submodule's index read as "unavailable
    submodule" and verify.py said VERIFY: PASS over a genuinely missing
    sealed file. Only an actually-uninitialized submodule waives the absence;
    every other absence is published for verify.py to fail on."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    # The submodule IS checked out: no '-' prefix in `git submodule status`.
    monkeypatch.setattr(extract, "run", lambda *a: " deadbeef packages/acgs-lite (v1.0)\n")
    _lock(tmp_path, {"packages/acgs-lite/rust/src/lib.rs": "0123456789abcdef"})
    extract.G.node("Package", "packages/acgs-lite", path="packages/acgs-lite")

    extract.build_sealed([])

    props = extract.G.nodes[("Package", "packages/acgs-lite")]["props"]
    assert "sealed_files_absent" not in props
    assert extract.SEALED_STATS["sealed_lock_missing"] == ["packages/acgs-lite/rust/src/lib.rs"]
    assert extract.SEALED_STATS["sealed_lock_missing_count"] == 1


def test_build_sealed_reports_a_parent_tree_lock_entry_with_no_file_node_as_missing(
    tmp_path, monkeypatch
):
    """A pinned parent-tree path with no File node at all (removed from the
    index and the spine) is missing, not waivable: it belongs to no
    submodule, initialized or otherwise."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    monkeypatch.setattr(extract, "run", lambda *a: "")
    _lock(tmp_path, {"docs/SECURITY_MODEL.md": "0123456789abcdef"})

    extract.build_sealed([])

    assert extract.SEALED_STATS["sealed_lock_missing"] == ["docs/SECURITY_MODEL.md"]


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
def test_build_policies_requires_live_tracked_sources(tmp_path, monkeypatch):
    """REGRESSION. build_policies scanned the filesystem directly, so an
    untracked local draft minted a current Policy node, and a policy removed
    from the index but left on disk (tracked=false) could even mint
    DEFINED_IN via its semantic-retained File node — a policy inventory
    depending on local-only files that will not exist in a checkout. The
    same live-and-tracked source predicate as workflows, ADRs, links, and
    mapping documents applies."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    pol = tmp_path / "automation" / "policies"
    pol.mkdir(parents=True)
    (pol / "tracked.yaml").write_text("rule: a\n")
    (pol / "draft.yaml").write_text("rule: b\n")  # untracked: no File node
    (pol / "removed.yaml").write_text("rule: c\n")  # index-removed remnant
    _files("automation/policies/tracked.yaml")
    extract.G.node("File", "automation/policies/removed.yaml", tracked=False, present=True)

    extract.build_policies()

    assert extract.G.has("Policy", "automation/policies/tracked.yaml")
    assert not extract.G.has("Policy", "automation/policies/draft.yaml")
    assert not extract.G.has("Policy", "automation/policies/removed.yaml")
    assert (
        "DEFINED_IN",
        "Policy",
        "automation/policies/tracked.yaml",
        "File",
        "automation/policies/tracked.yaml",
    ) in extract.G.rels
    assert not any(
        src == "Policy" and key != "automation/policies/tracked.yaml"
        for (_, src, key, *_rest) in extract.G.rels
    )


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


def test_build_adrs_skips_adr_files_that_are_not_live(tmp_path, monkeypatch):
    """REGRESSION. The filesystem glob also found an untracked local draft
    (no File node) and an index-removed ADR left on disk (tracked=false),
    minting ADR nodes and DECIDES_ON edges for decisions that will not exist
    in a checkout: the phantom appeared in Q7 and suppressed Q3b's
    missing-ADR finding for the sealed files it cited."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0001-draft.md").write_text(
        "# 0001. Draft\n\n## Status\n\nAccepted\n\nDecides on `src/kernel.py`.\n"
    )
    (adr_dir / "0002-removed.md").write_text(
        "# 0002. Removed\n\n## Status\n\nAccepted\n\nRelates to ADR-0001.\n"
    )
    _files("src/kernel.py")
    extract.G.node(
        "File",
        "docs/adr/0002-removed.md",
        path="docs/adr/0002-removed.md",
        present=True,
        tracked=False,
    )

    extract.build_adrs()

    assert ("ADR", "ADR-0001") not in extract.G.nodes
    assert ("ADR", "ADR-0002") not in extract.G.nodes
    assert not any(key[0] in ("DECIDES_ON", "RELATES_TO") for key in extract.G.rels)


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


def test_build_controls_accumulates_citations_from_every_mapping_document(tmp_path, monkeypatch):
    """REGRESSION. Two mapping documents citing the same file for the same
    control share one EVIDENCED_BY identity, and each call overwrote the
    scalar cited_in/cited_line/resolved_by props: the graph kept only
    whichever sorted document was processed last while the extraction counter
    still claimed both evidence links were recorded."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir(parents=True)
    # The weaker (basename) citation sorts first so the stronger (path)
    # citation must upgrade the already-set scalars, not merely seed them.
    (docs / "a-compliance-mapping.md").write_text("| Art. 12(1) | see `audit.py` |\n")
    (docs / "z-compliance-mapping.md").write_text(
        "| Art. 12(1) | implemented in `packages/gove-zone/audit.py:141` |\n"
    )
    _files(
        "docs/a-compliance-mapping.md",
        "docs/z-compliance-mapping.md",
        "packages/gove-zone/audit.py",
    )

    extract.build_controls()

    evidence = extract.G.rels[
        ("EVIDENCED_BY", "Control", "EU AI Act Art 12(1)", "File", "packages/gove-zone/audit.py")
    ]
    assert evidence["props"]["citations"] == [
        "docs/a-compliance-mapping.md",
        "docs/z-compliance-mapping.md:141",
    ]
    # The scalars mirror the strongest citation, not the last-processed doc.
    assert evidence["props"]["cited_in"] == "docs/z-compliance-mapping.md"
    assert evidence["props"]["cited_line"] == 141
    assert evidence["props"]["resolved_by"] == "path"
    assert extract.CONTROL_STATS["evidence_links"] == 2


def test_build_controls_keeps_every_same_file_line_citation(tmp_path, monkeypatch):
    """REGRESSION. One scope citing several lines of the same evidence file
    (docs/EU_AI_ACT_MAPPING.md:49 cites receipt.py:139, :140 and :141 for a
    single control) collapsed to one citation: evidence was keyed on the
    target alone, and tokens iterate over a set, so the surviving line was
    hash-order dependent. Every distinct target-and-line citation must be
    recorded, in deterministic order."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text(
        "| Art. 12(1) | `packages/gove-zone/receipt.py:139`, "
        "`packages/gove-zone/receipt.py:140` and `packages/gove-zone/receipt.py:141` |\n"
    )
    _files("docs/compliance-mapping.md", "packages/gove-zone/receipt.py")

    extract.build_controls()

    evidence = extract.G.rels[
        (
            "EVIDENCED_BY",
            "Control",
            "EU AI Act Art 12(1)",
            "File",
            "packages/gove-zone/receipt.py",
        )
    ]
    assert evidence["props"]["citations"] == [
        "docs/compliance-mapping.md:139",
        "docs/compliance-mapping.md:140",
        "docs/compliance-mapping.md:141",
    ]
    # The scalars mirror the first equally-strong citation, deterministically.
    assert evidence["props"]["cited_line"] == 139
    assert evidence["props"]["resolved_by"] == "path"
    assert extract.CONTROL_STATS["evidence_links"] == 3


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


def test_build_controls_ignores_an_untracked_mapping_document(tmp_path, monkeypatch):
    """REGRESSION. Evidence *targets* were filtered through file_is_live(),
    but the mapping document itself never was: a doc removed from the index
    yet retained by the semantic snapshot (tracked=false, present=true) was
    still scanned, minting MAPS_TO and attaching its citations to tracked
    code, so the compliance report published and tiered controls sourced from
    a document that will not exist in a checkout."""
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("| Art. 12(1) | implemented in `packages/gove-zone/audit.py` |\n")
    extract.G.node(
        "File",
        "docs/compliance-mapping.md",
        path="docs/compliance-mapping.md",
        tracked=False,
        present=True,
    )
    _files("packages/gove-zone/audit.py")

    extract.build_controls()

    assert not any(label == "Control" for label, _ in extract.G.nodes)
    assert not any(key[0] in ("MAPS_TO", "EVIDENCED_BY") for key in extract.G.rels)


def test_build_controls_never_binds_a_document_as_its_own_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(extract, "ROOT", tmp_path)
    doc = tmp_path / "docs" / "compliance-mapping.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("| CC7.2 | described in `docs/compliance-mapping.md` |\n")
    _files("docs/compliance-mapping.md")

    extract.build_controls()

    assert not any(key[0] == "EVIDENCED_BY" for key in extract.G.rels)
