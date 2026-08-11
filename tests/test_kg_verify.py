"""Guards for ``tools/kg/verify.py`` — the loaded-graph health gate.

The whole point of this script is that it fails when the ingest layers did not
actually join. A regression that turns it into a pass-always smoke check would
be invisible: the container is up, the queries return, and the report says
nothing is wrong. Each hard failure condition is pinned here, plus the
pass path, using a stub driver rather than a live Neo4j.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _kg_common import fake_neo4j, load_kg_module

verify = load_kg_module("verify")

HEALTHY_JOIN = {"files": 100, "with_semantic": 60, "with_git": 90, "joined_both": 55, "sealed": 12}


@pytest.fixture
def run_verify(monkeypatch):
    """Run ``verify.main()`` with canned join-health rows and catalog hits."""

    def _run(
        join_row: dict,
        *,
        catalog_hits: int = len(verify.CATALOG),
        absent_lock_entries: int = 0,
        snapshot_rows: int = 1,
        semantic_declared_loaded: bool = False,
        constraint_names: tuple[str, ...] | None = None,
        constraint_rows: list[dict] | None = None,
        argv: tuple[str, ...] = (),
    ):
        catalog_queries = [q for _, q in verify.CATALOG]
        answered = set(catalog_queries[:catalog_hits])
        constraints = (
            sorted(verify.REQUIRED_CONSTRAINTS)
            if constraint_names is None
            else list(constraint_names)
        )

        def _row(name: str) -> dict:
            label, prop = verify.REQUIRED_CONSTRAINT_SCHEMAS.get(name, ("X", "key"))
            return {"name": name, "on": [label], "props": [prop]}

        def responder(query: str) -> list[dict]:
            if query.startswith("SHOW CONSTRAINTS"):
                if constraint_rows is not None:
                    return list(constraint_rows)
                return [_row(n) for n in constraints]
            if query.startswith("MATCH (f:File) RETURN count(*) AS files"):
                return [join_row]
            if query == verify.SEALED_ABSENT_Q:
                return [{"absent": absent_lock_entries}]
            if query == verify.SEMANTIC_DECLARED_Q:
                return [{"loaded": 1 if semantic_declared_loaded else 0}]
            if query.startswith("MATCH (s:Snapshot)"):
                return [{"head": "abc123", "branch": "main"}] * snapshot_rows
            if query in answered:
                return [{"col": "value"}]
            if query in catalog_queries:
                return []
            return [{"label": "File", "n": 1}]

        captured = fake_neo4j(monkeypatch, responder)
        monkeypatch.setattr(sys, "argv", ["verify.py", *argv])
        return verify.main(), captured["driver"]

    return _run


# --------------------------------------------------------------------------- #
# Row rendering
# --------------------------------------------------------------------------- #
def test_table_renders_aligned_columns():
    rendered = verify.table([{"label": "File", "n": 1}, {"label": "Commit", "n": 400}])

    lines = rendered.splitlines()
    assert lines[0].split() == ["label", "n"]
    assert set(lines[1].strip()) == {"-", " "}
    assert "File" in lines[2] and "400" in lines[3]


def test_table_reports_no_rows_rather_than_rendering_an_empty_header():
    assert verify.table([]) == "    (no rows)"


def test_table_truncates_overlong_cells():
    rendered = verify.table([{"key": "x" * 100}])

    assert "..." in rendered
    assert "x" * 100 not in rendered


def test_table_widths_account_for_the_header_when_values_are_shorter():
    rendered = verify.table([{"framework": "a"}])

    assert rendered.splitlines()[0].strip() == "framework"


# --------------------------------------------------------------------------- #
# Hard failure conditions
# --------------------------------------------------------------------------- #
def test_a_healthy_graph_passes(run_verify, capsys):
    code, driver = run_verify(HEALTHY_JOIN)

    assert code == 0
    assert "VERIFY: PASS" in capsys.readouterr().out
    assert driver.closed is True


def test_an_empty_file_spine_fails(run_verify, capsys):
    code, _ = run_verify({**HEALTHY_JOIN, "files": 0, "joined_both": 0, "sealed": 0})

    assert code == 1
    assert "FAIL: no File nodes" in capsys.readouterr().out


def test_a_graph_whose_layers_did_not_join_fails(run_verify, capsys):
    """The load-bearing check: files exist and the queries return, but fewer
    than a quarter carry both semantic and git facts — the path keys are not
    unifying, which is exactly the failure this script exists to catch."""
    code, _ = run_verify({**HEALTHY_JOIN, "files": 100, "joined_both": 10})

    assert code == 1
    out = capsys.readouterr().out
    assert "join health: only 10/100 files carry" in out


def test_join_health_threshold_is_a_quarter_of_the_spine(run_verify):
    """25% exactly must pass; anything under it must fail."""
    assert run_verify({**HEALTHY_JOIN, "files": 100, "joined_both": 25})[0] == 0
    assert run_verify({**HEALTHY_JOIN, "files": 100, "joined_both": 24})[0] == 1


def test_a_graph_with_no_sealed_files_fails(run_verify, capsys):
    """Constitutional-hash markers exist in the tree; zero linked means the
    governance layer never joined."""
    code, _ = run_verify({**HEALTHY_JOIN, "sealed": 0})

    assert code == 1
    assert "FAIL: no sealed files linked" in capsys.readouterr().out


def test_a_graph_without_a_snapshot_node_fails(run_verify, capsys):
    """REGRESSION. An otherwise healthy graph with no Snapshot node printed an
    empty snapshot table and still said VERIFY: PASS, then the documented next
    step (reports.py) crashed on `s.run(SNAPSHOT_Q).single().data()` because
    provenance could not be established at all."""
    code, _ = run_verify(HEALTHY_JOIN, snapshot_rows=0)

    assert code == 1
    assert "FAIL: expected exactly 1 Snapshot node, found 0" in capsys.readouterr().out


def test_a_graph_with_multiple_snapshot_nodes_fails(run_verify, capsys):
    """Provenance must be unique: two Snapshot nodes mean two competing claims
    about which commit the graph describes."""
    code, _ = run_verify(HEALTHY_JOIN, snapshot_rows=2)

    assert code == 1
    assert "FAIL: expected exactly 1 Snapshot node, found 2" in capsys.readouterr().out


def test_a_missing_required_constraint_fails(run_verify, capsys):
    """REGRESSION. The constraints check only printed the SHOW CONSTRAINTS
    rows, so a database where schema.cypher was never applied (or where a
    uniqueness constraint was dropped) still said VERIFY: PASS while later
    loads could mint duplicate nodes and fan out relationships. The returned
    names must cover every constraint schema.cypher declares."""
    present = tuple(sorted(verify.REQUIRED_CONSTRAINTS - {"file_key"}))
    code, _ = run_verify(HEALTHY_JOIN, constraint_names=present)

    assert code == 1
    out = capsys.readouterr().out
    assert "FAIL: missing required constraints: file_key" in out


def test_an_unconstrained_database_fails(run_verify, capsys):
    """SHOW CONSTRAINTS returning nothing at all is the fresh-container case:
    every required constraint is missing."""
    code, _ = run_verify(HEALTHY_JOIN, constraint_names=())

    assert code == 1
    assert "missing required constraints:" in capsys.readouterr().out


def test_extra_constraints_beyond_the_schema_still_pass(run_verify):
    """The gate requires coverage of schema.cypher, not exact equality: an
    operator adding an extra local constraint is not a verification failure."""
    present = (*sorted(verify.REQUIRED_CONSTRAINTS), "operator_extra")

    assert run_verify(HEALTHY_JOIN, constraint_names=present)[0] == 0


def test_required_constraints_are_derived_from_the_schema_file():
    """The requirement list is parsed from schema.cypher itself so the two
    cannot drift; spot-check the join spine's constraint and the overall
    shape rather than duplicating the file here."""
    assert "file_key" in verify.REQUIRED_CONSTRAINTS
    assert "snapshot_key" in verify.REQUIRED_CONSTRAINTS
    assert len(verify.REQUIRED_CONSTRAINTS) >= 10
    assert verify.REQUIRED_CONSTRAINT_SCHEMAS["file_key"] == ("File", "key")
    assert verify.REQUIRED_CONSTRAINT_SCHEMAS["snapshot_key"] == ("Snapshot", "key")


def test_a_required_constraint_on_the_wrong_label_fails(run_verify, capsys):
    """REGRESSION. The constraints gate compared names only, so an operator
    database where `file_key` was declared on :X(key) instead of :File(key)
    still said VERIFY: PASS. schema.cypher's IF NOT EXISTS never replaces a
    same-named constraint, so duplicate File nodes stayed possible while the
    apply step "succeeded". The (label, property) tuple must match too."""
    rows = [
        {"name": n, "on": [label], "props": [prop]}
        for n, (label, prop) in sorted(verify.REQUIRED_CONSTRAINT_SCHEMAS.items())
        if n != "file_key"
    ] + [{"name": "file_key", "on": ["X"], "props": ["key"]}]
    code, _ = run_verify(HEALTHY_JOIN, constraint_rows=rows)

    assert code == 1
    out = capsys.readouterr().out
    assert "FAIL: constraint file_key exists on :X(key) " in out
    assert "schema.cypher requires :File(key)" in out


def test_a_required_constraint_on_the_wrong_property_fails(run_verify, capsys):
    """Same gate, other half of the tuple: the right label constraining the
    wrong property (:File(path) instead of :File(key)) does not protect the
    join spine either."""
    rows = [
        {"name": n, "on": [label], "props": [prop]}
        for n, (label, prop) in sorted(verify.REQUIRED_CONSTRAINT_SCHEMAS.items())
        if n != "file_key"
    ] + [{"name": "file_key", "on": ["File"], "props": ["path"]}]
    code, _ = run_verify(HEALTHY_JOIN, constraint_rows=rows)

    assert code == 1
    assert "constraint file_key exists on :File(path)" in capsys.readouterr().out


def test_absent_marker_lock_entries_satisfy_the_sealed_check(run_verify, capsys):
    """A non-recursive checkout has zero sealed :File nodes by design:
    build_sealed records the lock entries as Package.sealed_files_absent.
    Failing on sealed == 0 would fail every ordinary `make all` run."""
    code, _ = run_verify({**HEALTHY_JOIN, "sealed": 0}, absent_lock_entries=17)

    assert code == 0
    out = capsys.readouterr().out
    assert "17 lock entries recorded" in out
    assert "VERIFY: PASS" in out


def test_a_declared_absent_semantic_layer_skips_the_join_threshold(run_verify, capsys):
    """build_semantic() skips when no knowledge-graph.json is tracked (fresh
    clone) and the Snapshot declares the layer absent. joined_both is then
    necessarily zero, which is a declared absence, not broken path-key joins;
    the gate must not fail `make all` for it."""
    code, _ = run_verify({**HEALTHY_JOIN, "with_semantic": 0, "joined_both": 0})

    assert code == 0
    assert "join threshold not applicable" in capsys.readouterr().out


def test_a_declared_loaded_semantic_layer_with_no_facts_fails(run_verify, capsys):
    """REGRESSION. The waiver keyed on count(f.summary) == 0 alone, so an
    ingested knowledge-graph.json that produced zero file summaries (incomplete
    export, semantic-schema change) was reported as "no semantic snapshot
    loaded" and VERIFY passed. The Snapshot's authoritative
    semantic_layer_loaded flag must gate the waiver: declared loaded with zero
    semantic facts is a hard failure."""
    code, _ = run_verify(
        {**HEALTHY_JOIN, "with_semantic": 0, "joined_both": 0},
        semantic_declared_loaded=True,
    )

    assert code == 1
    out = capsys.readouterr().out
    assert "declares the semantic layer loaded" in out
    assert "join threshold not applicable" not in out


def test_a_present_semantic_layer_still_enforces_the_join_threshold(run_verify):
    """The skip is only for a declared absence: one analyzed file with a bad
    join ratio is exactly the failure this script exists to catch."""
    assert run_verify({**HEALTHY_JOIN, "with_semantic": 1, "joined_both": 1})[0] == 1


def test_mostly_empty_catalog_queries_fail(run_verify, capsys):
    code, _ = run_verify(HEALTHY_JOIN, catalog_hits=2)

    assert code == 1
    assert f"only 2/{len(verify.CATALOG)} catalog queries returned rows" in capsys.readouterr().out


def test_three_answered_catalog_queries_are_enough(run_verify):
    assert run_verify(HEALTHY_JOIN, catalog_hits=3)[0] == 0


def test_every_failure_is_reported_not_just_the_first(run_verify, capsys):
    code, _ = run_verify(
        {"files": 0, "with_semantic": 0, "with_git": 0, "joined_both": 0, "sealed": 0}
    )

    assert code == 1
    out = capsys.readouterr().out
    assert "no File nodes" in out
    assert "no sealed files linked" in out


# --------------------------------------------------------------------------- #
# Query catalogue integrity
# --------------------------------------------------------------------------- #
def test_join_health_check_is_present_and_uniquely_prefixed():
    """``main`` selects the join-health row by title prefix, so exactly one
    check may carry it."""
    titled = [t for t, _ in verify.CHECKS if t.startswith("JOIN HEALTH")]

    assert len(titled) == 1


def test_every_check_and_catalog_entry_is_a_title_query_pair():
    for title, query in [*verify.CHECKS, *verify.CATALOG]:
        assert isinstance(title, str) and title
        assert isinstance(query, str) and query.strip()


def test_catalog_q5_ignores_test_edges_to_deleted_targets():
    """REGRESSION. The verifier's Q5 kept the unqualified
    `NOT (f)-[:TESTED_BY]->()` after the report queries were fixed, so a stale
    snapshot's edge to a deleted test file (present=false) still hid a hotspot
    from the catalog check. It must restrict to live tracked targets like
    reports.py: an index-removed test left on disk (tracked=false,
    present=true) is not coverage either (nodes without the flags, e.g.
    Symbols, stay countable)."""
    q5 = dict(verify.CATALOG)["Q5 hotspots with no test edge"]

    assert "TESTED_BY]->()" not in q5
    match = re.search(r"TESTED_BY]->\((\w+)", q5)
    assert match, f"query no longer binds its TESTED_BY target:\n{q5}"
    assert f"coalesce({match.group(1)}.present, true)" in q5
    assert f"coalesce({match.group(1)}.tracked, true)" in q5


def test_catalog_q5_excludes_absent_hotspot_subjects():
    """REGRESSION. tracked stays true for an unstaged deletion (build_spine
    records present=false), so the tracked-only filter reported a deleted
    source as a live hotspot. The subject file itself must be live, exactly
    like the queries.cypher catalog and the generated reports."""
    q5 = dict(verify.CATALOG)["Q5 hotspots with no test edge"]

    assert "coalesce(f.present, true)" in q5


def test_catalog_queries_are_distinct():
    queries = [q for _, q in verify.CATALOG]

    assert len(set(queries)) == len(queries)


def test_connection_settings_come_from_the_environment(run_verify, monkeypatch):
    monkeypatch.setenv("NEO4J_DATABASE", "kg")

    _, driver = run_verify(HEALTHY_JOIN)

    assert driver.sessions[0].database == "kg"
