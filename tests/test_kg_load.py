"""Guards for ``tools/kg/load.py`` — the graph.json -> Neo4j loader.

The loader never runs in CI, so nothing else pins its behaviour. Three things
here are easy to break silently: the schema splitter (prose comments in
``schema.cypher`` legitimately contain ``;``, so comments must be stripped
*before* splitting), the label grouping that turns extra labels into a
``SET n:`X``` suffix, and the explicitly requested wipe drain loop.
A stub driver stands in for Neo4j; no live service is required.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _kg_common import fake_neo4j, load_kg_module

load = load_kg_module("load")


def _graph(nodes: list[dict] | None = None, rels: list[dict] | None = None) -> dict:
    return {"nodes": nodes or [], "rels": rels or []}


def _node(key: str, label: str = "File", extra: list[str] | None = None, **props) -> dict:
    return {"label": label, "key": key, "extra": extra or [], "props": props}


def _rel(rtype: str, src: str, dst: str, src_label="File", dst_label="File", **props) -> dict:
    return {
        "type": rtype,
        "src_label": src_label,
        "src": src,
        "dst_label": dst_label,
        "dst": dst,
        "props": props,
    }


@pytest.fixture
def run_load(tmp_path, monkeypatch):
    """Run ``load.main()`` against a stub driver; return (exit_code, driver)."""

    def _run(graph: dict, *argv: str, schema: str = "CREATE CONSTRAINT a;\n", wipe_counts=None):
        graph_path = tmp_path / "graph.json"
        graph_path.write_text(json.dumps(graph))
        schema_path = tmp_path / "schema.cypher"
        schema_path.write_text(schema)
        monkeypatch.setattr(load, "SCHEMA", schema_path)

        remaining = list(wipe_counts or [])

        def responder(query: str) -> list[dict]:
            if "DETACH DELETE" in query:
                return [{"c": remaining.pop(0) if remaining else 0}]
            return []

        captured = fake_neo4j(monkeypatch, responder)
        monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), *argv])

        code = load.main()
        return code, captured["driver"], captured

    return _run


def test_chunks_splits_evenly_and_keeps_the_remainder():
    assert list(load.chunks([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]


def test_chunks_of_an_empty_sequence_yields_nothing():
    assert list(load.chunks([], 10)) == []


def test_schema_comments_are_stripped_before_splitting_on_semicolons(run_load):
    """A prose comment containing ';' would otherwise split one statement into
    two fragments, both of which fail."""
    schema = (
        "// Every node carries a unique key; File.key is the join spine.\n"
        "\n"
        "CREATE CONSTRAINT file_key IF NOT EXISTS FOR (n:File) REQUIRE n.key IS UNIQUE;\n"
        "CREATE INDEX file_pkg IF NOT EXISTS FOR (n:File) ON (n.package);\n"
    )

    _, driver, _ = run_load(_graph(), "--no-wipe", schema=schema)

    statements = [q for q, _ in driver.sessions[0].calls]
    assert len(statements) == 2
    assert all(s.startswith("CREATE") for s in statements)
    assert not any("join spine" in s for s in statements)


def test_blank_statements_between_semicolons_are_skipped(run_load):
    _, driver, _ = run_load(_graph(), "--no-wipe", schema="CREATE CONSTRAINT a;\n\n;\n")

    assert [q for q, _ in driver.sessions[0].calls] == ["CREATE CONSTRAINT a"]


def test_nodes_are_merged_on_key_and_grouped_by_label(run_load):
    graph = _graph(nodes=[_node("a.py", language="Python"), _node("b.py", language="Python")])

    code, driver, _ = run_load(graph)

    assert code == 0
    merge = next(q for q, _ in driver.sessions[0].calls if "MERGE (n:`File`" in q)
    assert "UNWIND $rows AS r MERGE (n:`File` {key: r.key}) SET n += r.props" == merge
    rows = next(p["rows"] for q, p in driver.sessions[0].calls if q == merge)
    assert [r["key"] for r in rows] == ["a.py", "b.py"]


def test_extra_labels_become_a_second_set_clause(run_load):
    graph = _graph(nodes=[_node("x.md", extra=["Document", "Config"])])

    _, driver, _ = run_load(graph)

    merge = next(q for q, _ in driver.sessions[0].calls if "MERGE (n:`File`" in q)
    assert merge.endswith("SET n:`Document`:`Config`")


def test_nodes_with_different_extra_labels_are_loaded_as_separate_groups(run_load):
    graph = _graph(nodes=[_node("a.md", extra=["Document"]), _node("b.py")])

    _, driver, _ = run_load(graph)

    merges = [q for q, _ in driver.sessions[0].calls if "MERGE (n:`File`" in q]
    assert len(merges) == 2
    assert sum(1 for q in merges if "SET n:`Document`" in q) == 1


def test_relationships_match_both_endpoints_before_merging(run_load):
    graph = _graph(
        nodes=[_node("a.py"), _node("b.py")],
        rels=[_rel("IMPORTS", "a.py", "b.py", count=3)],
    )

    _, driver, _ = run_load(graph)

    rel_stmt = next(q for q, _ in driver.sessions[0].calls if "MERGE (a)-[e:" in q)
    assert "MATCH (a:`File` {key: r.src}) MATCH (b:`File` {key: r.dst})" in rel_stmt
    assert "MERGE (a)-[e:`IMPORTS`]->(b) SET e += r.props" in rel_stmt
    rows = next(p["rows"] for q, p in driver.sessions[0].calls if q == rel_stmt)
    assert rows == [{"src": "a.py", "dst": "b.py", "props": {"count": 3}}]


def test_rows_are_sent_in_batches_of_the_requested_size(run_load):
    graph = _graph(nodes=[_node(f"f{i}.py") for i in range(5)])

    _, driver, _ = run_load(graph, "--batch", "2")

    merge_calls = [p for q, p in driver.sessions[0].calls if "MERGE (n:`File`" in q]
    assert [len(p["rows"]) for p in merge_calls] == [2, 2, 1]


@pytest.mark.parametrize("batch", ["0", "-1"])
def test_a_non_positive_batch_size_is_rejected_before_touching_the_database(
    tmp_path, monkeypatch, capsys, batch
):
    """REGRESSION. chunks() with a negative size yields no batches while the
    surrounding loops still count every row as loaded, so `--wipe --batch -1`
    exited 0 claiming a full load over an emptied database; `--batch 0` raised
    only after the wipe had already run. The loader must refuse a non-positive
    batch before connecting, applying schema, or deleting anything."""
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(nodes=[_node("a.py")])))
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(
        sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe", "--batch", batch]
    )

    with pytest.raises(SystemExit) as exc:
        load.main()

    assert exc.value.code == 2
    assert "--batch must be a positive integer" in capsys.readouterr().err
    assert "driver" not in captured  # never connected, so nothing was wiped


def test_wipe_drains_until_the_delete_batch_returns_zero(run_load):
    _, driver, _ = run_load(_graph(), "--wipe", wipe_counts=[20000, 137, 0])

    deletes = [q for q, _ in driver.sessions[0].calls if "DETACH DELETE" in q]
    assert len(deletes) == 3
    assert "LIMIT 20000" in deletes[0]


def test_a_flagless_load_never_wipes_the_existing_graph(run_load, capsys):
    """An ordinary load must never imply a graph-wide delete."""
    _, driver, _ = run_load(_graph())

    assert not any("DETACH DELETE" in q for q, _ in driver.sessions[0].calls)
    assert "WARNING: additive load" in capsys.readouterr().err


def test_a_custom_shared_database_is_not_wiped_without_the_explicit_flag(run_load):
    _, driver, _ = run_load(
        _graph(),
        "--uri",
        "bolt://shared.internal:7687",
        "--database",
        "shared",
    )

    assert driver.sessions[0].database == "shared"
    assert not any("DETACH DELETE" in q for q, _ in driver.sessions[0].calls)


def test_no_wipe_remains_an_additive_compatibility_alias(run_load):
    _, driver, _ = run_load(_graph(), "--no-wipe")

    assert not any("DETACH DELETE" in q for q, _ in driver.sessions[0].calls)


def test_connectivity_is_verified_and_the_driver_is_closed(run_load):
    code, driver, _ = run_load(_graph())

    assert code == 0
    assert driver.connectivity_checked is True
    assert driver.closed is True


def test_connection_settings_come_from_the_environment(run_load, monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://graph.internal:7687")
    monkeypatch.setenv("NEO4J_USER", "grapher")
    monkeypatch.setenv("NEO4J_PASSWORD", "from-env")
    monkeypatch.setenv("NEO4J_DATABASE", "kg")

    _, driver, captured = run_load(_graph())

    assert captured["uri"] == "bolt://graph.internal:7687"
    assert captured["auth"] == ("grapher", "from-env")
    assert driver.sessions[0].database == "kg"
    assert not any("DETACH DELETE" in q for q, _ in driver.sessions[0].calls)


def test_explicit_flags_override_the_environment(run_load, monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://from-env:7687")

    _, _, captured = run_load(_graph(), "--uri", "bolt://from-flag:7687")

    assert captured["uri"] == "bolt://from-flag:7687"


def test_an_empty_graph_loads_cleanly(run_load):
    code, driver, _ = run_load(_graph())

    assert code == 0
    assert not any("MERGE" in q for q, _ in driver.sessions[0].calls)
