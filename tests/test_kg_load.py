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

    def _run(
        graph: dict,
        *argv: str,
        schema: str = "CREATE CONSTRAINT a;\n",
        wipe_counts=None,
        fail_on: str | None = None,
    ):
        graph_path = tmp_path / "graph.json"
        graph_path.write_text(json.dumps(graph))
        schema_path = tmp_path / "schema.cypher"
        schema_path.write_text(schema)
        monkeypatch.setattr(load, "SCHEMA", schema_path)

        remaining = list(wipe_counts or [])

        def responder(query: str) -> list[dict]:
            if fail_on and fail_on in query:
                raise RuntimeError(f"injected failure for {fail_on}")
            if "DETACH DELETE" in query:
                return [{"c": remaining.pop(0) if remaining else 0}]
            return []

        captured = fake_neo4j(monkeypatch, responder)
        monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), *argv])

        try:
            code: int | RuntimeError = load.main()
        except RuntimeError as exc:
            code = exc
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


def test_schema_is_atomic_and_wipe_nodes_rels_share_one_data_transaction(run_load):
    graph = _graph(
        nodes=[_node("a.py"), _node("b.py")],
        rels=[_rel("IMPORTS", "a.py", "b.py")],
    )

    code, driver, _ = run_load(graph, "--wipe", wipe_counts=[2, 0])

    assert code == 0
    session = driver.sessions[0]
    assert session.autocommit_calls == []
    assert len(session.transactions) == 2
    schema_tx, data_tx = session.transactions
    assert schema_tx.committed is True
    assert schema_tx.rolled_back is False
    assert [query for query, _ in schema_tx.calls] == ["CREATE CONSTRAINT a"]
    assert data_tx.committed is True
    assert data_tx.rolled_back is False
    queries = [query for query, _ in data_tx.calls]
    assert any("DETACH DELETE" in query for query in queries)
    assert any("MERGE (n:`File`" in query for query in queries)
    assert any("MERGE (a)-[e:`IMPORTS`]" in query for query in queries)


def test_schema_failure_rolls_back_before_the_data_transaction_starts(run_load):
    result, driver, _ = run_load(
        _graph(),
        "--wipe",
        schema="CREATE CONSTRAINT a; CREATE INDEX b;",
        fail_on="CREATE INDEX b",
    )

    assert isinstance(result, RuntimeError)
    session = driver.sessions[0]
    assert session.autocommit_calls == []
    assert len(session.transactions) == 1
    schema_tx = session.transactions[0]
    assert schema_tx.committed is False
    assert schema_tx.rolled_back is True
    assert [query for query, _ in schema_tx.calls] == ["CREATE CONSTRAINT a", "CREATE INDEX b"]
    assert not any("DETACH DELETE" in query for query, _ in session.calls)


def test_relationship_failure_rolls_back_wipe_and_all_node_batches(run_load):
    graph = _graph(
        nodes=[_node("a.py"), _node("b.py")],
        rels=[_rel("IMPORTS", "a.py", "b.py")],
    )

    result, driver, _ = run_load(
        graph,
        "--wipe",
        wipe_counts=[2, 0],
        fail_on="MERGE (a)-[e:`IMPORTS`]",
    )

    assert isinstance(result, RuntimeError)
    session = driver.sessions[0]
    assert session.autocommit_calls == []
    assert len(session.transactions) == 2
    schema_tx, data_tx = session.transactions
    assert schema_tx.committed is True
    assert data_tx.committed is False
    assert data_tx.rolled_back is True
    assert any("DETACH DELETE" in query for query, _ in data_tx.calls)
    assert any("MERGE (n:`File`" in query for query, _ in data_tx.calls)


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


def test_a_dangling_relationship_is_refused_before_touching_the_database(
    tmp_path, monkeypatch, capsys
):
    """REGRESSION. The relationship loader's MATCH clauses silently discard a
    row whose endpoint is absent — a dangling rel after an extractor-schema
    change, or a hand-built --graph override — while the counter still added
    the full batch and the loader exited 0 claiming the relationship loaded.
    A partially linked graph must never be published as a successful load."""
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(
        json.dumps(_graph(nodes=[_node("a.py")], rels=[_rel("IMPORTS", "a.py", "ghost.py")]))
    )
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    err = capsys.readouterr().err
    assert "dangling relationship" in err
    assert "ghost.py" in err
    assert "driver" not in captured  # never connected, so nothing was wiped


def test_duplicate_node_identities_are_refused_before_touching_the_database(
    tmp_path, monkeypatch, capsys
):
    """REGRESSION. The node loader MERGEs on (label, key), so two input rows
    sharing an identity silently collapsed into one Neo4j node with the later
    row's SET overwriting the earlier row's properties — after an explicit
    --wipe the database held fewer nodes than supplied while the loader
    exited 0 and logged every input row as loaded. Duplicate identities must
    be refused before connecting or deleting anything."""
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(nodes=[_node("a.py", size=1), _node("a.py", size=2)])))
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    err = capsys.readouterr().err
    assert "duplicate node identity (:File {key: 'a.py'})" in err
    assert "refusing" in err
    assert "driver" not in captured  # never connected, so nothing was wiped


def test_duplicate_relationship_identities_are_refused_before_touching_the_database(
    tmp_path, monkeypatch, capsys
):
    """REGRESSION. The relationship loader MERGEs on (type, endpoints), so two
    input rows sharing an identity silently collapsed into one edge with the
    later row's SET overwriting the earlier row's properties — while
    loaded_rels still counted and logged both input rows, publishing fewer
    edges than supplied with a successful exit. Duplicate identities must be
    refused before connecting or deleting anything, exactly like nodes."""
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(
        json.dumps(
            _graph(
                nodes=[_node("a.py"), _node("b.py")],
                rels=[
                    _rel("IMPORTS", "a.py", "b.py", weight=1),
                    _rel("IMPORTS", "a.py", "b.py", weight=2),
                ],
            )
        )
    )
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    err = capsys.readouterr().err
    assert "duplicate relationship identity" in err
    assert "(:File {key: 'a.py'})-[:IMPORTS]->(:File {key: 'b.py'})" in err
    assert "refusing" in err
    assert "driver" not in captured  # never connected, so nothing was wiped


def test_same_endpoints_under_different_types_are_not_duplicate_relationships(run_load):
    """(type, endpoints) is the identity: two relationship types between the
    same pair of nodes are distinct edges and must still load."""
    graph = _graph(
        nodes=[_node("a.py"), _node("b.py")],
        rels=[_rel("IMPORTS", "a.py", "b.py"), _rel("COVERS", "a.py", "b.py")],
    )

    code, driver, _ = run_load(graph)

    assert code == 0
    merges = [q for q, _ in driver.sessions[0].calls if "MERGE (a)" in q]
    assert any("[e:`IMPORTS`]" in q for q in merges)
    assert any("[e:`COVERS`]" in q for q in merges)


def test_same_key_under_different_labels_is_not_a_duplicate(run_load):
    """(label, key) is the identity: a File and a Package sharing a key are
    distinct nodes and must still load."""
    graph = _graph(nodes=[_node("core"), _node("core", label="Package")])

    code, driver, _ = run_load(graph)

    assert code == 0
    merges = [q for q, _ in driver.sessions[0].calls if "MERGE" in q]
    assert any("MERGE (n:`File`" in q for q in merges)
    assert any("MERGE (n:`Package`" in q for q in merges)


def test_a_structurally_incomplete_node_is_refused_before_touching_the_database(
    tmp_path, monkeypatch, capsys
):
    """REGRESSION. The endpoint precheck reads only identity fields, so a
    node with a valid (label, key) but no `props` (a hand-built --graph
    override) passed it, the explicitly requested `--wipe` completed its
    DETACH DELETE, and only then did the grouping loop raise KeyError: the
    replacement the user asked for was left empty because malformed input
    was discovered after destruction. Every field the loading loops read
    must be validated before the loader connects, applies schema, or wipes."""
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(nodes=[{"label": "File", "key": "a.py", "extra": []}])))
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    err = capsys.readouterr().err
    assert "node[0] is missing 'props'" in err
    assert "refusing" in err
    assert "driver" not in captured  # never connected, so nothing was wiped


def test_a_mistyped_relationship_row_is_refused_before_touching_the_database(
    tmp_path, monkeypatch, capsys
):
    """Type errors are structural too: a rel whose `props` is a scalar would
    raise only inside the batched UNWIND, after the schema and any wipe."""
    rel = _rel("IMPORTS", "a.py", "b.py")
    rel["props"] = None
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(nodes=[_node("a.py"), _node("b.py")], rels=[rel])))
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    err = capsys.readouterr().err
    assert "rel[0].props is NoneType, expected dict" in err
    assert "driver" not in captured


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({"x": 1}, "dict is not a storable Neo4j property type"),
        ([[1, 2]], "array element is list; Neo4j arrays hold only primitives"),
        ([{"x": 1}], "array element is dict; Neo4j arrays hold only primitives"),
        ([1, None], "array properties cannot contain null"),
        ([1, "a"], "array mixes number and string elements"),
        ([True, 1], "array mixes boolean and number elements"),
    ],
)
def test_a_neo4j_invalid_property_value_is_refused_before_touching_the_database(
    tmp_path, monkeypatch, capsys, value, message
):
    """REGRESSION. The structural check accepted any `props` dict, so a row
    with all required fields but a Neo4j-invalid property value (a nested
    map like `{"meta": {"x": 1}}`, a mixed or null-bearing array) passed the
    pre-wipe validation; `--wipe` then emptied the database before the first
    `SET n += r.props` raised. Every property value must be validated as
    storable before the loader connects, applies schema, or deletes data."""
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(nodes=[_node("a.py", meta=value)])))
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    err = capsys.readouterr().err
    assert f"node[0].props['meta']: {message}" in err
    assert "driver" not in captured  # never connected, so nothing was wiped


def test_relationship_property_values_are_validated_too(tmp_path, monkeypatch, capsys):
    rel = _rel("IMPORTS", "a.py", "b.py", meta={"nested": True})
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(nodes=[_node("a.py"), _node("b.py")], rels=[rel])))
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    assert "rel[0].props['meta']: dict is not a storable Neo4j property type" in (
        capsys.readouterr().err
    )
    assert "driver" not in captured


def test_valid_primitive_and_homogeneous_array_properties_still_load(run_load):
    graph = _graph(
        nodes=[
            _node("a.py", language="Python", churn=3, hotspot=0.5, sealed=False, summary=None),
            _node("b.py", authors=["ann", "bob"], counts=[1, 2, 3], mixed_numbers=[1, 2.5]),
        ]
    )

    code, _, _ = run_load(graph)

    assert code == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda n, r: n.__setitem__("label", "File` ) DETACH DELETE (n) //"),
        lambda n, r: n.__setitem__("extra", ["Doc`ument"]),
        lambda n, r: r.__setitem__("type", "IMPORTS`]->() DETACH DELETE"),
        lambda n, r: r.__setitem__("src_label", "File`"),
        lambda n, r: r.__setitem__("dst_label", "no spaces allowed"),
    ],
)
def test_a_non_identifier_dynamic_label_or_type_is_refused(tmp_path, monkeypatch, capsys, mutate):
    """REGRESSION. Labels, extra labels, and relationship types are spliced
    into the Cypher text inside backticks, not passed as parameters, so a
    backtick-bearing or otherwise malformed name breaks (or injects into)
    the generated statement, and only inside the batched UNWIND after the
    schema and any wipe. They must be plain identifiers up front."""
    node = _node("a.py")
    rel = _rel("IMPORTS", "a.py", "a.py")
    mutate(node, rel)
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(nodes=[node], rels=[rel])))
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path), "--wipe"])

    code = load.main()

    assert code == 1
    assert "is not a plain Cypher identifier" in capsys.readouterr().err
    assert "driver" not in captured  # never connected, so nothing was wiped


def test_a_relationship_whose_endpoint_label_mismatches_is_dangling(tmp_path, monkeypatch, capsys):
    """Endpoint identity is (label, key), exactly what the MATCH clauses use:
    a rel naming the right key under the wrong label would also be silently
    dropped by Cypher."""
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(
        json.dumps(
            _graph(
                nodes=[_node("a.py"), _node("b.py")],
                rels=[_rel("GATES", "a.py", "b.py", src_label="Workflow")],
            )
        )
    )
    captured = fake_neo4j(monkeypatch, lambda query: [])
    monkeypatch.setattr(sys, "argv", ["load.py", "--graph", str(graph_path)])

    code = load.main()

    assert code == 1
    assert "1 dangling relationship(s)" in capsys.readouterr().err
    assert "driver" not in captured


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
