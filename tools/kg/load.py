#!/usr/bin/env python3
"""Load tools/kg/build/graph.json into Neo4j via batched UNWIND ... MERGE.

Loads are additive by default. Pass --wipe to explicitly replace the existing
graph first (constraints are kept). MERGE/SET only add or update, so a
flagless load can retain the previous Snapshot node (reports.py assumes
exactly one), deleted files, and obsolete governance edges.

    uv run --no-project --with neo4j python tools/kg/load.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
GRAPH = HERE / "build" / "graph.json"
SCHEMA = HERE / "schema.cypher"


def log(msg: str) -> None:
    print(f"[load] {msg}", file=sys.stderr)


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


# Every field the loading loops read, with its expected type. The endpoint
# precheck below touches only identity fields, so a row with valid endpoints
# but a missing `extra` or `props` (a hand-built --graph override) used to
# pass it, survive the explicitly requested DETACH DELETE, and only then
# raise KeyError in the grouping loop: the replacement the user asked for
# was destroyed in exchange for nothing. Validate the full shape up front.
NODE_FIELDS: dict[str, type] = {"label": str, "key": str, "extra": list, "props": dict}
REL_FIELDS: dict[str, type] = {
    "type": str,
    "src_label": str,
    "src": str,
    "dst_label": str,
    "dst": str,
    "props": dict,
}

# Fields interpolated into the Cypher text (inside backticks) rather than
# passed as parameters. A backtick or other exotic character in one of these
# breaks (or injects into) the generated statement, and only inside the
# batched UNWIND, after the schema and any wipe. Restrict them to plain
# identifiers up front; every label/type the extractor emits already is one.
NODE_IDENT_FIELDS = ("label",)
REL_IDENT_FIELDS = ("type", "src_label", "dst_label")
CYPHER_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def prop_error(value) -> str | None:
    """Why Neo4j cannot store ``value`` as a property, or None if it can.

    ``SET n += r.props`` accepts only primitives and homogeneous arrays of
    non-null primitives. A nested map, a mixed-type or null-bearing array,
    or any other payload passes a dict-shape check but raises only inside
    the batched UNWIND, after ``--wipe`` has already emptied the database.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return None
    if isinstance(value, list):
        families = set()
        for elem in value:
            if elem is None:
                return "array properties cannot contain null"
            if isinstance(elem, bool):
                families.add("boolean")
            elif isinstance(elem, (int, float)):
                families.add("number")
            elif isinstance(elem, str):
                families.add("string")
            else:
                return f"array element is {type(elem).__name__}; Neo4j arrays hold only primitives"
        if len(families) > 1:
            return "array mixes " + " and ".join(sorted(families)) + " elements"
        return None
    return f"{type(value).__name__} is not a storable Neo4j property type"


def malformed_rows(
    rows: list, fields: dict[str, type], kind: str, ident_fields: tuple[str, ...]
) -> list[str]:
    """Human-readable structural errors for every invalid row of one kind."""
    errors: list[str] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"{kind}[{i}] is {type(row).__name__}, not an object")
            continue
        for field, ftype in fields.items():
            if field not in row:
                errors.append(f"{kind}[{i}] is missing {field!r}")
            elif not isinstance(row[field], ftype):
                errors.append(
                    f"{kind}[{i}].{field} is {type(row[field]).__name__}, expected {ftype.__name__}"
                )
        for field in ident_fields:
            value = row.get(field)
            if isinstance(value, str) and not CYPHER_IDENT.fullmatch(value):
                errors.append(f"{kind}[{i}].{field} {value!r} is not a plain Cypher identifier")
        extra = row.get("extra")
        if isinstance(extra, list):
            if not all(isinstance(x, str) for x in extra):
                errors.append(f"{kind}[{i}].extra must contain only strings")
            else:
                for x in extra:
                    if not CYPHER_IDENT.fullmatch(x):
                        errors.append(
                            f"{kind}[{i}].extra label {x!r} is not a plain Cypher identifier"
                        )
        props = row.get("props")
        if isinstance(props, dict):
            for key in sorted(props):
                err = prop_error(props[key])
                if err:
                    errors.append(f"{kind}[{i}].props[{key!r}]: {err}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD", "acgs-kg-local"))
    ap.add_argument("--database", default=os.environ.get("NEO4J_DATABASE", "neo4j"))
    ap.add_argument("--graph", default=str(GRAPH))
    ap.add_argument("--batch", type=int, default=5000)
    ap.add_argument(
        "--wipe",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="explicitly delete all nodes before loading; without this flag, "
        "MERGE adds or updates data and may retain stale nodes and edges",
    )
    args = ap.parse_args()

    # A non-positive batch makes chunks() yield nothing (--batch -1) or raise
    # mid-load (--batch 0) while the counters still claim every row loaded —
    # after an explicit --wipe that reports success over an emptied database.
    # Refuse before connecting, applying schema, or deleting anything.
    if args.batch < 1:
        ap.error(f"--batch must be a positive integer (got {args.batch})")

    from neo4j import GraphDatabase

    data = json.loads(Path(args.graph).read_text())
    nodes, rels = data["nodes"], data["rels"]

    # Structural validation must complete before connecting, applying schema,
    # or wiping: discovering malformed input after an explicit DETACH DELETE
    # leaves the requested replacement empty (see malformed_rows above). That
    # includes value-level validation: a Neo4j-invalid property payload or a
    # non-identifier dynamic label fails only inside the batched UNWIND.
    invalid = malformed_rows(nodes, NODE_FIELDS, "node", NODE_IDENT_FIELDS) + malformed_rows(
        rels, REL_FIELDS, "rel", REL_IDENT_FIELDS
    )
    if invalid:
        for msg in invalid[:10]:
            log(f"ERROR: malformed row: {msg}")
        log(
            f"ERROR: {len(invalid)} structural error(s) in {args.graph}: the load "
            "would fail after the database had already been modified; refusing"
        )
        return 1

    # The relationship loader MATCHes both endpoints before MERGE, so Cypher
    # silently discards a row whose endpoint is absent — a dangling rel after
    # an extractor-schema change, or a hand-built --graph override — while
    # the counters still claim it loaded and the loader exits 0. A partially
    # linked graph published as success is false governance evidence, so
    # endpoint identities are prevalidated against the input nodes and the
    # whole load is refused before connecting or wiping anything.
    node_keys = {(n["label"], n["key"]) for n in nodes}
    dangling = [
        r
        for r in rels
        if (r["src_label"], r["src"]) not in node_keys
        or (r["dst_label"], r["dst"]) not in node_keys
    ]
    if dangling:
        for r in dangling[:10]:
            log(
                "ERROR: dangling relationship "
                f"(:{r['src_label']} {{key: {r['src']!r}}})-[:{r['type']}]->"
                f"(:{r['dst_label']} {{key: {r['dst']!r}}}): "
                "one or both endpoints are not in the input graph"
            )
        log(
            f"ERROR: {len(dangling)} dangling relationship(s): the MATCH clauses "
            "would silently drop them and claim a full load; refusing"
        )
        return 1

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    driver.verify_connectivity()

    with driver.session(database=args.database) as s:
        # Strip comment lines BEFORE splitting: prose comments may contain ';'.
        sql = "\n".join(
            ln
            for ln in SCHEMA.read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith("//")
        )
        for raw in sql.split(";"):
            stmt = raw.strip()
            if stmt:
                s.run(stmt)
        log("schema applied")

        if args.wipe:
            deleted = 1
            total = 0
            while deleted:
                rec = s.run(
                    "MATCH (n) WITH n LIMIT 20000 DETACH DELETE n RETURN count(*) AS c"
                ).single()
                deleted = rec["c"]
                total += deleted
            log(f"wiped {total} nodes")
        else:
            log(
                "WARNING: additive load; stale nodes/edges from a previous load may persist. "
                "Use --wipe only for an explicit full replacement"
            )

        groups: dict[tuple, list[dict]] = defaultdict(list)
        for n in nodes:
            groups[(n["label"], tuple(n["extra"]))].append({"key": n["key"], "props": n["props"]})
        loaded = 0
        for (label, extra), rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            label_set = "".join(f":`{x}`" for x in extra)
            cypher = f"UNWIND $rows AS r MERGE (n:`{label}` {{key: r.key}}) SET n += r.props" + (
                f" SET n{label_set}" if label_set else ""
            )
            for batch in chunks(rows, args.batch):
                s.run(cypher, rows=batch)
            loaded += len(rows)
            log(f"  nodes {label}{label_set}: {len(rows)}")
        log(f"loaded {loaded} nodes")

        rgroups: dict[tuple, list[dict]] = defaultdict(list)
        for r in rels:
            rgroups[(r["type"], r["src_label"], r["dst_label"])].append(
                {"src": r["src"], "dst": r["dst"], "props": r["props"]}
            )
        rloaded = 0
        for (rtype, sl, dl), rows in sorted(rgroups.items(), key=lambda kv: -len(kv[1])):
            cypher = (
                f"UNWIND $rows AS r "
                f"MATCH (a:`{sl}` {{key: r.src}}) MATCH (b:`{dl}` {{key: r.dst}}) "
                f"MERGE (a)-[e:`{rtype}`]->(b) SET e += r.props"
            )
            for batch in chunks(rows, args.batch):
                s.run(cypher, rows=batch)
            rloaded += len(rows)
            log(f"  rels {sl}-[:{rtype}]->{dl}: {len(rows)}")
        log(f"loaded {rloaded} relationships")

    driver.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
