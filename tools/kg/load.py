#!/usr/bin/env python3
"""Load tools/kg/build/graph.json into Neo4j via batched UNWIND ... MERGE.

Replacement is the default: the existing graph is wiped first (constraints
are kept), because MERGE/SET only ever add or update — an incremental reload
after moving commits would keep the previous Snapshot node (reports.py
assumes exactly one), deleted files, and obsolete governance edges forever.
Pass --no-wipe only when the previous graph is known to be a subset.

    uv run --no-project --with neo4j python tools/kg/load.py
"""

from __future__ import annotations

import argparse
import json
import os
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
        default=True,
        help="delete all nodes first (the default: MERGE never removes stale "
        "data, so an incremental reload retains the previous Snapshot, "
        "deleted files and obsolete edges; pass --no-wipe to merge additively)",
    )
    args = ap.parse_args()

    from neo4j import GraphDatabase

    data = json.loads(Path(args.graph).read_text())
    nodes, rels = data["nodes"], data["rels"]

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
            log("--no-wipe: merging additively; stale nodes/edges from a previous load persist")

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
