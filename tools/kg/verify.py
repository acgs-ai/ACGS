#!/usr/bin/env python3
"""Verify the loaded knowledge graph: shape, join health, and live answers.

Passing here means the layers actually joined — not merely that the container
is up. Exit code 1 if any hard check fails.

    uv run --no-project --with neo4j python tools/kg/verify.py
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

# The uniqueness constraints schema.cypher declares — name, label, AND
# property — derived from the file itself so the two cannot drift. If `SHOW
# CONSTRAINTS` is missing any name, schema.cypher was never applied or a
# constraint was dropped; if a name exists but on the wrong label/property
# tuple, `IF NOT EXISTS` will never replace it, so the apply step "succeeds"
# while duplicate nodes remain possible. Either way later loads can mint
# duplicates and fan out relationships, so the shape check must be a hard
# gate, not informational output.
REQUIRED_CONSTRAINT_SCHEMAS: dict[str, tuple[str, str]] = {
    name: (label, prop)
    for name, label, prop in re.findall(
        r"^CREATE CONSTRAINT (\w+) IF NOT EXISTS "
        r"FOR \(\w+:(\w+)\) REQUIRE \w+\.(\w+) IS UNIQUE",
        (Path(__file__).resolve().parent / "schema.cypher").read_text(),
        re.M,
    )
}
REQUIRED_CONSTRAINTS = frozenset(REQUIRED_CONSTRAINT_SCHEMAS)

# "Code evidence" means source code. Keep in lockstep with CODE_EXT in
# reports.py and the Q6/Q6b filters in queries.cypher.
SOURCE_EXT = "['.py', '.pyi', '.ts', '.tsx', '.js', '.mjs', '.cjs', '.rs', '.sh']"

# build_sealed() records lock entries for uninitialized submodules as
# Package.sealed_files_absent instead of minting phantom :File nodes, so a
# non-recursive checkout legitimately has zero sealed File nodes.
SEALED_ABSENT_Q = (
    "MATCH (p:Package) WHERE p.sealed_files_absent IS NOT NULL "
    "RETURN sum(p.sealed_files_absent) AS absent"
)

# extract.py publishes Snapshot.semantic_layer_loaded as the authoritative
# availability flag. Inferring absence from count(f.summary) alone would also
# waive a loaded-but-empty layer (incomplete export, semantic-schema change),
# which is a broken join, not a declared absence. Aggregated so zero Snapshot
# nodes still yield one row; the snapshot-count check reports that case.
SEMANTIC_DECLARED_Q = (
    "MATCH (s:Snapshot) RETURN sum(CASE WHEN s.semantic_layer_loaded THEN 1 ELSE 0 END) AS loaded"
)

CHECKS = [
    (
        "constraints",
        "SHOW CONSTRAINTS YIELD name, labelsOrTypes, properties "
        "RETURN name, labelsOrTypes AS on, properties AS props "
        "ORDER BY name",
    ),
    (
        "node labels",
        "MATCH (n) UNWIND labels(n) AS l RETURN l AS label, count(*) AS n ORDER BY n DESC",
    ),
    ("relationships", "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(*) AS n ORDER BY n DESC"),
    (
        "JOIN HEALTH (the load-bearing check)",
        "MATCH (f:File) RETURN count(*) AS files, "
        "count(f.summary) AS with_semantic, count(f.commit_count) AS with_git, "
        "sum(CASE WHEN f.summary IS NOT NULL AND f.commit_count IS NOT NULL "
        "THEN 1 ELSE 0 END) AS joined_both, "
        "sum(CASE WHEN f.sealed THEN 1 ELSE 0 END) AS sealed",
    ),
    (
        "orphan nodes (no relationships)",
        "MATCH (n) WHERE NOT (n)--() RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC",
    ),
    (
        "snapshot",
        "MATCH (s:Snapshot) RETURN s.git_head AS head, s.git_branch AS branch, "
        "s.ua_commit AS semantic_commit, s.semantic_layer_is_stale AS stale, "
        "s.dirty_count AS dirty",
    ),
]

CATALOG = [
    (
        "Q1 CI gates on gove-zone gateway.py",
        "MATCH (w:Workflow)-[:GATES]->(f:File "
        "{key:'packages/gove-zone/src/gove_zone/gateway.py'}) "
        "RETURN w.name AS workflow, w.jobs AS jobs",
    ),
    (
        "Q4 cross-package co-change (architecture erosion)",
        "MATCH (a:File)-[c:CO_CHANGED]->(b:File) WHERE a.package <> b.package "
        "AND c.count >= 4 "
        "WITH CASE WHEN a.package < b.package THEN a.package ELSE b.package END AS pkg_a, "
        "CASE WHEN a.package < b.package THEN b.package ELSE a.package END AS pkg_b, c "
        "RETURN pkg_a, pkg_b, count(*) AS pairs, sum(c.count) AS joint_commits "
        "ORDER BY joint_commits DESC LIMIT 5",
    ),
    (
        "Q5 hotspots with no test edge",
        # Test evidence must be live AND tracked: a stale snapshot keeps
        # TESTED_BY edges to deleted test files (present=false) and to tests
        # removed from the index but left on disk (tracked=false), which are
        # not coverage. The hotspot itself must be live too — tracked stays
        # true for an unstaged deletion (build_spine records present=false).
        "MATCH (f:File) WHERE f.tracked AND coalesce(f.present, true) "
        "AND NOT f.is_test AND f.hotspot > 0.05 "
        "AND f.language IN ['Python','TypeScript'] "
        "AND NOT EXISTS { MATCH (f)-[:TESTED_BY]->(tt) "
        "WHERE coalesce(tt.present, true) AND coalesce(tt.tracked, true) } "
        "RETURN f.key AS file, f.hotspot AS hotspot, f.commit_count AS commits "
        "ORDER BY hotspot DESC LIMIT 5",
    ),
    (
        "Q6 compliance controls with no code evidence",
        "MATCH (d:File)-[:MAPS_TO]->(c:Control) "
        "WHERE NOT EXISTS { MATCH (c)-[:EVIDENCED_BY]->(e:File) "
        f"WHERE e.ext IN {SOURCE_EXT} }} "
        "RETURN c.framework AS framework, count(DISTINCT c) AS no_evidence "
        "ORDER BY no_evidence DESC",
    ),
    (
        "Q3 sealed files changed in recent history",
        "MATCH (c:Commit)-[:TOUCHED]->(f:File {sealed:true}) "
        "RETURN f.key AS sealed_file, count(c) AS commits, max(c.date) AS last "
        "ORDER BY commits DESC LIMIT 5",
    ),
]


def table(rows: list[dict]) -> str:
    if not rows:
        return "    (no rows)"
    cols = list(rows[0].keys())

    def cell(v):
        s = str(v)
        return s if len(s) <= 60 else s[:57] + "..."

    widths = {c: max(len(c), *(len(cell(r[c])) for r in rows)) for c in cols}
    out = [
        "    " + "  ".join(c.ljust(widths[c]) for c in cols),
        "    " + "  ".join("-" * widths[c] for c in cols),
    ]
    out += ["    " + "  ".join(cell(r[c]).ljust(widths[c]) for c in cols) for r in rows]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD", "acgs-kg-local"))
    ap.add_argument("--database", default=os.environ.get("NEO4J_DATABASE", "neo4j"))
    args = ap.parse_args()

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    driver.verify_connectivity()
    failures: list[str] = []

    with driver.session(database=args.database) as s:
        for title, q in CHECKS:
            rows = [r.data() for r in s.run(q)]
            print(f"\n== {title} ==")
            print(table(rows))
            if title == "constraints":
                missing = sorted(REQUIRED_CONSTRAINTS - {row.get("name") for row in rows})
                if missing:
                    failures.append(
                        "missing required constraints: "
                        + ", ".join(missing)
                        + ": schema.cypher was not (fully) applied, so later "
                        "loads can create duplicate nodes"
                    )
                # Names alone cannot prove the schema was applied: a
                # same-named constraint on the wrong label or property (e.g.
                # file_key on :X(key) instead of :File(key)) is never
                # replaced by schema.cypher's IF NOT EXISTS, so duplicate
                # nodes stay possible while the name check passes.
                by_name = {row.get("name"): row for row in rows}
                for name, (label, prop) in sorted(REQUIRED_CONSTRAINT_SCHEMAS.items()):
                    row = by_name.get(name)
                    if row is None:
                        continue  # already reported as missing above
                    on = list(row.get("on") or [])
                    props = list(row.get("props") or [])
                    if on != [label] or props != [prop]:
                        failures.append(
                            f"constraint {name} exists on "
                            f":{':'.join(on) or '?'}({', '.join(props) or '?'}) "
                            f"but schema.cypher requires :{label}({prop}): "
                            "IF NOT EXISTS will not replace it, so duplicate "
                            f"{label} nodes remain possible"
                        )
            if title == "snapshot" and len(rows) != 1:
                # An otherwise healthy graph with no (or several) Snapshot
                # nodes has no provenance, and reports.py crashes on
                # `s.run(SNAPSHOT_Q).single().data()`. Printing the empty
                # table and passing would hide that.
                failures.append(
                    f"expected exactly 1 Snapshot node, found {len(rows)}: "
                    "graph provenance cannot be established"
                )
            if title.startswith("JOIN HEALTH"):
                r = rows[0]
                if r["files"] == 0:
                    failures.append("no File nodes")
                if r["with_semantic"] == 0:
                    row = s.run(SEMANTIC_DECLARED_Q).single()
                    if row and row["loaded"]:
                        failures.append(
                            "snapshot declares the semantic layer loaded but no "
                            "File carries semantic facts: the export is empty "
                            "or the path keys are not unifying"
                        )
                    else:
                        # build_semantic() skips when no snapshot is tracked
                        # (fresh clone: .understand-anything/ is ignored) and
                        # the Snapshot declares the layer absent. That is a
                        # declared absence, not a broken path-key join.
                        print("    (no semantic snapshot loaded: join threshold not applicable)")
                elif r["joined_both"] < 0.25 * r["files"]:
                    failures.append(
                        f"join health: only {r['joined_both']}/{r['files']} files carry "
                        "both semantic and git facts — path keys are not unifying"
                    )
                if r["sealed"] == 0:
                    # A non-recursive checkout has no live markers: the lock
                    # entries live on Package.sealed_files_absent instead of
                    # :File nodes. Only fail when neither state is present.
                    row = s.run(SEALED_ABSENT_Q).single()
                    absent = (row["absent"] if row else 0) or 0
                    if absent:
                        print(
                            f"    (0 sealed File nodes; {absent} lock entries recorded "
                            "as absent markers on uninitialized submodules)"
                        )
                    else:
                        failures.append("no sealed files linked")

        print("\n\n########## CATALOG QUERIES ##########")
        nonempty = 0
        for title, q in CATALOG:
            rows = [r.data() for r in s.run(q)]
            print(f"\n== {title} ==")
            print(table(rows))
            nonempty += bool(rows)
        if nonempty < 3:
            failures.append(f"only {nonempty}/{len(CATALOG)} catalog queries returned rows")

    driver.close()
    print("\n" + "=" * 60)
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("VERIFY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
