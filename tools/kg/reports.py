#!/usr/bin/env python3
"""Generate the governance reports from the loaded knowledge graph.

Deterministic: same graph in, same bytes out. Nothing is stamped from the wall
clock — provenance comes from the (:Snapshot) node, so a report can always be
traced to the commit and extraction it was computed from.

    uv run --no-project --with neo4j python tools/kg/reports.py

Writes:
    docs/governance/reports/cross-repo-hotspot-report.md
    docs/governance/reports/compliance-evidence-tiers.md

Reporting rules (both reports):
  - Observable evidence only. Absence of an edge is reported as absence of
    evidence, never as a quality judgement.
  - Where the semantic layer never analyzed a file, that is stated explicitly
    and is NOT collapsed into "no tests". The understand-anything snapshot
    predates the submodule checkout, so every submodule file is unanalyzed.
  - No tier is ever upgraded by inference. UNKNOWN stays UNKNOWN.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "docs" / "governance" / "reports"

# "Implemented" evidence must point at code. A compliance doc citing another
# compliance doc is a citation, not an implementation.
CODE_EXT = {".py", ".pyi", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".rs", ".sh"}
CONFIG_EXT = {".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}

HOTSPOT_LIMIT = 30


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_No rows._\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def test_evidence_state(rec: dict) -> str:
    """Three states, never two. Collapsing 'unanalyzed' into 'untested' would
    manufacture findings for every submodule file."""
    if not rec["ua_covered"]:
        return "not analyzed — outside semantic snapshot"
    if rec["test_edges"] > 0:
        return f"tested ({rec['test_edges']} edge(s))"
    return "no test edge (analyzed)"


def governance_coverage(rec: dict) -> str:
    bits = []
    if rec["gates"]:
        bits.append(f"CI\u00d7{rec['gates']}")
    if rec["sealed"]:
        bits.append("sealed")
    if rec["adrs"]:
        bits.append(f"ADR\u00d7{rec['adrs']}")
    return ", ".join(bits) if bits else "none observed"


# Test evidence must point at a live target: a semantic snapshot predating a
# test file's deletion keeps the TESTED_BY edge, but its target carries
# present=false and the extracted working tree no longer contains the test.
# Counting it would report deleted tests as coverage (and, in the tier report,
# promote compliance evidence to Tier C on the strength of a deleted file).
# The target must also be tracked: a test removed from the index but left on
# disk (tracked=false, present=true) will not exist in a checkout, so it is
# not evidence either. Nodes without the flags (e.g. Symbols) stay countable.
# The subject file must be live as well: build_spine() keeps tracked=true for
# an unstaged deletion and records present=false, and a deleted file is not a
# hotspot anyone can edit or gate. The subject must also be tracked: a
# semantic-retained node for a file removed from the index but left on disk
# (tracked=false, present=true) will not exist in a checkout, so neither
# report may publish it as a current path.
HOTSPOT_Q = """
MATCH (f:File)
WHERE f.tracked AND coalesce(f.present, true) AND f.commit_count IS NOT NULL
OPTIONAL MATCH (f)-[t:TESTED_BY]->(tt)
  WHERE coalesce(tt.present, true) AND coalesce(tt.tracked, true)
WITH f, count(t) AS test_edges
OPTIONAL MATCH (w:Workflow)-[g:GATES]->(f)
  WHERE 'pull_request' IN coalesce(g.events, [])
    AND NOT coalesce(g.conditional, false)
WITH f, test_edges, count(w) AS gates
OPTIONAL MATCH (a:ADR)-[:DECIDES_ON]->(f)
WITH f, test_edges, gates, count(a) AS adrs
RETURN f.key AS path,
       coalesce(f.package, '.') AS package,
       f.commit_count AS commits,
       coalesce(f.author_count, 0) AS contributors,
       coalesce(f.churn, 0) AS churn,
       coalesce(f.ua_covered, false) AS ua_covered,
       coalesce(f.sealed, false) AS sealed,
       coalesce(f.in_submodule, false) AS in_submodule,
       test_edges, gates, adrs
ORDER BY commits DESC, churn DESC, path ASC
LIMIT $limit
"""

CONTROL_PLANE_Q = """
MATCH (f:File)
WHERE f.key STARTS WITH 'packages/acgs-control-plane/'
  AND f.tracked AND coalesce(f.present, true)
  AND (f.key CONTAINS 'migration' OR f.key CONTAINS '/app.py'
       OR f.key CONTAINS 'tenant' OR f.key CONTAINS 'native')
OPTIONAL MATCH (f)-[t:TESTED_BY]->(tt)
  WHERE coalesce(tt.present, true) AND coalesce(tt.tracked, true)
WITH f, count(t) AS test_edges
OPTIONAL MATCH (w:Workflow)-[g:GATES]->(f)
  WHERE 'pull_request' IN coalesce(g.events, [])
    AND NOT coalesce(g.conditional, false)
WITH f, test_edges, count(w) AS gates
OPTIONAL MATCH (a:ADR)-[:DECIDES_ON]->(f)
RETURN f.key AS path, coalesce(f.package,'.') AS package,
       coalesce(f.commit_count,0) AS commits,
       coalesce(f.author_count,0) AS contributors,
       coalesce(f.churn,0) AS churn,
       coalesce(f.ua_covered,false) AS ua_covered,
       coalesce(f.sealed,false) AS sealed,
       coalesce(f.in_submodule,false) AS in_submodule,
       coalesce(f.is_test,false) AS is_test,
       test_edges, gates, count(a) AS adrs
ORDER BY commits DESC, path ASC
"""

REPO_Q = """
MATCH (c:Commit)
RETURN coalesce(c.repo, '.') AS repo, count(*) AS commit_nodes
ORDER BY commit_nodes DESC, repo ASC
"""

SNAPSHOT_Q = """
MATCH (s:Snapshot)
RETURN s.git_head AS head, s.git_branch AS branch, s.ua_commit AS ua_commit,
       s.semantic_layer_loaded AS semantic_loaded,
       s.semantic_layer_is_stale AS stale, s.generated_at AS generated_at,
       s.dirty_count AS dirty, s.enumeration_scopes_skipped AS enumeration_scopes_skipped
"""

COVERAGE_Q = """
MATCH (f:File) WHERE f.tracked
RETURN count(*) AS files,
       sum(CASE WHEN f.ua_covered THEN 1 ELSE 0 END) AS analyzed,
       sum(CASE WHEN f.in_submodule THEN 1 ELSE 0 END) AS in_submodules,
       sum(CASE WHEN f.in_submodule AND f.ua_covered THEN 1 ELSE 0 END)
           AS analyzed_in_submodules
"""

CONTROL_Q = """
MATCH (c:Control)
OPTIONAL MATCH (doc:File)-[:MAPS_TO]->(c)
WITH c, collect(DISTINCT doc.key) AS mapping_docs
OPTIONAL MATCH (c)-[:EVIDENCED_BY]->(e:File)
WITH c, mapping_docs,
     collect(DISTINCT {key: e.key, ext: e.ext, ua: coalesce(e.ua_covered,false)}) AS ev
RETURN c.key AS control, c.framework AS framework,
       mapping_docs, ev
ORDER BY framework ASC, control ASC
"""

TESTED_Q = """
MATCH (f:File)-[:TESTED_BY]->(tt)
WHERE coalesce(tt.present, true) AND coalesce(tt.tracked, true)
RETURN collect(DISTINCT f.key) AS tested
"""

RESOLUTION_Q = """
MATCH (:Control)-[e:EVIDENCED_BY]->(:File)
RETURN coalesce(e.resolved_by, 'unrecorded') AS how, count(*) AS n
ORDER BY n DESC, how ASC
"""


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
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with driver.session(database=args.database) as s:
        snap = s.run(SNAPSHOT_Q).single().data()
        cov = s.run(COVERAGE_Q).single().data()
        hot = [r.data() for r in s.run(HOTSPOT_Q, limit=HOTSPOT_LIMIT)]
        cplane = [r.data() for r in s.run(CONTROL_PLANE_Q)]
        repos = [r.data() for r in s.run(REPO_Q)]
        controls = [r.data() for r in s.run(CONTROL_Q)]
        tested = set(s.run(TESTED_Q).single()["tested"])
        resolutions = {r["how"]: r["n"] for r in s.run(RESOLUTION_Q)}

    # Both statements below are derived from the graph, never hard-coded:
    # a refreshed semantic layer can cover submodule files, and a fresh clone
    # extracts no semantic layer at all (Snapshot.ua_commit is null; slicing
    # it would raise TypeError before either report is written).
    sub_total = cov["in_submodules"]
    sub_analyzed = cov["analyzed_in_submodules"]
    if sub_analyzed:
        submodule_note = (
            f"{sub_analyzed} of the {sub_total} submodule files are analyzed; "
            f"the other {sub_total - sub_analyzed} are outside the snapshot."
        )
    else:
        submodule_note = f"None of the {sub_total} submodule files are analyzed."
    if snap["ua_commit"]:
        semantic_note = (
            f"Semantic layer (understand-anything) is pinned at "
            f"`{snap['ua_commit'][:12]}` and is "
            f"{'STALE relative to HEAD' if snap['stale'] else 'current'}"
        )
    elif snap.get("semantic_loaded"):
        # knowledge-graph.json was ingested but meta.json is missing: the
        # layer is loaded, its commit unknown — treated as stale, not absent.
        semantic_note = (
            "Semantic layer (understand-anything) is loaded but its meta.json "
            "is missing, so its commit is unknown and it is treated as STALE"
        )
    else:
        semantic_note = (
            "Semantic layer (understand-anything) is **absent** "
            "(this extraction recorded no semantic snapshot)"
        )

    provenance = (
        f"> **Provenance.** Computed from the knowledge graph at "
        f"`tools/kg`, extraction `{snap['generated_at']}`, "
        f"parent commit `{snap['head'][:12]}` on `{snap['branch']}`, "
        f"{snap['dirty']} uncommitted paths present.\n>\n"
        f"> {semantic_note}: "
        f"{cov['analyzed']}/{cov['files']} tracked files analyzed. "
        f"{submodule_note}\n>\n"
        f"> Regenerate: `cd tools/kg && make reload && "
        f"uv run --no-project --with neo4j python reports.py`\n"
    )

    # ---------------- Report 1: cross-repo hotspots ----------------
    rows = [
        [
            f"`{r['path']}`",
            r["package"],
            r["commits"],
            r["contributors"],
            r["churn"],
            test_evidence_state(r),
            governance_coverage(r),
        ]
        for r in hot
    ]
    cp_rows = [
        [
            f"`{r['path']}`",
            r["commits"],
            r["contributors"],
            r["churn"],
            test_evidence_state(r),
            governance_coverage(r),
        ]
        for r in cplane
    ]
    unanalyzed_top = sum(1 for r in hot if not r["ua_covered"])
    # The graph's own is_test classification, not a second heuristic: a bare
    # `test_` substring also matched source modules such as
    # tenant_bootstrap_test_worker.py and overstated the test-file count.
    _cp_tests = [r for r in cplane if r["is_test"]]
    cp_test_files = len(_cp_tests)
    cp_test_commits = sum(r["commits"] for r in _cp_tests)

    # Derived, not hard-coded: once the semantic layer is refreshed with
    # submodules initialized, focus-area rows can carry ua_covered=true and
    # asserting "never analyzed" would contradict the table right above it.
    cp_analyzed = sum(1 for r in cplane if r["ua_covered"])
    cp_unanalyzed = len(cplane) - cp_analyzed
    if cp_analyzed:
        cp_semantic_claim = (
            f"the semantic snapshot covers {cp_analyzed} of these {len(cplane)} focus-area paths"
        )
        cp_claim_bullet = (
            f"- {cp_unanalyzed} of the {len(cplane)} rows above are `not analyzed —\n"
            f"  outside semantic snapshot`; for those rows this report makes **no\n"
            f"  claim** about whether the files are tested. The other {cp_analyzed}\n"
            f"  rows carry semantic analysis and report their observed test-edge state."
        )
        cp_link_note = (
            "Where either side is unanalyzed, the graph cannot\n"
            "  link a test file to the modules it exercises."
        )
    else:
        cp_semantic_claim = "the semantic snapshot has never analyzed it"
        cp_claim_bullet = (
            "- Every row above is `not analyzed — outside semantic snapshot`. This report\n"
            "  therefore makes **no claim** about whether these files are tested."
        )
        cp_link_note = (
            "The graph cannot link them to the modules they exercise\n"
            "  because neither side was analyzed."
        )

    r1 = f"""# Cross-repo hotspot report

{provenance}
## How to read this

Every column is a direct graph observation. **No quality inference is made.**
"Modified" means commits recorded in that file's own repository history —
submodules are independent repos and are counted in their own history.

Test-evidence has **three** states, not two:

| State | Meaning |
|---|---|
| `tested (N edge(s))` | The semantic layer analyzed this file and recorded N `TESTED_BY` edges |
| `no test edge (analyzed)` | Analyzed, no `TESTED_BY` edge found. A lead, not a verdict — `TESTED_BY` undercounts barrel and dynamic imports |
| `not analyzed — outside semantic snapshot` | The summariser never saw this file. **Nothing at all is known** about its test coverage from this graph |

Governance coverage lists observed controls: `CI\u00d7N` path-filtered pull-request
workflows gating the file, `sealed` for a constitutional-hash marker, `ADR\u00d7N` for ADRs
citing it. `none observed` means no such edge exists — not that the file is
ungoverned by other means.

## Commit-node distribution by repo

{md_table(["repo", "commit nodes in graph"], [[r["repo"], r["commit_nodes"]] for r in repos])}
Commit nodes are capped at the 400 most recent across all repos; churn and
contributor counts below are computed over **full** history.

## Top {HOTSPOT_LIMIT} most-modified paths (all repos)

{
        md_table(
            [
                "path",
                "package",
                "commits",
                "contributors",
                "churn",
                "test evidence",
                "governance coverage",
            ],
            rows,
        )
    }
{unanalyzed_top} of these {len(hot)} rows are outside the semantic snapshot,
so their test-evidence state is unknown rather than absent.

## Focus: `packages/acgs-control-plane` (migrations, app.py, tenant*, native*)

Requested focus area. This submodule is **not** initialized by
`.github/workflows/constitutional-hash.yml`, and {cp_semantic_claim}.

{
        md_table(
            ["path", "commits", "contributors", "churn", "test evidence", "governance coverage"],
            cp_rows,
        )
    }
### Observable statements only

{cp_claim_bullet}
- Separately observable, and stated so the row above is not misread as
  "no tests exist": {cp_test_files} of the {len(cp_rows)} focus-area paths are
  themselves test files by path convention, carrying {cp_test_commits} commits
  between them. {cp_link_note}
- `governance coverage` for these files reflects parent-repo controls only.
  Any gate defined inside the submodule's own CI is invisible to this graph.
- To convert the unknowns into observations, re-run the semantic layer with
  submodules checked out: `git submodule update --init`, regenerate
  `.understand-anything/knowledge-graph.json` with the understand-anything
  analyzer, then `cd tools/kg && make reload`.
"""  # noqa: E501

    # ---------------- Report 2: compliance evidence tiers ----------------
    MAX_SCOPE = 2
    _meaning = {
        "path": "explicit repo-relative path in the citation — unambiguous",
        "basename-docscope": (
            "bare filename, disambiguated by a full path the same document names elsewhere"
        ),
        "basename": "bare filename, unique across the workspace by luck",
    }
    resolution_rows = [
        [m, n, _meaning.get(m, "unknown")]
        for m, n in sorted(resolutions.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    enum_note = snap.get("enumeration_scopes_skipped", "an unrecorded number of")

    by_fw: dict[str, dict] = {}
    detail_rows: list[list[str]] = []
    for c in controls:
        fw = c["framework"]
        acc = by_fw.setdefault(
            fw,
            {
                "A": 0,
                "B": 0,
                "C": 0,
                "D": 0,
                "cfg_only": 0,
                "cfg_and_doc": 0,
                "doc_only": 0,
                "none": 0,
            },
        )
        ev = [e for e in c["ev"] if e.get("key")]
        code_ev = [e for e in ev if (e["ext"] or "") in CODE_EXT]
        cfg_ev = [e for e in ev if (e["ext"] or "") in CONFIG_EXT]
        doc_ev = [e for e in ev if (e["ext"] or "") not in CODE_EXT | CONFIG_EXT]
        tested_ev = [e for e in code_ev if e["key"] in tested]

        acc["A"] += 1
        tier = "A referenced"
        if code_ev:
            acc["B"] += 1
            tier = "B implemented"
        if tested_ev:
            acc["C"] += 1
            tier = "C tested"
        if not ev:
            acc["none"] += 1
            tier = "A referenced (no evidence target)"
        elif not code_ev:
            # Config-only evidence is not a document and not source: it stays
            # below tier B (source code remains required for "implemented")
            # but is classified as what it is, not mislabelled a document.
            # A control citing both configuration AND documentation is a
            # mixed case counted on its own: folding it into "config-only"
            # overstated a category the summary declares mutually exclusive.
            if cfg_ev and doc_ev:
                acc["cfg_and_doc"] += 1
                tier = "A referenced (evidence targets are configuration and documents)"
            elif cfg_ev:
                acc["cfg_only"] += 1
                tier = "A referenced (evidence target is configuration)"
            else:
                acc["doc_only"] += 1
                tier = "A referenced (evidence target is a document)"

        detail_rows.append(
            [
                c["control"],
                fw,
                tier,
                len(c["mapping_docs"]),
                len(code_ev),
                len(cfg_ev),
                len(doc_ev),
                len(tested_ev),
                "UNKNOWN",
            ]
        )

    fw_rows = [
        [
            fw,
            v["A"],
            v["B"],
            v["C"],
            "UNKNOWN",
            v["cfg_only"],
            v["cfg_and_doc"],
            v["doc_only"],
            v["none"],
        ]
        for fw, v in sorted(by_fw.items())
    ]

    r2 = f"""# Compliance evidence tiers

{provenance}
## Tier definitions

These tiers are **evidence classes observed in the graph**, not conformance
statements. Consistent with `docs/CLAIMS.md`, nothing here asserts that any
framework requirement is satisfied.

| Tier | Definition | Graph criterion |
|---|---|---|
| **A referenced** | A document cites the control | `(:File)-[:MAPS_TO]->(:Control)` |
| **B implemented** | The citation points at **source code** | `(:Control)-[:EVIDENCED_BY]->(:File)` where the target extension is source (`{
        "`, `".join(sorted(CODE_EXT))
    }`) |
| **C tested** | That source file also carries a test edge | B, and the target has `(:File)-[:TESTED_BY]->()` |
| **D externally verified** | Independent third-party attestation | **UNKNOWN for every control.** No artifact in this repository records external verification, so this tier cannot be computed and is never inferred |

Four failure modes are reported explicitly rather than being folded into a tier:

- **evidence target is a document** — the control cites another `.md`, not an
  implementation. Counting these as "implemented" is the single easiest way to
  overclaim compliance, so they are broken out.
- **evidence target is configuration**: the control cites only configuration
  (`{"`, `".join(sorted(CONFIG_EXT))}`). Real evidence of *something*, but not
  source code, so it stays below tier B and is not mislabelled a document.
- **evidence targets are configuration and documents** — the control cites
  both, and neither is source code. Counted on its own so "config-only" and
  "doc-only" stay mutually exclusive and match the per-control detail counts.
- **no evidence target** — cited in prose with no resolvable file reference.

## Per-framework summary

{
        md_table(
            [
                "framework",
                "A referenced",
                "B implemented",
                "C tested",
                "D externally verified",
                "cited, config-only evidence",
                "cited, config+doc evidence",
                "cited, doc-only evidence",
                "cited, no evidence",
            ],
            fw_rows,
        )
    }
## Per-control detail

{
        md_table(
            [
                "control",
                "framework",
                "highest tier reached",
                "mapping docs",
                "code evidence",
                "config evidence",
                "doc evidence",
                "tested code",
                "external",
            ],
            sorted(detail_rows, key=lambda r: (r[1], r[0])),
        )
    }
## How the evidence links were resolved

Tier B/C rest on matching a citation in prose to a file. Not all matches are
equally trustworthy, so the method is recorded on every edge:

{md_table(["resolution", "links", "meaning"], resolution_rows)}
`basename` is the weakest: a bare `` `foo.py` `` that resolved only because
exactly one file in the workspace carries that name. Treat those as leads.

Citations appearing in an **enumeration** — a sentence listing more than
{MAX_SCOPE} control ids — are recorded as references but never as evidence:
{enum_note} such scopes were skipped. Binding every path in an index sentence
to every control it lists is how a document that says "these controls are
listed" becomes a false implementation claim.

## Caveats that bound every number above

1. **Control extraction is regex-based** over crosswalk and mapping documents,
   scoped to a paragraph or table row. It detects citations; it does not read
   intent. A control not cited in a scanned document is simply absent here.
2. **Tier C is bounded by the semantic snapshot.** `TESTED_BY` exists only for
   analyzed files ({cov["analyzed"]}/{cov["files"]}), so tier C is a floor, not
   a measurement.
3. **No tier may be upgraded without new graph evidence.** Re-running this
   report against an unchanged graph cannot raise a tier. New evidence enters
   the graph by adding code, tests, or an external attestation artifact, or by
   refreshing the semantic snapshot: re-analysis can mint `TESTED_BY` edges for
   tests and sources that already existed, promoting a control from tier B to
   tier C without any code, test, or attestation being added.
"""  # noqa: E501

    (OUT_DIR / "cross-repo-hotspot-report.md").write_text(r1)
    (OUT_DIR / "compliance-evidence-tiers.md").write_text(r2)
    driver.close()

    print(
        f"wrote {OUT_DIR.relative_to(ROOT)}/cross-repo-hotspot-report.md "
        f"({len(hot)} hotspot rows, {len(cplane)} control-plane rows)"
    )
    print(
        f"wrote {OUT_DIR.relative_to(ROOT)}/compliance-evidence-tiers.md "
        f"({len(controls)} controls across {len(by_fw)} frameworks)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
