// ===========================================================================
// govern-zone knowledge graph — curated query catalog
// Each block answers a question no single existing tool in this repo answers,
// because it joins two or more ingest layers on File.key.
// Run in Neo4j Browser (http://localhost:7474) or:
//   docker exec -i acgs-kg-neo4j cypher-shell -u neo4j -p acgs-kg-local
// ===========================================================================

// --- Q0. Snapshot honesty: how stale is the semantic layer? ---------------
MATCH (s:Snapshot)
RETURN s.git_head AS head, s.git_branch AS branch, s.ua_commit AS semantic_commit,
       s.semantic_layer_is_stale AS stale, s.dirty_count AS dirty_paths,
       s.generated_at AS generated_at;

// --- Q1. Which CI workflows gate the file I am about to edit? -------------
// Swap the path. Zero rows = the change ships with no path-filtered PR gate.
MATCH (w:Workflow)-[g:GATES]->(f:File {key: 'packages/gove-zone/src/gove_zone/gateway.py'})
WHERE 'pull_request' IN coalesce(g.events, [])
RETURN w.name AS workflow, w.path_filters AS filters, w.jobs AS jobs;

// --- Q2. Ungated source: code with no path-filtered PR workflow ------------
MATCH (f:File)
WHERE f.tracked AND NOT f.is_test
  AND f.language IN ['Python', 'TypeScript', 'JavaScript']
  AND NOT EXISTS {
    MATCH (:Workflow)-[g:GATES]->(f)
    WHERE 'pull_request' IN coalesce(g.events, [])
  }
RETURN f.package AS package, count(*) AS ungated_files,
       collect(f.key)[0..5] AS examples
ORDER BY ungated_files DESC;

// --- Q3. Sealed-file drift: hash-sealed files changed recently ------------
MATCH (c:Commit)-[t:TOUCHED]->(f:File {sealed: true})
RETURN f.key AS sealed_file, f.sealed_hash AS hash, count(c) AS recent_commits,
       collect(DISTINCT c.author) AS authors, max(c.date) AS last_change
ORDER BY recent_commits DESC LIMIT 25;

// --- Q3b. Sealed change with no ADR covering the same package -------------
MATCH (c:Commit)-[:TOUCHED]->(f:File {sealed: true})
WHERE NOT EXISTS { MATCH (:ADR)-[:DECIDES_ON]->(g:File)
                   WHERE g.package = f.package }
RETURN DISTINCT f.key AS sealed_file, f.package AS package, max(c.date) AS last_change
ORDER BY last_change DESC LIMIT 25;

// --- Q4. Architecture erosion: cross-package co-change --------------------
// CO_CHANGED is stored one-way on a path-sorted pair, so canonicalise the
// package pair before aggregating or the same coupling shows up twice.
MATCH (a:File)-[c:CO_CHANGED]->(b:File)
WHERE a.package <> b.package AND c.count >= 4
WITH CASE WHEN a.package < b.package THEN a.package ELSE b.package END AS pkg_a,
     CASE WHEN a.package < b.package THEN b.package ELSE a.package END AS pkg_b, c
RETURN pkg_a, pkg_b, count(*) AS coupled_pairs,
       sum(c.count) AS joint_commits, round(avg(c.jaccard), 3) AS avg_jaccard
ORDER BY joint_commits DESC LIMIT 20;

// --- Q5. Hotspots with no test edge ---------------------------------------
// hotspot = normalised churn x complexity weight. TESTED_BY undercounts
// barrel/dynamic imports — treat as leads, not verdicts.
MATCH (f:File)
WHERE f.tracked AND NOT f.is_test AND f.hotspot > 0.05
  AND f.language IN ['Python', 'TypeScript']
  AND NOT (f)-[:TESTED_BY]->()
RETURN f.key AS file, f.hotspot AS hotspot, f.churn AS churn,
       f.commit_count AS commits, f.complexity AS complexity, f.summary AS summary
ORDER BY hotspot DESC LIMIT 20;

// --- Q6. Compliance chain breaks: control cited but no code evidence ------
// "Code evidence" means a source-code target (same extension set as the tier
// report in reports.py). A control whose only evidence is a .md or config
// file has no source implementation and must still surface here.
MATCH (d:File)-[:MAPS_TO]->(ctl:Control)
WHERE NOT EXISTS {
  MATCH (ctl)-[:EVIDENCED_BY]->(e:File)
  WHERE e.ext IN ['.py', '.pyi', '.ts', '.tsx', '.js', '.mjs', '.cjs', '.rs', '.sh']
}
RETURN ctl.framework AS framework, count(DISTINCT ctl) AS controls_without_evidence,
       collect(DISTINCT ctl.key)[0..8] AS examples
ORDER BY controls_without_evidence DESC;

// --- Q6b. Full evidence chain for one framework ---------------------------
// code_evidence_files is restricted to source targets; doc/config citations
// are collected separately so they cannot masquerade as implementations.
MATCH (doc:File)-[:MAPS_TO]->(ctl:Control {framework: 'EU AI Act'})
OPTIONAL MATCH (ctl)-[:EVIDENCED_BY]->(code:File)
  WHERE code.ext IN ['.py', '.pyi', '.ts', '.tsx', '.js', '.mjs', '.cjs', '.rs', '.sh']
OPTIONAL MATCH (ctl)-[:EVIDENCED_BY]->(other:File)
  WHERE NOT other.ext IN ['.py', '.pyi', '.ts', '.tsx', '.js', '.mjs', '.cjs', '.rs', '.sh']
RETURN ctl.key AS control, collect(DISTINCT doc.key) AS mapping_docs,
       collect(DISTINCT code.key) AS code_evidence_files,
       collect(DISTINCT other.key) AS non_code_evidence_files
ORDER BY control;

// --- Q7. ADR reach: decisions touching code that is dirty right now --------
MATCH (a:ADR)-[:DECIDES_ON]->(f:File)
WHERE f.dirty_at_extract
RETURN a.key AS adr, a.status AS status, a.title AS title,
       collect(f.key) AS dirty_files_it_governs
ORDER BY adr;

// --- Q7b. ADR supersession chains -----------------------------------------
MATCH p = (a:ADR)-[:SUPERSEDES*]->(b:ADR)
RETURN [n IN nodes(p) | n.key + ' (' + n.status + ')'] AS chain
ORDER BY length(p) DESC;

// --- Q8. Orphan documentation: no inbound in-repo reference ---------------
MATCH (f:File)
WHERE f.tracked AND f.ext = '.md' AND NOT (:File)-[:LINKS_TO]->(f)
  AND NOT f.key IN ['README.md', 'CLAUDE.md', 'AGENTS.md']
RETURN f.package AS package, count(*) AS orphan_docs,
       collect(f.key)[0..6] AS examples
ORDER BY orphan_docs DESC;

// --- Q9. Layer coupling: imports that cross architectural layers ----------
MATCH (a:File)-[:IN_LAYER]->(la:Layer),
      (a)-[:IMPORTS]->(b:File)-[:IN_LAYER]->(lb:Layer)
WHERE la <> lb
RETURN la.name AS from_layer, lb.name AS to_layer, count(*) AS imports
ORDER BY imports DESC LIMIT 20;

// --- Q10. Semantic blind spots: tracked code the summariser never saw -----
// "Code" is the source-language set the other code-oriented queries use
// (Q2/Q5, plus Rust and Shell to mirror the tier report's source extensions).
// `language <> 'Other'` also admitted Markdown/JSON/YAML/TOML/lock files,
// which dominate a checkout without a semantic snapshot.
MATCH (f:File)
WHERE f.tracked AND NOT f.ua_covered
  AND f.language IN ['Python', 'TypeScript', 'JavaScript', 'Rust', 'Shell']
RETURN f.package AS package, count(*) AS uncovered,
       collect(f.key)[0..6] AS examples
ORDER BY uncovered DESC LIMIT 15;

// --- Q11. Bus factor: single-author, high-churn, governance-critical ------
MATCH (f:File)
WHERE f.author_count = 1 AND f.commit_count >= 5
  AND (f.sealed OR f.package STARTS WITH 'packages/')
RETURN f.key AS file, f.package AS package, f.commit_count AS commits,
       f.churn AS churn, f.sealed AS sealed
ORDER BY churn DESC LIMIT 20;

// --- Q12. Most-referenced knowledge: doc authority ranking ----------------
// LINKS_TO can target any tracked file; without the extension filter this
// "doc authority" ranking surfaces source, config, and lock files too.
MATCH (f:File)<-[l:LINKS_TO]-()
WHERE f.ext IN ['.md', '.mdx']
RETURN f.key AS doc, count(l) AS inbound_refs, f.summary AS summary
ORDER BY inbound_refs DESC LIMIT 20;

// --- Q13. Kernel symbols by complexity, with test status ------------------
MATCH (s:Symbol)<-[:CONTAINS]-(f:File)
WHERE f.package = 'packages/gove-zone' AND s.complexity = 'complex'
OPTIONAL MATCH (f)-[:TESTED_BY]->(t:File)
RETURN s.name AS symbol, f.key AS file, s.line_start AS line,
       count(t) AS test_files, s.summary AS summary
ORDER BY test_files ASC, symbol LIMIT 25;

// --- Q14. Blast radius of a file: 2 hops out over every structural edge ---
// Undirected on purpose: GATES/DECIDES_ON point INTO the file while
// SEALED_WITH/IMPORTS point OUT of it, and both directions are blast radius.
MATCH (f:File {key: 'packages/gove-zone/src/gove_zone/gateway.py'})
MATCH p = (f)-[:IMPORTS|DEPENDS_ON|DOCUMENTS|GATES|DECIDES_ON|SEALED_WITH*1..2]-(x)
RETURN DISTINCT labels(x)[0] AS kind, coalesce(x.key, x.name) AS node
ORDER BY kind, node LIMIT 60;

// --- Q15. Guided tour, rebuilt from the graph -----------------------------
MATCH (t:TourStep)-[:HIGHLIGHTS]->(f:File)
RETURN t.order AS step, t.title AS title, collect(f.key)[0..6] AS files
ORDER BY step;
