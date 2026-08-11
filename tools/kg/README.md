# govern-zone knowledge graph (Neo4j)

A queryable graph of this monorepo that joins **code semantics**, **git
history**, **repo topology** and **governance artifacts** on one key, so you can
ask questions no single existing tool here answers — "which CI workflow gates
this file", "which sealed files changed with no ADR behind them", "which
compliance control cites code that does not exist any more".

Local-only. Nothing in this directory runs in CI or touches the parent gates.

```bash
cd tools/kg
make all      # start Neo4j + extract + load + verify
make browser  # prints the browser URL and credentials
```

`make all` is idempotent and takes ~1 minute end to end.

---

## Why it exists

`.understand-anything/knowledge-graph.json` already holds 3.5k LLM-summarised
code nodes, and `git log` already holds the history. Neither can answer a
question that needs *both*, and neither knows about ADRs, constitutional-hash
seals, CI path filters, or compliance crosswalks. This graph is the join.

**The spine is `File.key` = the repo-relative POSIX path.** Every ingest layer
MERGEs onto that same key. If the layers stopped joining, the graph would look
big and answer nothing — so `make verify` hard-fails when fewer than 25% of
files carry both semantic and git facts.

---

## Ingest layers

| Layer | Source | Contributes |
|---|---|---|
| **A. Spine** | `git ls-files`, parent + each initialized submodule | every tracked path, language, package, test flag, `in_submodule` |
| **B. Semantic** | `.understand-anything/knowledge-graph.json` | LLM summaries, complexity, tags, `:Symbol` functions/classes, typed code edges, the 10 architectural layers, the 14-step guided tour |
| **C. History** | `git log --numstat -M`, once per repo (parent + each submodule) | churn, authors, first/last change, hotspot score, 400 most recent commits across all repos as nodes, co-change coupling |
| **D. Topology** | `.gitmodules`, `pyproject.toml`, `package.json` | packages, nested-repo submodules and whether they are initialized |
| **E. Governance** | working tree + `docs/` + `.github/workflows/` + `automation/` | constitutional-hash seals, ADRs and their supersession chains, CI path-filter gating, compliance controls and their evidence, policies, in-repo doc links |

### Node labels

`Snapshot` `File` (+`Document` `Config` `Pipeline` `Service` `Resource` `Schema`)
`Symbol` (+`Function` `Class`) `Endpoint` `Package` (+`Submodule`) `Layer`
`TourStep` `Commit` `Author` `Workflow` (+`CIGate`) `ADR` `Control` `Policy`
`Hash` (+`ConstitutionalHash`)

### Relationship types

Structural (from layer B): `CONTAINS` `IMPORTS` `EXPORTS` `TESTED_BY` `DOCUMENTS`
`DEPENDS_ON` `CONFIGURES` `CALLS` `INHERITS` `DEFINES_SCHEMA` `TRIGGERS`
`DEPLOYS` `SERVES` `ROUTES` `IMPLEMENTS` `RELATED_TO` `IN_LAYER` `HIGHLIGHTS`

Joined layers: `IN_PACKAGE` `PART_OF` `DECLARED_BY` `TOUCHED` `AUTHORED`
`CO_CHANGED` `GATES` `DEFINED_IN` `SEALED_WITH` `DECIDES_ON` `SUPERSEDES`
`RELATES_TO` `DOCUMENTED_IN` `MAPS_TO` `EVIDENCED_BY` `LINKS_TO`

Useful `File` properties: `summary` `complexity` `hotspot` `churn`
`commit_count` `author_count` `last_commit` `days_since_change` `package`
`language` `is_test` `sealed` `sealed_hash` (observed; `sealed_source` says
where) `pinned_hash` (the lock entry) `hash_drift` (marker ≠ pin) `ua_covered`
`dirty_at_extract`.

---

## Query catalog

`queries.cypher` holds all of these, ready to paste into the browser.

| # | Question |
|---|---|
| Q0 | How stale is the semantic layer vs `HEAD`? |
| Q1 | Which CI workflows gate the file I am about to edit? |
| Q2 | Which source files have **no** path-filtered CI gate at all? |
| Q3 | Which hash-sealed files changed recently, by whom — and with no ADR behind them? |
| Q4 | Which package pairs keep changing together (architecture erosion)? |
| Q5 | Which churn × complexity hotspots have no test edge? |
| Q6 | Which compliance controls are cited but evidenced by no code? |
| Q7 | Which ADRs govern code that is dirty right now? Which ADRs supersede which? |
| Q8 | Which docs are orphaned — nothing in the repo links to them? |
| Q9 | Which imports cross architectural layer boundaries? |
| Q10 | Which tracked code has the summariser never seen (semantic blind spots)? |
| Q11 | Bus factor: single-author, high-churn, governance-critical files |
| Q12 | Doc authority ranking by inbound in-repo references |
| Q13 | Complex kernel symbols and their test status |
| Q14 | Blast radius of one file, 2 hops over every structural edge |
| Q15 | The guided tour, rebuilt from the graph |

---

## Honesty properties — read before trusting a result

The graph carries its own caveats as data rather than hiding them:

- **The semantic layer is a snapshot, the git layer is live.**
  `(:Snapshot)` records `ua_commit` vs `git_head` and sets
  `semantic_layer_is_stale`. Files added since that snapshot get
  `ua_covered: false` — that is staleness, not a finding. Re-run
  `/understand` to refresh, then `make reload`.
- **`TESTED_BY` undercounts.** It misses barrel and dynamic imports. Q5's
  "no test edge" output is a list of leads, not a verdict (this was already
  established in `.understand-anything/risk-sweep-2026-08-08.md`).
- **`CALLS` is nearly empty** (27 edges over 2265 symbols). The source graph
  does not do real call resolution. Do not use this for call-graph traversal.
- **Submodule coverage depends on your checkout.** The spine walks each
  *initialized* submodule with its own `git ls-files`, and reads each one's
  history separately (they are independent repos; `Commit.repo` records which).
  With all five checked out that is 1882 extra files and 1271 extra commits.
  If a submodule is absent, its `docs/constitutional-hashes.lock` entries are
  counted as `sealed_files_absent` on the `:Package` node rather than minting
  phantom `:File` nodes — so the graph shrinks honestly instead of lying.
  Re-run `make reload` after `git submodule update --init`.
- **Sealed detection mirrors the repo's own gate** — it *imports*
  `SCAN_EXTENSIONS` and `SKIP_FILES` from `scripts/verify_constitutional_hashes.py`
  rather than copying them, and applies the same 4KB head window. A marker
  buried mid-file is prose, not a declaration.
  `hash_gated: false` means "real marker, in a file type the gate does not
  scan" — i.e. an enforcement gap. It is the check that found the 26 Rust
  files in `packages/acgs-lite/rust/` (closed 2026-08-10, ADR-0012; the gate
  now pins 248). Keep it at zero:
  `MATCH (f:File {sealed:true, hash_gated:false}) RETURN f.key`
- **`CO_CHANGED` is stored once per path-sorted pair.** Canonicalise the pair
  before aggregating by package, or couplings appear twice (Q4 does this).
- **`GATES` only sees path-filtered workflows.** A workflow with no `paths:`
  (or only `paths-ignore:`) runs on *every* PR and therefore produces zero
  `GATES` edges — `constitutional-hash.yml`, `gitguardian.yml` and
  `socket-security.yml` are in that group. They live on the `:Workflow` node
  with `path_filtered: false`. Q2's "ungated" means *no path-filtered gate*,
  not unprotected.
- **`.understandignore` exists**, so Q10's blind spots mix deliberately
  excluded paths (fixtures, archives, `.omc/` state) with genuinely new code.
  Check that file before treating a row as a gap.
- **Control extraction is regex-based** over crosswalk/mapping docs, scoped to
  the paragraph or table row. It finds citations, it does not judge conformance.

---

## Commands

| Command | Effect |
|---|---|
| `make up` | start Neo4j (`127.0.0.1:7474` browser, `7687` bolt) |
| `make extract` | rebuild `build/graph.json` from the repo |
| `make load` | wipe + load into Neo4j (idempotent) |
| `make verify` | shape, join-health and catalog-query evidence; non-zero exit on failure |
| `make reload` | extract + load + verify |
| `make shell` | interactive `cypher-shell` |
| `make down` / `make nuke` | stop / stop and delete the data volume |

Credentials default to `neo4j` / `acgs-kg-local`; override with
`NEO4J_PASSWORD`. Data lives in a **named docker volume**, not a repo
bind-mount — the container runs as uid 7474 and would otherwise leave
root-owned files in the worktree.

Python deps are pulled per-run by `uv` (`--with neo4j --with pyyaml`) and are
deliberately **not** added to the workspace `pyproject.toml`.

Run the whole catalog at once:

```bash
docker exec -i acgs-kg-neo4j cypher-shell -u neo4j -p acgs-kg-local \
  --format plain < queries.cypher
```

### Running these from inside a Claude Code session

The agent sandbox blocks both the docker socket and `localhost:7687`, so every
`docker`, `docker compose`, `make` and loader/verifier call here needs
`dangerouslyDisableSandbox: true`. Sandboxed `uv` also fails with
`Could not acquire lock … Read-only file system` on `~/.cache/uv`; if you must
stay sandboxed for the extract step (it needs no network), point `UV_CACHE_DIR`
at a writable scratch dir. `podman` is not a workaround — `/run/user/1000` is
read-only under the sandbox.

`build/` is gitignored via this directory's own `.gitignore`. There is no root
`Makefile` target on purpose: `Makefile` sits in several workflows' `paths:`
filters, so touching it would fire unrelated CI.
