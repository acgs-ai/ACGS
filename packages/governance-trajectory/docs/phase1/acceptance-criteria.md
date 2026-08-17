# Phase 1 — Acceptance Criteria, Validation Spec, Storage Decision

- **Status:** design, awaiting approval
- **Scope:** governed ingestion foundation only (ADR 0001 Phase 1; source-format facts ADR 0002;
  contract `governance_trajectory_v2.schema.json`).
- **Out of scope (hard exclusions):** evaluator, scoring, governance labels, annotation, tiering
  logic, outcome connectors, SQLite index build, packaging, benchmark, commercial datasets.

> **Numbering note (build reconciliation):** the authoritative V1–V6 gate
> definitions implemented in `acgs_trajectory/validate.py` follow the Phase-1-build
> brief: V1 causal-graph integrity, V2 block integrity, V3 provenance completeness,
> V4 tamper detection, V5 secret boundary, V6 schema validation. The design-draft
> table below predates that brief (it folded ordering/metadata differently); where
> they differ, `validate.py` governs. Every check listed here still exists — only the
> V-number grouping changed.

## 1. Deterministic validation checks

Each check is a pure function of `(raw JSONL, normalized record)` → pass/fail + reasons.
No LLM in this path. All failures are fail-closed (set `integrity.status`, never drop silently).

| ID | Check | Definition | On failure |
|---|---|---|---|
| **V1** | Orphan detection | Every node's `parent_uuid` resolves to an existing node **or** the node is in `root_uuids`. Sidechain roots must attach to their spawning `tool_use` via a `sidechain_spawn` edge. | `status=incomplete`, reason `orphan:<uuid>` |
| **V2** | Ordering consistency | `seq` monotonic by (`ts`, then topological order). Every `tool_result.tool_use_id` matches a **prior** `tool_use.id`; no result precedes its use; dangling `tool_use` (no result) flagged. | `status=incomplete`, reason `ordering:<detail>` |
| **V3** | Hash verification | `sha256(raw bytes) == provenance.raw_ref.sha256 == registry entry`. `integrity.normalized_sha256` recomputable from normalized record. | `status=incomplete` (mismatch) → record **rejected** from archive |
| **V4** | Missing-metadata handling | All required `environment` fields present (`session_id, model, claude_code_version, entrypoint, cwd, git.branch/head_sha/dirty`). Session-wide `sessionId`/`version` agree across records. | `status=incomplete`, reason `missing:<field>`; tier ceiling C |
| **V5** | Secret-detection boundary | detect-secrets (or equiv) scans raw + joined diff **before** archive write. 40-char git SHAs whitelisted (known FP, per workspace policy). | `status=quarantined` → NOT written to shared archive; restricted quarantine store + incident log |
| **V6** | Unknown-type / version guard | Any record `type` outside the D1 set, or a Claude Code `version` outside the supported adapter set. | `status=quarantined`, reason `unsupported:<type|version>` |

**Status resolution** is exactly the deterministic ladder in schema spec §3
(`quarantined` > `incomplete` > `complete`). `complete` ⇔ V1–V6 all pass and `reasons=[]`.

## 2. Acceptance criteria (Phase 1 exit gate)

Phase 1 is **done** only when all of the following produce literal, reproducible evidence:

| # | Criterion | Evidence required |
|---|---|---|
| A1 | Schema contract valid | `governance_trajectory_v2.schema.json` passes Draft 2020-12 `check_schema`; a fail-closed `incomplete` sample validates. **(Met at design time — see §4.)** |
| A2 | Golden round-trip | Normalize the real reference session → replay → the ordered (tool_call→tool_result→node) digest equals a byte-stable golden digest. |
| A3 | Orphan = 0 on golden | V1 reports 0 orphans on the reference session incl. any sidechains. |
| A4 | Tamper detection | Corrupt one raw byte → V3 **rejects** (fails closed), not warns. |
| A5 | Missing-field fail-closed | Strip `git.head_sha` → record `status=incomplete`, tier ceiling C, never `complete`. |
| A6 | Unknown-type quarantine | Inject a novel `type` → `status=quarantined`, record retained + flagged, pipeline continues. |
| A7 | Secret boundary | Inject a fake secret into a tool_result → V5 quarantines **before** archive write; nothing secret reaches the shared archive; incident logged. |
| A8 | Raw immutability | Archived raw object is write-once (0444 / content-addressed); a rewrite attempt fails; registry hash-chain links `prev→entry`. |
| A9 | Determinism | Running ingestion twice on identical input yields byte-identical normalized record + identical `trajectory_id`. |

No Phase 1 sign-off without A1–A9 evidence. A "should work" is not acceptance (workspace
verification-discipline rule).

## 3. Storage decision (architecture only — no build)

| Layer | Format | Rationale | Mutability |
|---|---|---|---|
| **Raw archive** | append-only **JSONL**, one object per session, **content-addressed** by `sha256` (e.g. `raw/<ab>/<sha256>.jsonl`), optional `.zst` compression, mode `0444` | Matches source format exactly (no lossy transform); content-addressing makes the path itself a hash witness | **write-once (WORM)** — authoritative |
| **Index** | **SQLite**, single file, single-writer | Deterministic, queryable, transactional; holds `trajectory_id`, env fields, `integrity.status`, pointers — **no authoritative content** | **derived, rebuildable** from raw |
| **Manifest / provenance registry** | append-only **JSONL**, **hash-chained** (each entry carries `prev_entry_sha256`) | The SHA256 provenance registry of ADR 0001; hash-chain makes silent modification detectable (tamper-evident, not merely tamper-resistant) | **append-only** |
| **Quarantine store** | separate restricted dir, not world-readable | Isolates secret-bearing / unparseable records from the shared archive | restricted |

**Separation guarantee:** deleting index + manifest loses nothing recoverable (rebuild from raw).
Deleting raw is the only irreversible act. Derived (`derived.*` schema block) is null in P1 and lives
only in the index/annotation layer later — never in raw.

## 4. Design-time verification already performed

- `governance_trajectory_v2.schema.json` — **VALID** under Draft 2020-12 `check_schema`.
- Minimal fail-closed `incomplete` record — **VALIDATES** against the contract.
- Source-format facts (D1–D7) — **observed** on a live 51-record session, not assumed.

(A2–A9 require the normalizer, which is Phase 1 *build* — begins only after this design is approved.)

## 5. What Phase 1 build will contain (for reference, not this deliverable)

Source adapter (version-aware) · normalizer (JSONL→v2) · provenance/registry writer · replay+verify
harness · secret-scrub gate · golden fixtures. Nothing beyond ingestion. Evaluator and all
downstream remain excluded until a future phase is approved.
