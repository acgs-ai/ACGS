# Phase 1 — Implementation Summary

- **Status:** built + verified; awaiting Phase 1 acceptance sign-off
- **Scope delivered:** governed ingestion foundation ONLY (source adapter, raw preservation,
  trajectory materialization, validation gates V1–V6, tests). No evaluator, annotation, scoring,
  packaging, or benchmark — those remain excluded until separately approved.

## 1. What was built

`acgs_trajectory/` — a Python package that turns a Claude Code session JSONL into an immutable,
provenance-stamped, replayable `governance_trajectory/v2` object.

| Module | Responsibility (request section) |
|---|---|
| `adapter.py` | §1 Source adapter: version-aware JSONL reader, causal-DAG extraction, block separation (text/thinking/tool_use/tool_result), tool_use↔tool_result linkage, hook events, token usage, subagent detection. No semantic interpretation. |
| `raw_store.py` | §2 Raw preservation: content-addressed WORM archive (mode 0444), restricted quarantine store, hash-chained manifest (SHA-256 provenance registry), digest verification. |
| `secrets_scan.py` | Gate V5: self-contained secret detector at the ingestion edge; 40-char git-SHA whitelist; findings never carry the secret value. |
| `materialize.py` | §3 Materialization: `ParsedSession` → `governance_trajectory/v2` dict; raw referenced by pointer, `derived.*` null; deterministic self-excluding normalized digest. |
| `validate.py` | §4 Gates V1–V6 (pure functions, no LLM). |
| `ingest.py` | Orchestrator: read → V5 → parse → materialize → V1–V4,V6 → fail-closed status → archive + manifest. |
| `cli.py` | `acgs-ingest` entrypoint; exits 0 only on `complete`. |
| `schemas/…v2.schema.json` | Packaged contract (byte-identical to `docs/schema/`, guarded by a test). |

## 2. Validation gates (as implemented)

| Gate | Checks | Fail-closed effect |
|---|---|---|
| V1 causal-graph integrity | parentUuid resolution, sidechain linkage, tool_use/tool_result linkage | `incomplete` |
| V2 block integrity | valid block types, valid references | `incomplete` |
| V3 provenance completeness | single session identity, source digest, required env metadata, git head | `incomplete`; missing head caps tier at C |
| V4 tamper detection | raw digest ≠ claimed → mismatch | `incomplete`, record rejected from archive |
| V5 secret boundary | detect before archive; quarantine; never redact raw | `quarantined`, routed to restricted store |
| V6 schema validation | `governance_trajectory/v2` compliance (incl. unsupported version / unknown record type) | `quarantined` (unsupported) / `incomplete` (schema) |

Status ladder: `quarantined` > `incomplete` > `complete`. A record *earns* `complete`; absence never grants it.

## 3. Test results (literal)

```
$ .venv/bin/python -m pytest -q
..................................                                       [100%]
34 passed in 0.12s
```

Coverage by required fixture class (request §5):

- real-shape session (`complete_session`, `subagent_session`) — passing paths, subagent nesting
- malformed transcript (`malformed_session`) — `ParseError` at the exact line
- missing parent (`missing_parent_session`) — V1 orphan
- broken tool references (`broken_tool_ref_session`) — V1 broken_tool_ref → incomplete
- hook events (`hook_prevented_session`) — `preventedContinuation` preserved as governance evidence
- secret detection (`secret_session`) — quarantined, raw byte-identical (unredacted), incident logged

Real-data check (the live session transcript, 393+ records): **0 schema errors**, causal graph +
tool/hook events extracted, correctly **quarantined** (the transcript legitimately contains an
`AKIA…EXAMPLE` literal). CLI end-to-end: complete→shared archive (exit 0); secret→quarantine
(exit 1); manifest hash-chain verified `(True, [])`.

## 4. Sample trajectory artifact

`docs/examples/sample_trajectory.json` — a full `complete` record (validates against the v2 schema).
Shows: provenance + hash-chained registry ref, environment with git join, causal `nodes`/`edges`,
one `tool_events` join, one `hook_events` entry, `derived` all-null, `integrity.status=complete`.

## 5. Changed / created files

Package (12): `acgs_trajectory/{__init__,canonical,errors,adapter,secrets_scan,raw_store,materialize,validate,ingest,cli}.py`, `acgs_trajectory/schemas/{__init__.py,governance_trajectory_v2.schema.json}`.
Tests (14): `tests/{conftest,_make_fixtures,test_adapter,test_raw_store,test_validate,test_ingest}.py` + 9 fixtures.
Docs: `docs/adr/0002…`, `docs/schema/governance_trajectory_v2.{md,schema.json}`, `docs/phase1/{acceptance-criteria,risk-register,implementation-summary}.md`, `docs/examples/sample_trajectory.json`.
Build: `pyproject.toml`, `.gitignore`. (~1280 LOC package, ~560 LOC tests.)

## 6. Known limitations

1. **Secret-scanner precision.** Fail-closed by design → over-quarantines. On the live transcript it
   flagged ~420 spans (real `AKIA` + high-entropy false positives like `toolu_…` ids and 64-hex
   digests, which the ≤40-hex whitelist does not cover). Safe direction, but noisy; tune the
   whitelist / integrate `detect-secrets` before large-scale ingestion. (Risk R2 residual.)
2. **Version boundary verified on 2.1.170 only.** Other `2.x` are accepted by prefix, not proven;
   non-`2.x` quarantines. Expand golden fixtures per version before production. (R1/R9.)
3. **git join fidelity.** `head_sha`/`dirty`/`diff` come from the repo at capture time, not the
   transcript; accuracy is bounded by that capture. `code_changes.files`/`diff` are not yet
   auto-populated by the CLI (only head/dirty/branch) — diff capture is a thin follow-up. (R4.)
4. **Multi-block records.** One node per record (primary block); v2.1.170 splits blocks one-per-record
   so impact is minimal, but a future multi-block record would under-node (tool events still scan all
   blocks). 
5. **Fixture corpus is small** (synthetic + one live session). Grow it (subagent-heavy, large-diff,
   multi-version) before declaring production-ready — distinct from design/Phase-1 acceptance. (R9.)
6. **Determinism requires injected time.** `captured_at` is a parameter (no wall-clock inside), so
   callers must supply the real capture timestamp; the CLI defaults to epoch for reproducible runs.

## 7. Explicitly NOT built (still gated)

Evaluator / scoring, governance auto-labels, annotation pipeline, quality tiering logic, outcome
connectors (Phase 3), SQLite index build, tiered release packaging, and the three commercial
datasets. `derived.*` stays schema-locked to `null`. Stop here per instruction — resume only on
separate approval of the next phase.
