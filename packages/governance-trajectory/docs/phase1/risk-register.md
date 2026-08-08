# Phase 1 — Risk Register

- **Status:** design, awaiting approval
- **Scope:** governed ingestion foundation (Phase 1 only). Downstream-phase risks tracked in ADR 0001 §6.

Severity = impact × likelihood on Phase-1 correctness. Every mitigation is fail-closed:
uncertainty degrades a record's status, never silently passes it.

| ID | Risk | Sev | Trigger / how it bites | Mitigation (Phase 1) | Residual |
|---|---|---|---|---|---|
| **R1** | **Transcript format drift** across Claude Code `version`s (block shapes, new record types) | HIGH | A newer session uses a shape the adapter never saw → mis-normalized or dropped events | Version-aware parsing boundary (ADR 0002 D5); **V6** quarantines unsupported `type`/`version`; one golden fixture pinned per supported version; adapter is first + most-tested component | LOW — unknown shapes are retained + flagged, never silently lost |
| **R2** | **Secret leakage** — tool I/O, diffs, `.env`, tokens in an ACGS session enter the shared archive | HIGH | A tool_result contains a live key; archived world-readable → credential exposure | **V5** scans raw+diff **before** archive write; hit ⇒ `quarantined`, restricted store, incident log; 40-char SHA whitelist for FP; detection-before-archive is a hard boundary (ADR 0002 D7) | MED — scanner recall < 100%; pair with human review before any external release (later phase) |
| **R3** | **Causal-chain gaps** with subagents / sidechains / parallel tool calls | MED | `isSidechain` branch or a parallel `tool_use` batch produces orphaned or mis-parented nodes | **V1** asserts 0 orphans incl. sidechains; sidechain roots must attach via `sidechain_spawn` edge (D2); dangling `tool_use` flagged by **V2** | LOW |
| **R4** | **Raw ↔ git join is off-session** — `head_sha`/diff not in JSONL, captured from repo state | MED | Capture host repo state differs from session's true state, or is absent | Environment `git.*` required; absence ⇒ **V4** `incomplete`, tier ceiling C (never `complete`); `dirty` flag preserved | MED — accuracy bounded by capture-time repo fidelity; documented limitation |
| **R5** | **Hash/immutability regression** — raw mutated after archive, or registry not chained | MED | A rewrite or a broken chain lets silent modification pass undetected | Content-addressed WORM raw (0444); hash-chained manifest (`prev_entry_sha256`); **V3** rejects on mismatch; **A4/A8** acceptance gates | LOW |
| **R6** | **Non-determinism in normalization** (map ordering, timestamp parsing, float/serialization) | MED | Two runs on identical input yield different `normalized_sha256` → provenance meaningless | Canonical JSON serialization (sorted keys, fixed number format); **A9** requires byte-identical repeat run + identical `trajectory_id` | LOW |
| **R7** | **Scope creep into evaluator/derived** during "just add a label" pressure | MED | A score/label written into a record breaks raw/derived separation | `derived.*` schema-locked to `null` in v2 (`{"type":"null"}` per field); any value fails schema validation → structural guard, not a convention | LOW |
| **R8** | **Quarantine as silent data loss** — quarantined records forgotten | LOW | Operators treat quarantine as `/dev/null` | Quarantine is a **retained, flagged, logged** store with reasons; **A6** asserts retention + pipeline continuation; periodic quarantine review is an operating requirement | LOW |
| **R9** | **Reference sample too small** — 1 session (51 records) may miss real-world shapes | MED | Golden fixture under-covers; adapter passes A2–A9 yet fails on production sessions | Treat current fixture as seed; expand fixture set with multi-session / subagent-heavy / large-diff cases before declaring Phase 1 production-ready (distinct from design approval) | MED until fixture corpus grows |

## Escalation rule

Any Phase-1 check that cannot render a deterministic pass/fail (ambiguous parse, partial git state,
scanner error) **must** resolve to `incomplete` or `quarantined` — never `complete`. Fail closed is
the default; a record earns `complete`, it is never granted it by absence of evidence.
