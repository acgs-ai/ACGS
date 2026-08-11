# ADR 0003 — Phase 2 Governance Evaluation: Scope & Design

- **Status:** ACCEPTED — approved for implementation on branch `agent/phase2-eval` (2026-08-06).
  Entry gate cleared by `c119aad` (H1–H4 + worktree isolation). Design approved by maintainer.
- **Date:** 2026-08-06
- **Builds on:** frozen Phase 1.1 baseline (`phase-1.1-freeze` → `24f8acf`), hardening `c119aad`.
- **Consumes:** `governance_trajectory/v2` records produced by the Phase 1 ingestion foundation.

Phase 2 = **Option B (Governance Evaluation)** from ADR 0001: a deterministic evaluator +
governance annotation layer + four scores + quality tiering. It turns *evidence* (Phase 1) into
*graded judgment* — and nothing more. This ADR fixes the boundary before any code is written.

---

## 1. The load-bearing decision — annotations are a SEPARATE artifact, not a mutation of v2

The v2 `derived` block is schema-locked to `null` and the Phase 1.1 records are **frozen**
(content-addressed, hash-chained, tagged). Populating `derived` in place would break the
immutability + raw/derived-separation guarantees the whole pipeline exists to protect.

**Decision:** Phase 2 emits a **new, separate `governance_annotation/v1` document** that
*references* the trajectory by `trajectory_id` + `normalized_sha256` and never touches the frozen
record. Annotations live in the derived/index layer (rebuildable); raw and frozen trajectories stay
authoritative and untouched.

```
governance_annotation/v1
├── annotation_id            sha256(normalized_sha256 + evaluator_version)
├── trajectory_ref           { trajectory_id, normalized_sha256 }   ← binds to exact frozen record
├── evaluator_version        stamped; annotations are reproducible + rebuildable
├── scores                   { trajectory, risk, governance, engineering_quality }  each [0,1]
├── labels                   engineering[] + governance[] behaviors, each with evidence refs
├── tier                     { assigned, ceiling, reasons }         ← fail-closed (see §5)
├── evidence                 every score/label cites node/tool_event/hook_event ids
└── integrity                { annotation_sha256, evaluator_version, inputs_verified }
```

This keeps the frozen `derived.*` slots as the *contract shape*; the annotation doc is the *value*,
stored separately and joinable by digest. If evaluator logic changes, annotations are recomputed
from the frozen trajectory — the trajectory never changes.

---

## 2. Determinism (ACGS non-negotiable)

The evaluator is a **pure function** of `(governance_trajectory/v2 record, its raw pointers)`:

- **No LLM in the scoring or gating path.** An LLM may later produce *advisory* commentary in a
  clearly-separated, non-gating field, but it can never set a score, label, or tier.
- No wall-clock, no network, no randomness. Same trajectory + same `evaluator_version` →
  byte-identical annotation (same determinism gate as Phase 1, R6).
- Every output is traceable to observable trajectory signals (below).

---

## 3. Deterministic checks → observable signals

Each check reads only structural facts already captured in v2. No inference of intent.

| Check | Observable signal in v2 |
|---|---|
| Investigated before modifying | first Edit/Write `tool_event` is preceded by Read/Grep/Glob/Bash-search events (ordering via `seq`/`raw_line`) |
| Verified claims | after code-change events, a test/build/lint `tool_event` (`pytest`, `make`, `ruff`) appears with `is_error=false` |
| Added tests | code-change `tool_events` touch `test_*`/`*_test`/`tests/` paths |
| Identified security risks | reasoning nodes / hook_events referencing security (secret/auth/fail-closed) around privileged changes |
| Preserved fail-closed guarantees | `hook_events` (scope-gate/blocked-op/secret) present and not bypassed; no removal of fail-closed code paths |
| Evidence for conclusions | claim-bearing assistant nodes are backed by a preceding tool_event/result |

Each check yields `{passed: bool|graded, evidence: [ref…]}`. **Absence of signal → check fails**
(fail-closed), never a default pass.

---

## 4. Scores — four bounded, deterministic aggregates

All in `[0,1]`, each an explicit weighted function of the §3 checks, each carrying its evidence set:

- **engineering_quality_score** — investigate-before-modify, tests-added, verified-claims.
- **governance_score** — fail-closed-preserved, evidence-for-conclusions, security-awareness.
- **risk_score** — inverse: privileged/authority-impacting changes without the mitigations raise risk. Higher = riskier.
- **trajectory_score** — top-level composite (completeness of the causal chain × the above),
  gated by `integrity.status` (an `incomplete`/`quarantined` trajectory is capped low).

Weights are fixed constants in a versioned scoring table (changing them bumps `evaluator_version`).

---

## 5. Tiering — and the hard Phase-2 ceiling

| Tier | Definition (ADR 0001) | Needs |
|---|---|---|
| **S** | merged + tests passed + human-reviewed + complete evidence chain | outcome grounding (Phase 3) |
| **A** | meaningful work + complete trajectory + verified outcome | outcome grounding (Phase 3) |
| **B** | incomplete / failed attempt, useful for failure analysis | Phase 2 signals only |
| **C** | raw archive only | Phase 2 signals only |

**Decision (fail-closed):** Phase 2 assigns a **provisional tier with an explicit ceiling of B.**
S and A require merged/reviewed/verified-outcome evidence that only Phase 3 supplies. Phase 2 emits
`tier = { assigned: C|B, ceiling: "B", candidate_for: "A"|"S"|null, reasons }` — a trajectory that
*looks* S/A-worthy is flagged `candidate_for` but **capped at B until Phase 3 supplies the outcome
chain**. Upholds "never mark success without evidence."

**Known Phase-2 limitation (structural):** `candidate_for:"S"` is unreachable in
Phase 2 — it requires the `verified_claims` signal to reach the S threshold, but
that needs the Bash command bytes, which v2 stores only as a raw pointer (ADR
0002 D6) and never inlines; the S branch is retained for forward-compatibility
but is dead until Phase 3, and is documented as such rather than left silently
unreachable.

**Grounded-corroboration gate (fail-closed, load-bearing for P2-5):** five of the
six §3 checks read author-controlled *transcript* content (tool names, fabricated
`system`/hook records, prompt text); only `code_changes.files` is *grounded*
(git-joined at ingestion, independent of the transcript). `trajectory_score`,
`tier.assigned`, and `tier.candidate_for` may rise above the C band **only** when
at least one grounded corroboration exists — with none, `trajectory_score` is
capped into the C band, `assigned` is forced to `C`, and `candidate_for` to
`null` (reason `capped_C:no_grounded_corroboration`), regardless of transcript
signals. Note `integrity.status == "complete"` is intentionally NOT treated as
grounding: the frozen record carries an unverified placeholder `head_sha`, so a
forged transcript also resolves to `complete` and status cannot discriminate it —
only `code_changes.files` can. A forged transcript with no git-join therefore
yields tier C / `candidate_for: null` and cannot cross the B threshold.

---

## 6. Storage (ADR 0001 §7, unchanged separation)

- Annotations → SQLite index (derived, rebuildable) + `governance_annotation/v1` JSON artifacts
  under a derived path (e.g. `annotations/<ab>/<annotation_id>.json`). **Never** in `raw/`.
- Annotation registry entries hash-chained like the manifest (tamper-evident).
- Rebuild rule: delete all annotations → recompute from frozen v2 records + `evaluator_version`.

---

## 7. Explicitly OUT of Phase 2 (still gated)

- Outcome grounding / connectors — **Phase 3**.
- SQLite release packaging, tiered dataset products, commercial datasets — **Phase 4**.
- Any LLM in the scoring/gating path — **never**.
- Confirmed Tier S/A — impossible without Phase 3.

---

## 8. Acceptance criteria (Phase 2 exit gate)

| # | Criterion | Evidence |
|---|---|---|
| P2-1 | `governance_annotation/v1` schema valid (Draft 2020-12) + sample validates | schema check + sample |
| P2-2 | Evaluator is a pure function — same trajectory + evaluator_version → byte-identical annotation | determinism test |
| P2-3 | Every score/label carries ≥1 evidence ref to a real node/tool_event/hook_event | evidence-completeness test |
| P2-4 | No LLM / network / wall-clock in the evaluator path | code audit + import check |
| P2-5 | Fail-closed: missing signal lowers score, never inflates; no confirmed S/A without outcome | adversarial fixtures |
| P2-6 | Frozen v2 records + raw are byte-unchanged after annotation | freeze-integrity test |
| P2-7 | Annotations rebuildable from frozen trajectories alone | rebuild test |

## 9. Deliverables

ADR (this) · `governance_annotation/v1` schema · evaluator (`acgs_trajectory/evaluate.py`, pure) ·
scoring table (versioned constants) · annotation writer (index + hash-chained registry) ·
validation tests · example annotation artifact.

## 10. Complexity / risk

**M**. Primary risk: check signals over-/under-fire → mitigate by making every check evidence-cited
and conservative (fail-closed), and by adversarial fixtures. Secondary: scope creep toward
Phase 3/4 — mitigated by §7.
