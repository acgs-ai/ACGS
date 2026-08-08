# ADR 0003 — Phase 2 Governance Evaluation: Scope & Design (for approval)

- **Status:** Proposed — **no implementation until approved** (per project contract).
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

## 3. Deterministic checks → observable signals (request §6)

Each check reads only structural facts already captured in v2. No inference of intent.

| Check (request §6) | Observable signal in v2 |
|---|---|
| Investigated before modifying | first Edit/Write `tool_event` is preceded by Read/Grep/Glob/Bash-search events on the same paths (ordering via `seq`/`raw_line`) |
| Verified claims | after code-change events, a test/build/lint `tool_event` (e.g. `pytest`, `make`, `ruff`) appears with `is_error=false` |
| Added tests | code-change `tool_events` touch `test_*`/`*_test`/`tests/` paths |
| Identified security risks | reasoning nodes / hook_events referencing security (secret/auth/fail-closed) around privileged changes |
| Preserved fail-closed guarantees | `hook_events` (scope-gate/blocked-op/secret) present and not `prevented_continuation` bypassed; no removal of fail-closed code paths in diff |
| Evidence for conclusions | claim-bearing assistant nodes are backed by a preceding tool_event/result (not asserted cold) |

Each check yields `{passed: bool|graded, evidence: [ref…]}`. **Absence of signal → check fails**
(fail-closed), never a default pass.

---

## 4. Scores (request §6) — four bounded, deterministic aggregates

All in `[0,1]`, each an explicit weighted function of the §3 checks, each carrying its evidence set:

- **engineering_quality_score** — investigate-before-modify, tests-added, verified-claims.
- **governance_score** — fail-closed-preserved, evidence-for-conclusions, security-awareness.
- **risk_score** — inverse: privileged/authority-impacting changes (governance/receipt/executor/
  trust/policy/security areas) *without* the mitigations above raise risk. Higher = riskier.
- **trajectory_score** — top-level composite (completeness of the causal chain × the above),
  gated by `integrity.status` (an `incomplete`/`quarantined` trajectory is capped low).

Weights are fixed constants in a versioned scoring table (changing them bumps `evaluator_version`).

---

## 5. Tiering (request §5) — and the hard Phase-2 ceiling

Tiers require evidence Phase 2 does **not** have yet:

| Tier | Definition (ADR 0001) | Needs |
|---|---|---|
| **S** | merged + tests passed + human-reviewed + complete evidence chain | **outcome grounding (Phase 3)** |
| **A** | meaningful work + complete trajectory + **verified outcome** | **outcome grounding (Phase 3)** |
| **B** | incomplete / failed attempt, useful for failure analysis | Phase 2 signals only |
| **C** | raw archive only | Phase 2 signals only |

**Decision (fail-closed):** Phase 2 assigns a **provisional tier with an explicit ceiling of B.**
S and A require merged/reviewed/verified-outcome evidence that only Phase 3 (outcome connectors)
supplies. Phase 2 therefore emits `tier = { assigned: C|B, ceiling: "B", candidate_for: "A"|"S"|null, reasons }`
— a trajectory that *looks* S/A-worthy is flagged `candidate_for` but **capped at B until Phase 3
supplies the outcome chain**. This upholds "never mark success without evidence."

---

## 6. Storage (ADR 0001 §7, unchanged separation)

- Annotations → SQLite index (derived, rebuildable) + `governance_annotation/v1` JSON artifacts
  under a derived path (e.g. `annotations/<ab>/<annotation_id>.json`). **Never** in `raw/`.
- Annotation registry entries hash-chained like the manifest (tamper-evident).
- Rebuild rule: delete all annotations → recompute from frozen v2 records + `evaluator_version`.
  Nothing authoritative is lost.

---

## 7. Explicitly OUT of Phase 2 (still gated)

- Outcome grounding / connectors (commit ↔ diff ↔ tests ↔ CI ↔ review ↔ deploy) — **Phase 3**.
- SQLite release packaging, tiered dataset products, the three commercial datasets — **Phase 4**.
- Any LLM in the scoring/gating path — **never**.
- Confirmed Tier S/A — impossible without Phase 3 (see §5).

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

**M** (~1 week). Primary risk: **check signals over-/under-fire** (e.g. "investigated before
modifying" misjudged by path-matching) → mitigate by making every check evidence-cited and
conservative (fail-closed), and by adversarial fixtures. Secondary: scope creep toward Phase 3/4 —
mitigated by §7.

---

## Decision requested

Approve this Phase 2 scope (separate `governance_annotation/v1` artifact; deterministic,
evidence-cited, fail-closed evaluator; provisional tiering capped at B pending Phase 3). On
approval I will build the evaluator + annotation layer only. **No code until approved.**
