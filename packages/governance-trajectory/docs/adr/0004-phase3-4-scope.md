# ADR 0004 — Phase 3 (Outcome Grounding) + Phase 4 (Dataset Factory): Scope

- **Status:** Accepted (user directive: finish remaining phases).
- **Builds on:** Phase 2 (`4cfd2ce`, `governance_annotation/v1`).

## Phase 3 — Outcome Grounding (Option D)

Link a trajectory to **measurable** outcomes and only then confirm high tiers.

- **`governance_outcome/v1`** — a separate artifact (never mutates trajectory or
  annotation) bound by `trajectory_ref` + `annotation_ref`. Fields: `commit`
  (sha + diff_ref), `tests` (passed/command/marker), `ci`, `review`, `deploy`.
- **Deterministic + injected.** Outcome evidence is *supplied* (from git via the
  H1 `git_evidence` capture, plus test/CI/review/deploy records) — the grounder
  never performs non-deterministic fetches. Same inputs → byte-identical outcome.
- **`ground_tier(annotation, outcome)`** lifts the Phase-2 ceiling:
  - **A** — annotation `candidate_for == "A"` **and** `tests.passed` **and** a commit.
  - **S** — the A-conditions **and** `review.decision == "approved"` **and**
    `ci.status == "passed"`.
  - Otherwise the annotation's provisional tier (B/C) stands.
  - **Fail-closed:** any missing/None required evidence → **no promotion**. Success
    is never marked without evidence.

## Phase 4 — Dataset Factory (Option C)

- **`index.py`** — SQLite index (derived, rebuildable) over trajectories +
  annotations + outcomes. Holds ids, digests, scores, tiers, area — **no
  authoritative content** (raw/annotations remain the source).
- **`packaging.py`** — tiered release packages (S/A/B/C): a signed (hash-chained)
  manifest listing member `{trajectory_id, normalized_sha256, annotation_id,
  outcome_id}` by reference + digest. No raw copying (separation preserved).
- **`datasets.py`** — three products, each a named selection query + manifest:
  - **ACGS-Claude-Engineering-v1** — grounded tier ∈ {S,A}, high engineering_quality.
  - **ACGS-Governance-Benchmark** — trajectories touching authority-impact areas,
    with governance scores + fail-closed verdicts (can an agent safely modify
    governance infra?).
  - **ACGS-Agent-SWE** — issue → investigation → patch → verification chains.

## Storage (ADR 0001 §7, unchanged separation)

Raw (immutable) · SQLite index (derived) · annotation/outcome artifacts (derived,
hash-chained) · release/dataset manifests (reference-only, hash-chained). Deleting
any derived layer loses nothing — all rebuildable from frozen trajectories.

## Out of scope / invariants

No LLM in scoring/gating. No raw copying into packages. Confirmed S/A requires
real outcome evidence. Every package/dataset manifest is content-hashed and
references members by id+digest.
