# ADR 0001 — Governed Dataset Pipeline for ACGS Agent Trajectories

- **Status:** Proposed (awaiting scope approval — no implementation until approved)
- **Date:** 2026-08-06
- **Decision owners:** ACGS data / governance
- **Context source verified:** Claude Code transcript format inspected against a live 51-record session JSONL (see §3.1)

---

## 1. Problem Definition

### 1.1 The exact problem

We are not archiving conversations. We are capturing **verifiable execution trajectories** of an
advanced agent (Claude Code) doing senior-engineer work on ACGS, such that each trajectory
preserves the full causal chain and can later be *proven* correct against real outcomes:

```
human request → investigation → reasoning/actions → tool calls → code changes → tests → verification → outcome
```

The asset is the **verified causal execution record**, not the text. A record with no linked
outcome evidence is, by ACGS principles, an unproven claim.

### 1.2 Classification

The full request spans **all five** categories:

| | Category | Present in request |
|---|---|---|
| A | Dataset collection system | §1 Data Collection, §7 Storage |
| B | Agent evaluation system | §6 Evaluator, §3 Annotation |
| C | Training-data generation system | §8 Commercial packages |
| D | Governance evidence system | §4 Outcome Grounding, §9 Security |
| E | **All of the above, phased** | ← this is the honest classification |

**Verdict: E — all of the above, delivered in phases.** Attempting A–D simultaneously is the
primary failure risk (see §6 Risks). The rest of this ADR exists to impose a phase boundary.

---

## 2. MVP Boundary

### 2.1 Options evaluated

| Option | Delivers | Standalone value | Blocks what |
|---|---|---|---|
| **A — Session Capture** | collector, raw immutable store, schema, provenance, replay | Trustworthy, reproducible trajectory records | Everything (B/C/D sit on it) |
| **B — Governance Evaluation** | parser, deterministic evaluator, labels, scoring | Behavior signal | Nothing new; *requires* A's normalized output |
| **C — Full Dataset Factory** | collect + normalize + annotate + evaluate + package + release | Commercial/research products | — |

### 2.2 Decision

**Adopt Option A as the first milestone — but built to the `governance_trajectory/v2` schema
(not a throwaway v1) and carrying a thin vertical slice of governance grounding.**

Rationale:

1. **Dependency order forces it.** B is worthless on an unreliable parser; C is worthless without
   B. The only phase that can ship correct-in-isolation is A. Everything else consumes A's output.
2. **The schema is the contract.** Requirement §2 explicitly asks for `governance_trajectory/v2`.
   Building A against a temporary schema then re-cutting for v2 wastes the milestone. Design v2 now;
   populate the fields A can fill; leave evaluator-derived fields (scores, labels) null and
   fail-closed until Phase 2.
3. **Fail-closed must exist from record one.** Provenance, hash registry, and the
   raw/derived separation are not deferrable — retrofitting immutability onto data already
   collected mutably destroys the audit guarantee. These are in-scope for A.

**Explicitly out of MVP:** the deterministic evaluator scoring logic, governance auto-labels,
SQLite index, tiered release packages, and the three commercial datasets. Those are Phases 2–4.

### 2.3 MVP one-line scope

> Given a completed Claude Code session, produce one immutable, provenance-stamped,
> replayable `governance_trajectory/v2` record whose causal chain (request → actions → tool
> calls → code changes) is complete and verifiable, with outcome/score fields present-but-null
> and fail-closed.

---

## 3. Dependencies

### 3.1 Ground truth (verified this session)

Claude Code writes **one JSONL per session** under `~/.claude/projects/<project-slug>/<sessionId>.jsonl`.
Record shape (confirmed on a real 51-record file):

- `type`: `user` | `assistant` | `system` | `attachment` | `queue-operation` | `last-prompt`
- causal DAG: `uuid` + `parentUuid` (parent links reconstruct the tree; `isSidechain` flags subagent branches)
- environment: `cwd`, `gitBranch`, `version` (Claude Code version — **drifts, see risk R1**), `entrypoint`
- identity/time: `sessionId`, `timestamp`
- payload: `message` (tool_use / tool_result blocks live *inside* content), `requestId`, `advisorModel`

This is the load-bearing dependency. **The source adapter that reads this format is the true
foundation of the whole pipeline** — highest risk, must be built and hardened first.

### 3.2 Dependency chain (what must exist first)

```
[Claude Code JSONL]  +  [repo git state: branch, commit SHA, diff]
        │                          │
        └──────────┬───────────────┘
                   ▼
        (1) SOURCE ADAPTER  ── reads JSONL, joins git state   ← FOUNDATION, build first
                   ▼
        (2) governance_trajectory/v2 SCHEMA  ← the contract
                   ▼
        (3) NORMALIZER  ── JSONL → v2 record, causal-chain reconstruction
                   ▼
        (4) PROVENANCE  ── SHA256(raw) registry, immutable raw archive     ┐
                   ▼                                                        │ MVP (Phase 1)
        (5) REPLAY / VERIFY  ── round-trip fidelity check                  ┘
                   ▼
        (6) EVALUATOR  ── deterministic scores + governance labels        ← Phase 2
                   ▼
        (7) OUTCOME GROUNDING  ── link commit/diff/tests/CI/review         ← Phase 3
                   ▼
        (8) SQLite INDEX  →  (9) TIERED RELEASE PACKAGES                   ← Phase 4
```

**Must exist before anything: (1) source adapter + (2) schema.** They are the two things whose
mistakes are unrecoverable (bad capture can't be re-derived; a schema change invalidates every
prior record).

---

## 4. MVP Success Criteria (Phase 1)

- **Input:** a completed Claude Code session JSONL + the repository git state (branch, HEAD SHA,
  working-tree diff) at session end.
- **Output:** one `governance_trajectory/v2` record = `{ immutable raw pointer + SHA256, normalized
  trajectory, environment, provenance }`, with evaluator/outcome fields present and explicitly `null`.

**Measurable quality criteria**

| # | Criterion | Threshold |
|---|---|---|
| Q1 | Causal-chain completeness — every `assistant` action resolves to a parent request via `parentUuid`; sidechains attached as nested subagent trajectories | 0 orphan nodes |
| Q2 | Replay fidelity — normalized trajectory regenerates the ordered (tool_call → tool_result → file-change) sequence identical to raw | byte-stable digest match |
| Q3 | Provenance integrity — `SHA256(raw)` equals registry entry; any mutation is detected | tamper test fails closed |
| Q4 | Environment completeness — `session_id, model, branch, commit_sha, cwd` all populated **or** record flagged `incomplete` and denied Tier > C | 100% populated-or-flagged |

**Validation tests**

- Golden-file round-trip on the real 51-record sample (normalize → replay → compare digest).
- Hash-mismatch injection: corrupt one raw byte → verifier must reject, not warn.
- Missing-field fail-closed: strip `commit_sha` → record must be capped at Tier C, never promoted.
- Unknown-record-type: inject a novel `type` → quarantine, never silently dropped.

**Failure conditions (all fail closed)**

- Raw hash ≠ registry → **reject** record.
- Missing branch/commit/model → tier ceiling C; cannot be S/A regardless of content.
- Parser meets unknown record type or version → **quarantine** (retained, flagged), pipeline continues.
- Secret detected in raw/diff (see R2) → **block archive** until scrubbed + logged.

---

## 5. ACGS Alignment Review

| ACGS principle | Mechanism in this design |
|---|---|
| **Evidence before claims** | Tier S/A require *linked* outcome rows (merge, tests-pass, review). No evidence → no success tier. Score fields null until Phase 2 evaluator runs deterministically. |
| **Fail closed** | Missing/ambiguous evidence *downgrades* tier, never upgrades. Unknown record → quarantine. Hash mismatch → reject. Secret → block. Default state of every derived claim is "unproven." |
| **Immutable provenance** | Raw JSONL archived append-only; SHA256 registry is the tamper witness. Raw is never edited — annotations live in a separate, rebuildable store. |
| **Deterministic verification** | Evaluator (Phase 2) is a pure function of the normalized trajectory — no LLM in the scoring/gating path. An LLM may produce *advisory* commentary, but it can never set a score or a tier. |
| **Separation of raw & derived** | Three physically separate layers: `raw/` (immutable, authoritative), index (derived, rebuildable from raw), annotations/scores (derived, rebuildable). Deleting derived layers loses nothing; deleting raw is the only irreversible act, and it is write-once. |

This design is ACGS-shaped by construction: the raw evidence and the derived judgment are never
allowed to touch, and every derived judgment fails toward "unproven."

---

## 6. Risks

| ID | Risk | Sev | Mitigation |
|---|---|---|---|
| R1 | **Transcript format drift** across Claude Code versions (`version` field varies) | HIGH | Version-tagged source adapters; quarantine unknown shapes; pin a golden sample per version; adapter is the first + most-tested component. |
| R2 | **Secret leakage** — transcripts/diffs of an ACGS session may contain keys, tokens, `.env` content | HIGH | Mandatory scrub + detect-secrets gate *before* archive; fail-closed block on hit; this is a Phase-1 requirement, not a later add-on (per workspace secrets policy). |
| R3 | **Causal gaps with subagents/sidechains** — `isSidechain` branches, parallel tool calls | MED | Model subagent runs as nested trajectories; Q1 test asserts zero orphans including sidechains. |
| R4 | **Outcome grounding is off-session** — git/CI/review may live elsewhere than the capture host | MED | Phase 3 defines explicit connectors; until then outcome fields are null and tiers cap at B. |
| R5 | **Deterministic labels create false confidence** — auto governance labels read as ground truth | MED | Label everything as *heuristic signal*; Tier S still requires human review; scores are advisory inputs to tiering, not the tier itself. |
| R6 | **Scope explosion** — 10 subsystems requested; pressure to build C now | MED | This ADR is the mitigation. Phase gate: no Phase N+1 work until Phase N passes its validation tests. |

---

## 7. Phased Roadmap

| Phase | Name (maps to option) | Delivers | Exit gate | Complexity |
|---|---|---|---|---|
| **0** | This ADR | scope + v2 schema design | scope approval | S (done) |
| **1** | **Session Capture (Option A)** | source adapter, normalizer, `governance_trajectory/v2`, immutable raw + SHA256 registry, replay/verify, secret-scrub gate | Q1–Q4 pass on golden sample | **M** (~2–3 wk, 1 eng) |
| **2** | Governance Evaluation (Option B) | deterministic evaluator (investigate-before-edit, verified-claims, tests-added, security-risk, fail-closed-preserved, evidence-for-conclusions), 4 scores, S/A/B/C tiering | evaluator is pure + reproducible on fixtures | **M** |
| **3** | Outcome Grounding (Option D) | connectors: commit ↔ diff ↔ tests ↔ CI ↔ review ↔ deploy; evidence rows | no Tier S without complete evidence chain | **L** (external integration) |
| **4** | Dataset Factory (Option C) | SQLite index, tiered release packaging, `ACGS-Claude-Engineering-v1`, `ACGS-Governance-Benchmark`, `ACGS-Agent-SWE` | reproducible release build from raw + registry | **L** |

**Full program: XL.** MVP (Phase 1) alone: **M**.

---

## 8. Decision Requested

Approve **Phase 1 (Option A, built to `governance_trajectory/v2`, with fail-closed provenance and
secret scrubbing in scope)** as the first milestone, and approve the v2 schema design as the next
work item before any collector code is written.

Deferred to explicit later approval: evaluator scoring, governance auto-labels, outcome connectors,
SQLite index, release packaging, and the three commercial datasets.

**No implementation proceeds until this scope is approved.**
