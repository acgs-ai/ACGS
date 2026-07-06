# ACGS/govern-zone — 12-Week Development Roadmap

> **Status**: Draft synthesized 2026-05-22 from CCA (Claude+Codex+Agy) advisor pass against
> the existing 7 roadmap docs. Strategic approach: **hybrid** — kernel-first hardening +
> paper-validation gate, then R5/R6→R1/R2→R3→R7/R4 features layered on a verified kernel.
> Not yet committed to git. Review then `git add ROADMAP.md` deliberately.

## Reconciliation of existing roadmap docs

| Doc | Action | Reason |
|---|---|---|
| `ROADMAP.md` (this file) | **Canonical, root-level** | Single source of truth for the quarter |
| `docs/PLAN-GOVE-ZONE-KERNEL.md` | **Promoted to Phase 1 spec** | Kernel-first principle is sound; embed |
| `AUTHZ-ROADMAP.md` | **Demoted to design spec referenced from Phase 2-4** | Drives feature plan but conditional on validation gate |
| `MACI-ROADMAP.md` | Keep as Phase 2/4 dependency track | R1/R2 identity + R4 aggregation reference |
| `MONOREPO.md` | Keep as package registry/gate map | Authoritative for what exists, not what to build |
| `docs/PLAN-MONOREPO.md` | Merge Phase 5 (hash CI) into Phase 4 below; archive remainder | Largely subsumed; constitutional-hash CI is the surviving asset |
| `docs/workspace-PLAN.md` | Archive | Duplicate of PLAN-MONOREPO content |
| `PLAN.md` (84KB) | Keep, scope frozen to `acgi-ai/` frontend | Different scope entirely; runs parallel |
| `docs/PLAN-GOVE-ZONE-KERNEL.md` | Keep, embedded in Phase 1 | See above |
| `COMPARISON.md` | Keep as decision-record artifact | Historical |

## Strategic decision

Codex recommended building the AUTHZ feature stack directly on the existing runtime. agy
recommended kernel-first hardening AND flagged the arXiv 2605.05440 preprint as
single-author, unreplicated, and a P0 risk to build a quarter on.

**Hybrid chosen**: Phase 1 hardens `packages/gove-zone` (kernel) AND runs a Week-2
benchmark gate on the paper's propagation model. If propagation overhead >15% vs token-based
headers, fall back to the lightweight authz design and re-scope Phases 2-4 accordingly.

## Phase overview

| Phase | Weeks | Name | Exit Criteria | Owning Packages | Top Risk |
|---|---|---|---|---|---|
| 1 | 1-3 | Kernel hardening + paper gate | Fail-closed tool interception + receipt-chain verify + benchmark verdict | `packages/gove-zone`, `acgs_governance_eval_mvp` | Benchmark verdict invalidates downstream phases |
| 2 | 4-6 | R5/R6 trace receipts (gated) | Receipt + audit-chain event in `make verify` and `python-eval-mvp.yml` | `acgs_governance_eval_mvp` (incl. `governance/adapters/hermes`), `packages/acgs-lite` | Receipt format divergence across packages |
| 3 | 7-9 | R1/R2 identity + R3 boundary enforcement | Actor/tenant/role propagate through adapter→gate→receipt→replay; boundary mismatch fails closed before side effects | `packages/acgs-lite`, `acgs_governance_eval_mvp` (incl. `governance/adapters/hermes`), `packages/Acgs-Swarm` | Submodule pointer drift; py3.10 floor break in `acgs-lite` |
| 4 | 10-12 | R7/R4 recovery + aggregation + constitutional-hash CI | Recovery emits governed incident evidence; aggregate reporting is MACI-aware; hash workflow gates sealed files | Root CI, `acgi-ai`, `packages/acgs-lite`, `acgs_governance_eval_mvp` | Hash updates become manual brittle release blockers |

## Cross-package coupling

```
Tight serial:   gove-zone → acgs-lite → {Acgs-Swarm, clinicalguard, acgs_governance_eval_mvp}
Parallel-safe:  acgi-ai (frontend) | agent-bus-analyzer (observability)
```

`acgi-ai` and `agent-bus-analyzer` can ship features in parallel using mocked API endpoints.
Anything on the tight serial path must wait for upstream phase completion.

## Phase 1 (Weeks 1-3) — concrete deliverables

> **Reality check (audited 2026-05-22):** `packages/gove-zone/` already contains a built
> kernel (`kernel.py`, `policy.py`, `decision.py`, `audit.py`, `receipt.py`, `replay.py`,
> `api.py`, `cli.py`, `tool.py`, `errors.py`) and 8 test files including
> `tests/test_fail_closed.py` (5.8KB). **Week 1 is AUDIT-and-GAP-FILL, not greenfield.**

### Week 1: Audit existing kernel + gap-fill fail-closed coverage
- **AUDIT** `packages/gove-zone/tests/test_fail_closed.py` against the 3 scenarios:
  - **Scenario A** (disk/log exhaustion): mock filesystem `OSError` during
    `ChainHashAuditStore.append`; assert tool is never executed, kernel raises `AuditError`
  - **Scenario B** (policy runtime crash): inject `ValueError` inside `Policy.evaluate`;
    assert kernel catches, writes synthesized `DENY` to audit log, raises `DeniedError`
  - **Scenario C** (watchdog timeout): mock policy evaluation to hang; assert watchdog
    aborts after 200ms, records synthesized `DENY`, fails closed
- **GAP-FILL** any missing scenarios as new test functions in the existing file (or a
  new `test_fail_closed_gaps.py` if scope grows)
- Verify `make verify` reaches `packages/gove-zone` tests (if not, wire it up)
- **DO NOT create `interception.py`** — kernel is already implemented in `kernel.py`

### Week 2: Paper validation gate
- `packages/gove-zone/benchmarks/test_propagation_overhead.py` — Mock 3-agent chain
  (Orchestrator → Planner → Executor), 50KB payload, 10 parallel chains
- **Pass/fail thresholds**:
  - Mean latency overhead ≤15%; **p95 ≤25%** (sharper agy criterion)
  - Token-consumption overhead ≤10%
  - Heap growth ≤5MB across the suite (no leaks)
  - Network resilience: under simulated 500ms timeout, lookup must abort + fail closed
    within 500ms (no hang)
- **Gate verdict**:
  - PASS → ADR `docs/adr/0005-authz-propagation-accepted.md`, proceed with R5/R6
  - FAIL → ADR `docs/adr/0005-authz-propagation-rejected.md`, switch to token-based
    fallback (JWT-style capability tokens signed by Orchestrator with localized path +
    capability caveats; verification in PreToolUse hooks)
- Benchmark output committed under `.benchmarks/propagation-gate-week2.json`

### Week 3: Audit-chain verification + R5/R6 schema (conditional)
- `acgs_governance_eval_mvp/tests/test_authorization_trace_receipts.py` — receipt + chain
  verify, fail-closed on missing/mismatched hash
- `acgs_governance_eval_mvp/governance/schema/authorization_trace.schema.json`
- `acgs_governance_eval_mvp/governance/models.py` — additive `AuthorizationTrace`,
  `DecisionReceiptRef` types
- `acgs_governance_eval_mvp/governance/audit/jsonl_chain.py` — persist trace payload in
  chain-hashed event
- CI: `.github/workflows/python-eval-mvp.yml` runs the new tests

## Phase 1 first action (do this)

```bash
# AUDIT existing fail-closed coverage (do NOT recreate; the file already exists at 5.8KB)
cd packages/gove-zone && python -m pytest tests/test_fail_closed.py -v
# Then read the file and check which of agy's scenarios A/B/C above are NOT covered.
# Add a separate test_fail_closed_gaps.py for missing scenarios via TDD.
```

## Execution protocol (from CCA round 2)

### Branch + PR cadence
- One feature branch per phase off `master`: `phase-1-kernel-hardening`
- Weekly PRs into that phase branch: `phase-1-week-1-fail-closed-audit`,
  `phase-1-week-2-paper-gate`, `phase-1-week-3-audit-chain` (R5/R6 conditional)
- Merge each week before starting the next unless blocked by review

### Commit location
- `packages/gove-zone` is NOT a submodule — commit in parent repo
- `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard` ARE nested repos:
  commit inside the nested repo, THEN bump the parent pointer in a separate commit

### Dirty-state handling
- `packages/Acgs-Swarm` is already DIRTY (untracked). **Carve around it for Phase 1
  Week 1**: no edits, no staging, no parent pointer update. If Phase 3 needs it, resolve
  via a separate prep PR before that phase.

### Phase 1 Week 1 first commit (after Week 1 work)

```bash
git add ROADMAP.md
git add packages/gove-zone/tests/test_fail_closed_gaps.py  # if gap-fill needed
# DO NOT git add packages/Acgs-Swarm
# DO NOT git add -A
git commit -m "feat(gove-zone): audit + gap-fill fail-closed coverage (OSError, watchdog)"
```

## Verification matrix per phase

### Phase passes (local exit code 0)
- Phase 1: `make verify` + `cd packages/gove-zone && python -m pytest tests/ -q` +
  benchmark gate artifact at `.benchmarks/propagation-gate-week2.json`
- Phase 2: `make verify` + `cd acgs_governance_eval_mvp && python -m pytest -q` +
  `cd packages/acgs-lite && make lint typecheck test`
- Phase 3: above + `cd packages/Acgs-Swarm && python -m pytest tests/ --import-mode=importlib`
- Phase 4: above + `pnpm -F acgi-ai lint && pnpm -F acgi-ai build && pnpm -F acgi-ai test`

### Phase ready for review
- Phase passes AND `git diff --stat` scoped (no submodule pointer drift) AND
  relevant `.github/workflows/*.yml` green AND ADR landed (when phase requires one)

### Workflow files gated per phase
- Phase 1: `python-gove-zone.yml`, `python-eval-mvp.yml`, `constitutional-hash.yml`
- Phase 2: + `python-acgs-lite.yml` (hermes bundle folded into eval-mvp; covered by `python-eval-mvp.yml`)
- Phase 3: + `python-acgs-swarm.yml`
- Phase 4: + `console.yml`, `marketing.yml`

## Final-goal acceptance test (end of week 12)

```bash
make verify \
  && cd packages/acgs-lite && make lint typecheck test \
  && cd ../../packages/Acgs-Swarm && python -m pytest tests/ --import-mode=importlib \
  && cd ../../acgs_governance_eval_mvp && python -m pytest -q \
  && cd .. && test -f .benchmarks/propagation-gate-week2.json \
  && test -f docs/adr/0005-authz-propagation-{accepted,rejected}.md
```

Exit 0 = quarter done.

## Receipt-chain integrity caveat (from agy)

Multi-agent concurrent writes serialize via `fcntl.flock` on `audit.jsonl.lock`. On
distributed/network filesystems (NFS without lockd), this is unsafe — sibling records
with duplicate parentage break the linear cryptographic history. **Mitigation**: enforce
local SSD storage, or add a central lock-broker service. Document as known risk in
Phase 2 spec; add a startup probe that fails if `audit.jsonl` lives on NFS.

## Executor (Codex) failure mode (predicted + mitigated)

Codex tends to over-index on happy-path graph propagation and fail open on disk-exhaustion
or lock errors. Every Codex prompt for Phase 1 work MUST include:

> The authorization kernel is strictly fail-closed. Write tests asserting that any
> exception during policy evaluation, receipt hashing, or audit logging blocks tool
> execution BEFORE any side effects. Mock disk-full errors. No fallback-to-allow.

## Hard traps (executor must respect)

1. **Constitutional hashes are sealed.** Files with `# Constitutional Hash:` markers must
   not change without recomputing the hash via the documented flow.
2. **Submodule pointer drift.** `packages/acgs-lite`, `packages/Acgs-Swarm`,
   `packages/clinicalguard` are independent repos. Stage and commit from inside each.
   Update parent pointer as a separate deliberate commit.
3. **`acgs-lite` py3.10 published floor.** Any change in acgs-lite must remain additive,
   typed, lazy-imported, and pass `cd packages/acgs-lite && make lint typecheck test`.
4. **Never `git add -A`.** Stage explicitly file-by-file.
5. **Console CSP.** No public-only patterns (CDN fonts, third-party scripts) inside
   `acgi-ai/src/routes/console/**`.

## Verification gates (per phase)

Every phase MUST pass before the next begins:
- `make verify` at repo root (lint + typecheck + test across Python + JS)
- Per-package gate inside each touched package
- `.github/workflows/` CI green on the phase's PR
- Constitutional-hash check (`docs/constitutional-hashes.lock`) unchanged unless the
  phase explicitly modifies sealed files with a recomputation receipt
- Submodule pointers: deliberate commits, no accidental drift

## Final goal (end of week 12)

A multi-harness AI workspace where:
- Every governed tool call emits a replayable receipt linked to an audit chain
- Identity (principal/tenant/role/delegation) survives end-to-end
- Boundary mismatches fail closed before side effects, not after
- Recovery paths emit governed incident evidence
- Aggregate reporting is MACI-aware
- Constitutional-hash CI blocks unsigned changes to sealed files

This satisfies AUTHZ R1-R7 IF the Week-2 gate validates the paper's claims, OR a clean
token-based fallback satisfies a reduced authz set IF the gate fails.

## Archive criteria (falsifiable, per-file)

A roadmap doc can be archived (moved to `docs/archive/`) only when ALL three conditions
hold AND the file-specific gate below passes:

1. All its referenced tasks are either complete or migrated to `ROADMAP.md`
2. No active PR or open ADR references it
3. A `docs/archive/INDEX.md` entry records the archive date and reason

### Per-file gates (sharper than "tasks complete")

| Doc | Concrete gate before archive is allowed |
|---|---|
| `docs/PLAN-GOVE-ZONE-KERNEL.md` | `tests/test_fail_closed.py` + any gap-fill test reach 100% statement coverage; all pass |
| `AUTHZ-ROADMAP.md` | Week-2 benchmark results committed at `.benchmarks/propagation-gate-week2.json` AND ADR `docs/adr/0005-authz-propagation-{accepted,rejected}.md` merged |
| `docs/PLAN-MONOREPO.md` | `docs/constitutional-hashes.lock` integrated into pre-commit; `python-constitutional-hash.yml` green on a PR that intentionally modifies a sealed file |
| `docs/workspace-PLAN.md` | All non-duplicate tasks migrated; final diff with `ROADMAP.md` shows zero unmigrated items |
| `MACI-ROADMAP.md` | R1/R2 identity AND R4 aggregation implemented (verified by Phase 4 test fan-out) |
| `COMPARISON.md` | Replaced by at least 2 merged ADRs in `docs/adr/` covering its decision points |

## Open items requiring follow-up CCA round

- Exact execution protocol per phase (file-by-file order, branch strategy, PR cadence)
- Verification matrix per package (what tests/gates count as "phase complete")
- Detailed archive criteria for each demoted/merged document
- Final-goal acceptance test (what "quarter done" looks like as a single command output)
