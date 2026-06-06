---
title: "Correctness-gated self-improve on acgs-lite: the critic gate is load-bearing and H002 is the real iteration ceiling"
date: 2026-06-06
category: workflow-issues
module: self-improve
problem_type: workflow_issue
component: development_workflow
severity: medium
related_components:
  - tooling
  - testing_framework
applies_when:
  - "Running a behavior-preserving, clean-files-only performance self-improve loop"
  - "The objective is single-axis (throughput) so every candidate is approach_family optimization"
  - "Optimizing a governance/enforcement engine where the cheapest throughput wins weaken enforcement"
  - "The harness has an anti-streak rule (no approach_family wins 3+ consecutive iterations)"
  - "A loop gate depends on cross-iteration history (consecutive-winner caps, novelty quotas)"
symptoms:
  - "Iterations 1-2 merged on benchmark + re-benchmark alone with NO recorded critic verdict"
  - "Loop converged at iter3 not on performance headroom but on the H002 streak rule"
  - "A change passing every correctness/scope gate was rejected as the 3rd consecutive optimization winner"
tags:
  - self-improve
  - evolutionary-optimization
  - correctness-gate
  - critic-gate
  - approach-family
  - acgs-lite
  - governance-engine
  - performance
---

# Correctness-gated self-improve on acgs-lite: the critic gate is load-bearing and H002 is the real iteration ceiling

## Context

We ran a `/self-improve` tournament evolutionary loop on `packages/acgs-lite` — a
PyPI-published constitutional-governance library that lives as a nested git repo
inside the govern-zone monorepo. The loop ran under deliberately conservative
constraints: **correctness-gated, local-only, behavior-preserving,
clean-files-only**. Only three hot-path modules were editable
(`engine/enforcement.py`, `engine/matcher.py`, `engine/models.py`); the
constitutional core, rule definitions, tests, and benchmark scripts were SEALED.

Optimizing a sealed, correctness-critical governance engine surfaces friction you
do not see on ordinary perf work. The cheapest throughput wins are precisely the
changes the project forbids (weakening enforcement). The diversity guard meant to
prevent local-optimum thrash collides with a scope that admits essentially one
approach-family. And the harness gate that is supposed to enforce that guard turns
out to depend on cross-iteration history that the controller can silently fail to
supply.

Outcome: 4 iterations, stopped on `max_iterations`, **net +10.0%**
(543.581 → 597.944 k-OPS), with the full 5916-test suite green on every confirmed
round. The durable value is not the +10% — it is the three process learnings below.

## Guidance

### A. On a constrained perf loop, the diversity guard is the iteration ceiling — not raw headroom

A behavior-preserving + clean-files-only performance loop is effectively a
**single approach-family** (`optimization`). Every micro-opt is "optimization"; the
only other defined family, `infrastructure`, would require restructuring that needs
the sealed files or risks semantic change. Plan for the loop to terminate on the
diversity guard, not on exhausting performance headroom.

Harness rule **H002**: the same `approach_family` must not WIN 3+ consecutive
iterations (it guards against local-optimum exploration loops). In this run, after
two `optimization` wins (iter1: lazy `EnforcementResolution.outcomes`; iter2:
hand-written `ValidationResult.__init__`), iter3's only remaining lever — a
hand-written `EnforcementResolution.__init__` worth ~0.6–1.2%, *below* the plateau
threshold — passed every correctness/scope gate (H001, H010–H014) but the critic
correctly REJECTED it on H002 as the would-be 3rd consecutive `optimization`
winner, advising "the clean-files vein is exhausted, converge to a stop." Treat
that verdict as the honest signal to stop. Do **not** fabricate an
`infrastructure`-family plan just to dodge H002 — that violates the sealed-scope
rules (H010/H014). Bank the verified win and converge.

### B. The critic gate is load-bearing — spawn it explicitly WITH the prior-winner family history

In this run, iters 1–2 were merged on benchmark + re-benchmark alone, with **no
recorded critic verdict** — the controller silently stood in for H002, which left
the diversity guard effectively unenforced for two rounds. That is a wiring gap,
not a stylistic one.

H002 is the **critic's** call (skill Step 6b), not the controller's. The critic
agent must be spawned with the prior winners' `approach_family` values in its
prompt — without that history it physically cannot apply a "3 consecutive winners"
rule. Two reusable rules:

1. **Always spawn the critic explicitly, and pass it the running list of prior
   winning families.** A gate that depends on cross-iteration state is unenforced
   unless that state is handed to the agent that owns the gate.
2. **Don't game the streak counter.** After an H002 rejection produces a no-winner
   round, the consecutive-streak technically resets — but re-submitting the
   identical rejected plan next round honors H002's letter while defeating its
   spirit. Let the critic own the call; don't agonize and don't game.

### C. Embed the correctness gate INSIDE the benchmark command

On a governance engine, the cheapest throughput wins are enforcement-weakening
shortcuts (skip MACI separation, short-circuit constitutional validation). A
perf-only score rewards exactly the changes the project forbids. The fix: make the
benchmark command itself run the full test suite FIRST and emit a zero score on any
failure, so a behavior-breaking candidate can never out-score the baseline and can
never merge.

`scripts/si_benchmark_gated.py` runs the full suite first; on any failure it emits
`{"primary": 0.0, ..., "correctness_passed": false}` and exits non-zero. The loop
only trusts the benchmark command's **stdout**, so the gate must live *inside* that
command — never as a separate step the loop could skip or reorder.

Worktree gotcha: the benchmark must run from inside its own checkout (conftest
force-inserts the local `src` at the front of `sys.path`; a default cwd would
import the stale installed PyPI copy). Resolve `PKG_ROOT` from
`Path(__file__).resolve().parents[1]` so it is worktree-safe.

## Why This Matters

- **Without an enforced diversity guard (A + B):** the loop either thrashes against
  a local optimum or, worse, an agent games the reset to keep merging the same
  micro-opt — burning iterations while believing it is exploring. Knowing the guard
  *is* the ceiling lets you stop honestly with a banked, fully-tested win instead of
  fabricating an out-of-scope plan to keep the streak alive.
- **Without passing prior-winner history to the critic (B):** H002 cannot fire at
  all — the critic has no way to know what won before, so a guard that exists on
  paper is dead in practice. Two rounds shipped here with the controller silently
  standing in; the gap was invisible until an advisor caught it.
- **Without embedding correctness inside the benchmark (C):** a perf-only score
  actively rewards enforcement-weakening "wins." On a regulated governance library
  that is the most dangerous possible failure — the loop would optimize *toward* the
  behavior the project is built to forbid, and a green perf number would launder it.

## When to Apply

- Running any tournament / evolutionary self-improvement loop (`/self-improve`,
  `ce-optimize`, autoresearch-style loops), **especially** on sealed, regulated, or
  correctness-critical code.
- Any agentic loop with a gate that depends on cross-iteration history
  (consecutive-winner caps, diversity quotas, novelty requirements) — the state that
  gate needs must be explicitly threaded into whichever agent owns the gate.
- Any optimization loop scored by a single metric where the cheapest way to raise
  the metric is to weaken a property the project must preserve (correctness, safety,
  security, compliance). Fold the must-preserve check into the scoring command
  itself.
- Any loop that runs candidates in worktrees while a stale copy of the same package
  is installed on the path.

## Examples

**Iter2 winner — hand-written `__init__` that preserves `default_factory`
semantics (allow path 809k → 889k k-OPS):**

```python
# Before: generated __init__ pays a _HAS_DEFAULT_FACTORY sentinel check
#         + a list() call per list field on every construction.
@dataclass(slots=True)
class ValidationResult:
    valid: bool
    constitutional_hash: str
    violations: list[str] = field(default_factory=list)
    warnings: list[str]  = field(default_factory=list)

# After: suppress only __init__; hand-write it. __eq__/__repr__ still auto-generate.
_MISSING = object()  # module-level sentinel: an explicitly-passed None is preserved exactly

@dataclass(slots=True, init=False)
class ValidationResult:
    valid: bool
    constitutional_hash: str
    violations: list[str]
    warnings: list[str]

    def __init__(self, valid, constitutional_hash,
                 violations=_MISSING, warnings=_MISSING):
        self.valid = valid
        self.constitutional_hash = constitutional_hash
        self.violations = [] if violations is _MISSING else violations  # BUILD_LIST literal
        self.warnings  = [] if warnings  is _MISSING else warnings
```

Invariants that make this behavior-preserving: param names **equal** field names
exactly (callers use kwargs); field order preserved (positional construction sites
still work); `_MISSING` sentinel (not `None`) so an explicitly-passed `None` is
kept, matching `default_factory` semantics; `init=False` suppresses only `__init__`,
so `__eq__`/`__repr__` still auto-generate.

**Benchmark-gate shape — correctness check lives inside the scored command:**

```python
# scripts/si_benchmark_gated.py  (SEALED — the loop trusts only its stdout)
from pathlib import Path
PKG_ROOT = Path(__file__).resolve().parents[1]   # worktree-safe; not cwd-dependent

# 1. Correctness FIRST — full suite, run from inside this checkout.
rc = run_pytest(PKG_ROOT / "tests")              # conftest force-inserts local src on sys.path
if rc != 0:
    print(json.dumps({"primary": 0.0, "correctness_passed": False}))
    sys.exit(1)                                  # behavior-breaker can never out-score baseline

# 2. Only a correct candidate reaches the throughput measurement.
score = measure_kops()
print(json.dumps({"primary": score, "correctness_passed": True}))
```

The ordering is the point: pytest gates the score, the gate is *inside* the command
the loop reads, and a failing candidate is pinned to `primary: 0.0` so it can never
merge.

## Related

- Project memory (canonical source for this run, not a `docs/solutions/` doc):
  `~/.claude/projects/-home-martin-Documents-ACGS/memory/self-improve-acgs-lite-correctness-gate.md`
- Loop artifacts: `.omc/self-improve/topics/acgs-lite-validate-throughput/` (per-round
  research briefs, iteration history, merge reports, tracking data).
