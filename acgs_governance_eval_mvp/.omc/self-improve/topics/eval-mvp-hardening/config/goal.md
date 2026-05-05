# Improvement Goal

## Objective
Harden the ACGS governance eval MVP so the self-improve loop **cannot claim progress without reproducible evidence**. Every accepted improvement must be backed by a benchmark output that another clean run reproduces, and every change must stay inside the agreed scope fence.

This is *defensive* improvement: the loop is improving the system's ability to demonstrate correctness under repeated evaluation, not optimizing a single accuracy number.

## Target Metric
- **Metric name**: `pass_rate` — fraction of repo-local pytest cases that pass on a fresh run from a clean working tree.
- **Target value**: `1.0` (100%)
- **Direction**: `higher_is_better`
- **Tie-breaker**: when multiple candidates report the same `pass_rate`, prefer the one with (a) more total tests collected (signal: the harness grew, not shrank), then (b) smaller diff size (signal: minimal correctness fix).

## Scope
- **In scope** (and only these):
  - `tests/**` (add or repair tests)
  - `governance/**` (small correctness fixes only — no architectural rewrites)
  - `docs/**` (clarification, no scope change)
- **Out of scope** (auto-rejected unless plan carries `scope_override: true` AND user idea.md preapproval):
  - Dependency changes (`pyproject.toml`, `requirements*.txt`, `setup.{py,cfg}`, lockfiles — all sealed)
  - Refactors of `governance/**` (>50 lines moved, public API change, new module)
  - Network-dependent code paths (HTTP clients, file uploads, websocket, DNS, raw sockets)
  - Deploy paths (`gh pr create`, `git push`, `kubectl`, `vercel`, `wrangler`, `flyctl`, `docker push`)
  - Upstream writes (push, force-push, PR creation, merge to main/master)
  - Submodule pointer changes (none expected — repo has no submodules)
  - `.omc/**`, `.git/**`, `.omx/**`, `.benchmarks/**` (runtime state, not source)

## Non-Goals (explicit)
- Performance optimization (latency, throughput) — not measured by this loop.
- Coverage percentage — `pass_rate` is the only primary metric.
- New features beyond what's needed to repair a failing test or fix a CRIT/HIGH regression.

## Success Definition
The loop has succeeded when **all three** hold:
1. `pass_rate == 1.0` for two consecutive iterations on independent runs from clean tree.
2. No CRIT/HIGH issue resolved in upstream PRs #4–#8 has been reintroduced (verified by `tests/test_*.py` cases that originated from those PRs).
3. The `.omc/self-improve/topics/eval-mvp-hardening/state/iteration_history/` shows every accepted winner has both `before_score`, `after_score`, and a non-empty `changed_files` list.

## Milestones
| Milestone | Target | Strategy Focus |
|-----------|--------|----------------|
| M1 | Baseline `pass_rate` recorded | Confirm deterministic baseline via 3× validation |
| M2 | `pass_rate >= 0.95` sustained | Repair flaky/missing tests; small correctness patches |
| M3 | `pass_rate == 1.0` confirmed twice | Final hardening; reproducibility audit |

## Experiment Ideas
See `idea.md` (managed separately).
