# Improvement Goal

## Objective
Harden the ACGS governance eval MVP so regression evidence is measured by severity-weighted, fixed-denominator coverage rather than raw pass rate alone. Phase A establishes the manually-authored seed baseline and deterministic benchmark harness. Phase B may later add net-new regression tests for additional failure modes.

## Target Metric
- **Metric name**: `regression_coverage_score`
- **Formula**: `regression_coverage_points / seed_baseline_points`
- **Seed denominator**: `70`, sourced from `tests/regression_seed.json`
- **Target value**: `1.20`
- **Direction**: `higher_is_better`
- **Secondary guard**: `pass_rate` must not fall below `1.0`.

## Scope
- **In scope**:
  - `tests/**` for marker annotation, seed registry, and net-new regression tests.
  - `governance/**` only for small correctness fixes required by new regression tests.
  - `docs/**` for generated or explanatory regression evidence.
  - `scripts/**` for the benchmark wrapper and scope checks, except sealed files after activation.
  - `.omc/self-improve/topics/eval-regression-coverage-hardening/{config,state,plans,tracking}/` for this topic's own artifacts.
- **Out of scope unless explicitly preapproved**:
  - Dependency or lockfile changes.
  - Network, secret-reading, deploy, push, auto-PR, or upstream-write behavior.
  - Merges into `main` or any upstream branch.
  - Edits to `.omc/self-improve/topics/eval-mvp-hardening/**`.
  - Submodule changes.

## Phase A Milestones
| Milestone | Target |
|---|---|
| A1 | Seed mapping and registry files exist and parse. |
| A2 | Topic config, harness, and benchmark wrapper exist. |
| A3 | Seed tests are marked with `@pytest.mark.regression(...)`. |
| A4 | Baseline benchmark is byte-identical across three runs for the required JSON fields. |
| A5 | `phase_a_nodeids.json` is written once and sealed. |

## Phase B Readiness
Phase B may start only after Phase A commits a deterministic baseline where:
1. `regression_coverage_score == 1.0`
2. `regression_coverage_points == 70`
3. `seed_baseline_points_recomputed == 70`
4. `pass_rate == 1.0`

## Reference
The authoritative design source is `.omc/self-improve/topics/eval-regression-coverage-hardening/PROPOSAL.md` Rev 2.1.
