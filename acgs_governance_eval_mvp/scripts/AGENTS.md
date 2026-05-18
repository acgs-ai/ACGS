# AGENTS.md - acgs_governance_eval_mvp/scripts

## Purpose

Operator-facing shell tooling for the governance harness: pytest pass-rate
benchmark, severity-weighted regression-coverage benchmark, and a scope-fence
checker used before tournament acceptance / internal merges. All scripts are
no-network, no-secret, no-deploy and emit one structured JSON object on stdout
with pytest output redirected to stderr.

## Scripts

- `bench.sh` - repo-local pytest pass-rate benchmark. Emits `{pass_rate, passed, failed, errors, skipped, xfailed, xpassed, total, pytest_exit_code}`. Fail-closed: `total==0` or unparseable pytest output exits code 2 with `harness_error`. Refuses to delete a tracked `.acgs/audit.jsonl` fixture.
- `bench-coverage.sh` - severity-weighted regression-coverage benchmark. Reads `tests/regression_seed.json` plus `.omc/self-improve/topics/eval-regression-coverage-hardening/state/phase_a_nodeids.json`. Emits `{regression_coverage_points, regression_coverage_score, ...}` on top of the bench.sh shape. Also fail-closed on seed drift, empty collection, invalid markers.
- `check-scope.sh` - H006 scope fence + H007 network/secret/deploy denylist check. Usage: `./scripts/check-scope.sh --base <ref> [--worktree <path>]`. Exit 0 clean, 1 violations, 2 internal error. Base defaults to `improve/eval-regression-coverage-hardening`.

## How to Run

From the package root (`acgs_governance_eval_mvp/`):

```bash
bash scripts/bench.sh            # pass-rate JSON on stdout
bash scripts/bench-coverage.sh   # coverage JSON on stdout
bash scripts/check-scope.sh --base improve/eval-regression-coverage-hardening
```

## Gotchas

- Scripts `cd "$(dirname "$0")/.."` then operate from the package root; never invoke from a deeper cwd assuming relative paths will resolve.
- Bench scripts read `.acgs/audit.jsonl` and treat a tracked copy as a fixture (will not delete). Untracked copies are wiped at the start of `bench.sh`.
- `check-scope.sh` is read-only and safe to run in any worktree; the other two run pytest, so the worktree must be installable (`pip install -e .[test]`).
