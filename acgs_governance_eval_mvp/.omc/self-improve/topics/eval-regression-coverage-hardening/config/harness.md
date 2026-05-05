# Harness Rules

## H001 — One Hypothesis Per Plan
Each plan must test exactly one hypothesis. Plans with zero or multiple hypotheses are rejected by the critic.

## H002 — No Approach Family Streak
The same `approach_family` must not appear as the winner for 3 or more consecutive iterations. This prevents the system from getting stuck in a local exploration loop.

## H003 — Intra-Round Diversity
Within a single round, no two plans may share the same `approach_family`. The critic rejects the later plan if a duplicate family is detected.

## H004 — Reproducibility
Any candidate's reported `regression_coverage_score` and `pass_rate` must be reproducible. The orchestrator re-runs the benchmark on the merged improvement branch with `regression_threshold = 0.0`. If the second run does not match within threshold, the merge is reverted and the candidate is rejected.

## H005 — Evidence-Required Winner
Every accepted winner's iteration history record must contain:
- `before_score`
- `after_score`
- `benchmark_output_before`
- `benchmark_output_after`
- `changed_files`
- `hypothesis`

If any field is missing or empty, the recording step writes `status: "evidence_incomplete"` instead of a winner record, and the merge is reverted in a follow-up cleanup pass.

## H006 — Scope Fence
Edits must touch only paths under:
- `tests/**`
- `governance/**` for small correctness fixes of 50 lines or fewer per file
- `docs/**`
- `scripts/**`, excluding sealed benchmark wrappers
- `.omc/self-improve/topics/eval-regression-coverage-hardening/state/**`
- `.omc/self-improve/topics/eval-regression-coverage-hardening/plans/**`
- `.omc/self-improve/topics/eval-regression-coverage-hardening/tracking/**`

Plans whose `target_files` include any other path are rejected unless they declare `scope_override: true` and the override is preapproved in `config/idea.md`.

## H007 — No Network / Secret / Deploy
The benchmark wrapper and any plan-introduced code must not:
- Make outbound HTTP, HTTPS, DNS, socket, websocket, or upload requests.
- Read secrets from environment variables or hard-code secret literals.
- Invoke deploy or upstream-write commands such as `gh pr create`, `git push`, `kubectl`, `vercel`, `wrangler`, `flyctl`, or `docker push`.

`scripts/check-scope.sh` is invoked before tournament acceptance and before any internal `--no-ff` merge into `improve/eval-regression-coverage-hardening`. Non-zero exit rejects the candidate and prevents benchmark acceptance.

## H008 — No CRIT/HIGH Regression
PRs #4-#8 and the codex-investigate/autofix rows in the source final report resolved CRIT/HIGH issues including O(n^2) audit append, fnmatch path traversal, API auth bypass, decision-state TOCTOU, tenant spoof, audit race, and no-audit guard. Any plan that touches related surfaces must reference the corresponding regression tests in its verification section. Plans that touch those paths without relevant regression verification are rejected.

## H009 — Sealed Files Are Hard-Sealed
`validate.sh` enforces `sealed_files`. If the diff modifies any sealed path, the executor must fail with `status: "harness_violation"` before benchmarking. Candidates with `harness_violation` are not considered.

## H010 — Benchmark Sanity & Determinism
`scripts/bench-coverage.sh` must:
1. Emit exactly one parseable JSON object on stdout.
2. Include `total > 0`; if `total == 0` or output is unparseable, exit 2 and emit `harness_error`.
3. Support a 3x baseline determinism gate whose compared JSON fields are byte-identical for `pass_rate`, `passed`, `failed`, `errors`, `skipped`, and `total`.
4. Treat candidates with `harness_error` as infrastructure failures, not scores.

H010's byte-identical determinism gate applies to JSON bench outputs only. `progress.png` is optional visualization output and is excluded from determinism comparison.

## H011 — Regression Marker Integrity
Every seed and Phase-B regression test must carry `@pytest.mark.regression(pr, severity, issue, coverage_angle)`. All four fields are required. Missing fields reject the candidate.

## H012 — Severity Inheritance
For each `(pr, issue)` tuple, marker `severity` must equal the issue severity declared in `tests/regression_seed.json`. Severity downgrades or mismatches reject the candidate.

## H013 — Coverage-Angle Uniqueness
`coverage_angle` is per-test and must be unique within each `(pr, issue)` tuple. Multiple tests for one issue are allowed only when their `coverage_angle` values are distinct.

## H014 — Skip/Xfail Guard
Marked tests with outcomes `skipped` or `xfailed` contribute zero weight. If the marked test severity is `CRIT` or `HIGH`, a skipped or xfailed outcome rejects the candidate.

## H015 — Phase-B Credit Boundary
The bench records a frozen Phase-A baseline nodeid set at `.omc/self-improve/topics/eval-regression-coverage-hardening/state/phase_a_nodeids.json`. That file is sealed after it is written once at activation.

Rules:
- Seed-marked Phase-A tests count toward `seed_baseline_points`.
- Existing unmarked tests present in the Phase-A baseline do not earn new Phase-B credit if merely re-tagged later.
- Phase-B contribution is cumulative across accepted iterations, but only for regression-marked nodeids not present in the frozen Phase-A baseline.
- Each candidate must increase cumulative Phase-B points versus the previously accepted iteration unless it is an explicitly approved non-scoring maintenance iteration using `scope_override` plus `idea.md`.

## H016 — Seed-Baseline Integrity
`scripts/bench-coverage.sh` recomputes `seed_baseline_points` from `tests/regression_seed.json` by summing `severity_weight * len(seed_tests)` for all issues with `contributes: true`.

If the recomputed value differs from the declared `seed_baseline_points`, the bench fails closed with:

```json
{"harness_error": "seed_baseline_drift", "declared": 70, "recomputed": 0}
```

The wrapper exits 2, and the orchestrator treats the result as an infrastructure failure. H016 runs at Phase A baseline and every Phase B bench invocation.

## Custom Approach Families
- `test_repair` — fixing a failing or flaky test without changing production code.
- `correctness_fix` — small bug fix in `governance/**` covered by an existing or newly-added test.
- `evidence_hardening` — improving determinism or reproducibility of the test suite.
- `regression_proofing` — adding a test that locks in a previously-fixed CRIT/HIGH issue.
