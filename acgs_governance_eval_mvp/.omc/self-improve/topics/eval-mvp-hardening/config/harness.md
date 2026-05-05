# Harness Rules

## H001 — One Hypothesis Per Plan
Each plan must test exactly ONE hypothesis. Plans with zero or multiple hypotheses are rejected by the critic.

## H002 — No Approach Family Streak
The same `approach_family` must not appear as the winner for 3 or more consecutive iterations. This prevents the system from getting stuck in a local exploration loop.

## H003 — Intra-Round Diversity
Within a single round, no two plans may share the same `approach_family`. The critic rejects the later plan if a duplicate family is detected.

## Custom Rules

### H004 — Reproducibility
Any candidate's reported `pass_rate` must be reproducible. The orchestrator re-runs the benchmark on the merged improvement branch (Step 8d in SKILL.md) — if the second run does not match within `regression_threshold` (0.0), the merge is reverted and the candidate is rejected. Executors who emit non-deterministic test orderings, time-dependent assertions, or mutable global state are violating H004 even if their first-run number passes.

### H005 — Evidence-Required Winner
Every accepted winner's iteration history record (`state/iteration_history/round_{n}.json`) must contain:
- `before_score` (orchestrator-side, pre-merge)
- `after_score` (orchestrator-side, post-merge re-bench)
- `benchmark_output_before` (raw JSON line from bench.sh, pre-merge)
- `benchmark_output_after` (raw JSON line from bench.sh, post-merge)
- `changed_files` (non-empty list, sourced from `git diff --name-only improve/eval-mvp-hardening~1..improve/eval-mvp-hardening`)
- `hypothesis` (one sentence, from the winning plan)

If any field is missing or empty, the recording step writes `status: "evidence_incomplete"` instead of a winner record, and the merge is reverted in a follow-up cleanup pass.

### H006 — Scope Fence
Edits must touch only paths under: `tests/**`, `governance/**` (small correctness fixes ≤50 lines per file), `docs/**`, `scripts/**` (excluding sealed `scripts/bench.sh`). Plans whose `target_files` include any other path are rejected by critic unless they declare `scope_override: true` AND the override is preapproved in `config/idea.md`.

### H007 — No Network / Secret / Deploy (executable)
The benchmark wrapper and any plan-introduced code must not:
- Make outbound HTTP/HTTPS/DNS requests
- Read secrets from env or hard-code secret literals
- Invoke deploy commands (`gh pr create`, `git push`, `kubectl`, `vercel`, `wrangler`, `flyctl`, `docker push`)

**Enforcement** — `scripts/check-scope.sh` is invoked by the orchestrator BEFORE tournament acceptance and BEFORE any internal `--no-ff` merge into `improve/eval-mvp-hardening`. It runs `git diff --unified=0 <base>` and grep-rejects added lines matching the network / deploy / secret-name denylists. Non-zero exit → candidate rejected, no merge attempted, no benchmark accepted. The check runs against:
1. Each executor's experiment branch vs `improve/eval-mvp-hardening` (pre-merge)
2. The merged improvement branch vs the prior tip (post-merge but pre-acceptance)

If `scripts/check-scope.sh` cannot run (missing, errors, sealed-file tampering), the orchestrator treats it as `harness_violation` and aborts the iteration's tournament — no winner is recorded.

### H008 — No CRIT/HIGH Regression
PRs #4–#8 in the source repo (`govern-zone/dislovelhl/govern-zone:master`) resolved specific CRIT/HIGH issues:
- O(n²) audit append (CRIT)
- fnmatch path-traversal (HIGH)
- API auth bypass (HIGH)
- Decision state TOCTOU
- Tenant spoof, audit race, no-audit guard, OIDC scope

Each of these has at least one regression test in the imported `tests/`. The critic must verify, for any plan that modifies `governance/audit/**`, `governance/service/api.py`, `governance/models.py`, or `governance/replay.py`, that the corresponding regression tests are referenced in the plan's `verification` section. Plans that touch these paths without referencing the relevant regression tests are rejected.

### H009 — Sealed Files Are Hard-Sealed
`validate.sh` enforces `sealed_files`. If the diff modifies any sealed path, the executor MUST fail with `status: "harness_violation"` before benchmarking. The orchestrator does not consider candidates with `harness_violation`.

### H010 — Benchmark Sanity & Determinism
The benchmark wrapper (`scripts/bench.sh`) must:
1. Emit **exactly one** parseable JSON object on stdout (last line; pytest output is on stderr).
2. The JSON must include `total > 0`. If `total == 0` or output is unparseable, bench.sh exits with code 2 and emits a `harness_error` field — the orchestrator treats this as `infrastructure` failure, NOT a candidate score.
3. **Baseline determinism gate**: before entering the loop, the orchestrator runs `scripts/bench.sh` 3× back-to-back. The three JSON outputs must be byte-identical for `pass_rate`, `passed`, `failed`, `errors`, `skipped`, `total`. If any field varies across the three runs, the loop does NOT start — the orchestrator stops and reports the diverging fields plus the three raw outputs.
4. **Per-iteration sanity**: every executor's reported `pass_rate` must come from a bench.sh run whose JSON has no `harness_error` field. Candidates with `harness_error` are rejected before tournament ranking.

## Custom Approach Families

In addition to the built-in taxonomy in SKILL.md, this project allows:
- `test_repair` — fixing a failing or flaky test without changing production code
- `correctness_fix` — small bug fix in `governance/**` covered by an existing or newly-added test
- `evidence_hardening` — improving determinism / reproducibility of the test suite (deterministic ordering, fixture isolation, time freezing, audit log clearing)
- `regression_proofing` — adding a test that locks in a previously-fixed CRIT/HIGH issue
