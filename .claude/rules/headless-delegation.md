# Headless Delegation Contract (Claude lane)

> Default operating loop for delegating to a non-interactive Claude process: **parent plans
> and scopes, headless Claude executes under bounded turns/tools, parent re-runs the exact
> gate, humans push/merge.** This is the Claude-native sibling of
> `codex-execution-workflow.md` — same discipline, Claude engine instead of Codex.

## The loop

1. **Plan (parent).** Scope the task, split by subproject boundary, name the exact files and
   gate. Use the scope gate (`scope-detect.py`) for multi-package work.
2. **Delegate (headless Claude).** Precise, file-scoped prompt with an explicit tool allowlist
   and turn cap. Never hand it an open-ended "figure it out."
3. **Verify (parent).** Re-run the exact gate locally; a green claim needs literal output.
   Headless output is an artifact to check, never auto-accepted.
4. **Human gate.** `git push` and `gh pr merge` stay human-gated. Agents prepare a
   verified, CI-green branch; a human pushes/merges.

## Standard invocation

```bash
claude -p "<task>" \
  --output-format json \
  --max-turns <N> \
  --allowedTools <comma,separated,list> \
  [--max-budget-usd <cap>] \
  [--fallback-model haiku]
```

- **Always set `--max-turns`.** No unbounded lane.
- `--max-budget-usd` bounds spend; use it for anything non-trivial.
- `--fallback-model haiku` degrades gracefully on overload instead of failing the lane.
- `--output-format json` so the parent can assert on `subtype` (see Verification).

## Task classes

| Class | `--allowedTools` | `--max-turns` | Notes |
|---|---|---|---|
| Read-only review | `Read,Grep,Glob` | `10` | No Bash, no Edit/Write. Structural review only. |
| Scoped edit | `Read,Grep,Glob,Edit,Write,Bash(<gate cmd>)` | ~`2×files + 5` | Allow only the exact gate command in Bash; name the files in the prompt. |
| Research / strategy | `Read,Grep,Glob` + `--json-schema <file>` | `10` | Read-only; structured output via schema for machine-checkable results. |
| Adversarial review | `Read,Grep,Glob,Bash(<probe cmds>)` | `20–50` | Second-stage gate for edge-high work; see below. |

For a scoped edit, restrict Bash to the specific gate (e.g. `Bash(uv run --package gove-zone python -m pytest*)`),
never a blanket `Bash`.

## Brief-authoring standard (what every headless prompt must contain)

1. **Ground truth first.** Name the exact source files the task must read before acting;
   "the code wins over the spec" with deviations reported.
2. **Scope fence.** Exact files/dirs it may create or touch; everything else forbidden;
   no commit/push; nested repos untouched.
3. **Mandatory verification section.** Numbered commands with "show literal output",
   always ending with the loop invariant gate (`bash scripts/claim_verify_headless.sh`
   → `all_passed: true`) plus `git status --short` scope check.
4. **Claim-safe wording clause** for anything user-facing (see `claim-safety.md`).
5. **Explicit orchestration opt-in when wanted.** Workflow/multi-agent fan-out requires
   opt-in "in the user's words" — in headless mode the brief IS the user's words, so say
   e.g. "use a workflow to fan out reviewers" explicitly, or it stays single-agent.
   Prefer `Explore` subagents for broad read-only sweeps (keeps main context small) and
   `isolation: "worktree"` when parallel subagents mutate files.
6. **Schema-forced findings for reviews.** Ask reviewers to return a machine-parseable
   findings array (severity/file:line/description/proof/minimal-fix) so the parent can
   assert on it, not parse prose.
7. **State the pre-existing dirty baseline explicitly for adversarial/scope-fence probes.**
   A repo with an in-flight multi-cycle working tree (this repo, routinely) will show
   unrelated `M`/`??` entries in `git status`/`git diff --stat` that predate the task under
   review. A reviewer running a blanket `git diff --stat -- <scope>` without a baseline will
   false-positive on ambient dirt as if it were its own scope violation (observed: cycle 7
   adversarial review flagged pre-existing `src/gove_zone/**` and `docs/CLAIMS.md` edits from
   an unrelated earlier task as findings). Give the reviewer either (a) a base commit/stash
   to diff against, or (b) the explicit list of files this specific build was allowed to
   touch plus an instruction to check content/attribution (mtime, diff hunks matching the
   task) before treating any extra dirty file as a finding.

## Adversarial review stage (edge-high gate)

Any non-trivial build cycle gets a **second headless run** — fresh context, independent
session, read-only + probe Bash — briefed to BREAK the work, not summarize it:

- **Bypass probes:** attempt ≥3 hand-crafted gate-bypass/fail-open attacks with literal
  probe output (arg/actor/tenant substitution, tamper, error-path fall-through).
- **Mutation analysis:** neuter the enforcement point and re-run the negative tests; if
  no test fails, the tests are exception-theater → finding. Restore state after.
- **Verdict contract:** PASS / PASS-WITH-FINDINGS / FAIL + findings table with proof.
- LOW findings still get a scoped fix run — at edge-high, doc precision is part of the bar.
- Builder and reviewer must be **separate sessions** (never let the builder review itself).

## Verification (parent re-runs, does not trust)

- Parent (Hermes / Martin) re-runs the **exact** gate the task targeted — never accepts the
  headless run's own pass claim.
- The JSON result's `subtype` must be `success`. Any other value is a fail.
- `error_max_turns` means the task was **under-scoped** → re-scope and re-delegate, do not
  blindly retry with the same prompt and a higher cap.
- Security-sensitive changes (receipt/executor/kernel/audit/policy/signing) are re-reviewed
  by the parent (T2), not merged on a headless pass — see `security-sensitive-files.md`.
- **Self-report / final-artifact divergence.** An agent's embedded verification output (test
  counts, `all_passed: true`, JSON contract fields) can be stale relative to what's actually
  on disk — e.g. captured from a mid-edit pass before a later edit pass, or from a
  provider-side reconnect that re-emitted an earlier turn's result. Observed once on a Codex
  build (cycle 7 / adaptive-eval-adversary-suite): the agent's final JSON claimed
  `"adversary_suite": "30 passed"` and `claim_verify_all_passed: true`, but re-running the
  identical command against the actual files on disk produced a collection-time crash (a
  dynamic-module-loader bug) and, once fixed, a real manifest/observed-reality mismatch the
  agent's own harness should have caught. **Rule: always re-run the target test command
  yourself against the files on disk, from a clean bytecode cache
  (`find . -name __pycache__ -path '*<scope>*' -exec rm -rf {} +`), before accepting any
  embedded pass/fail claim — a headless agent's self-reported verification is not evidence,
  only its own re-executed gate output is.**

## Streaming-abort failure mode + parent-fallback protocol

The Copilot-hosted lane intermittently dies mid-stream: `subtype` = `aborted_streaming`
(or `error_during_execution`), empty/near-empty stdout (`bytes=0`), `$0` cost. Two shapes:

- **Post-write abort:** the run wrote its files, then the stream died before emitting the
  result JSON. Files are complete and on disk — verify them and proceed; do NOT re-run.
- **Pre-work abort:** the run dies after reading the brief with **zero** Edit/Write/Bash
  calls. Nothing landed; the stage produced no work.

**Distinguish before retrying — never trust `bytes=0` alone.** Inspect the transcript
`~/.claude/projects/<slug>/<newest>.jsonl`: count `tool_use` blocks of type Edit/Write/Bash.
Zero mutating calls ⇒ pre-work abort; ≥1 ⇒ post-write, check disk.

**Retry budget: 2 headless attempts per stage.** Adding "Begin <editing|the probes>
immediately; do not stop after reading" to the prompt slightly reduces pre-work aborts but
does not eliminate them.

**Parent-fallback (after 2 aborts):** the parent executes the stage directly rather than
burning more dispatches. This preserves the loop's independence guarantee **as long as the
parent was not the builder** — parent-as-reviewer and parent-as-fixer keep builder ≠
reviewer ≠ fixer separation intact (headless Claude built it; the parent reviews/fixes a
different stage). What the parent must NOT do is build AND self-review the same artifact.
When falling back, the parent still runs the full brief (all mandated probes / the exact
fix spec) and the complete verification ladder — the fallback changes the executor, not the
rigor.

## Parallelism

- Isolate parallel lanes with worktrees: `claude -w <name> --tmux`.
- **Never run two lanes editing the same package** — they will collide on the index / files.
  One package per lane; distinct branches; parent merges after each verifies.
- Cap adversarial rework (delegate → fix → re-review) at 2 cycles, then re-scope.
