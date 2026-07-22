# Advanced Claude Code Playbook — ACGS / govern-zone

> **Purpose:** the most effective way to drive Claude Code (v2.1.207) to systemically
> improve this repo, given its existing governance scaffolding. This is a *usage*
> playbook — it builds on the scaffolding already in `.claude/` (agents, commands,
> skills, workflows, hooks, the Codex-execution rule) rather than duplicating it.
>
> Source of truth for raw CLI surface: the Hermes `claude-code` skill. This doc is
> the ACGS-specific *strategy* layer on top of it.

---

## 0. TL;DR decision table — which mode for which job

| Job shape | Mode | Command skeleton |
|---|---|---|
| Bounded, fully-specified change (one gate, one bug, one file-set) | Print + brief file | `claude -p "read <brief> and implement exactly…" --permission-mode acceptEdits --max-turns 60 --output-format json` |
| Read-only research / strategy / triage | Print, read-only tools | `claude -p "<question>" --allowedTools "Read,Glob,Grep" --output-format json --max-turns 15` |
| Security / auth / fail-closed / sealed-file work | **Claude plans + verifies; do NOT auto-accept** | interactive or print with review, per `codex-execution-workflow.md` |
| Multi-turn iterative (build→review→fix→test) | Interactive via tmux | `tmux … claude -w <name>` |
| Fan-out (5–30 independent edits) | `/batch` or parallel tmux + worktrees | see §6 |
| PR review | Print from PR | `claude -p "review" --from-pr <n> --allowedTools "Read,Bash(git *)" --max-turns 10` |
| Long autonomous run you don't babysit | Background agent | `claude --bg "<task>" …` then `claude agents` |

---

## 1. The prompt contract (why the G1.6 run first failed, then worked)

Claude Code performs best when the prompt is a **contract**, not a wish. Every
delegated task in this repo should pin all seven:

1. **Exact deliverable files** — "create `packages/gove-zone/src/gove_zone/_fsprobe.py`
   and `tests/test_fs_probe.py`; wire into `audit.py`". Naming the paths stops the
   agent from exploring for 60 turns and writing nothing (the original failure mode).
2. **The environment escape hatches** — this repo's uv workspace does NOT resolve in a
   fresh worktree (acgs-lite misses `tool.uv.sources`). Tell Claude the exact
   interpreter: "use `packages/gove-zone/.venv-gz/bin/python` for all pytest/ruff; do
   NOT run `uv run` or `make`." Omitting this burns the whole turn budget on env
   thrash.
3. **The hard constraints** — "stdlib only, zero runtime deps"; "fail closed";
   "side-effect-free refusal". State them as MUST/MUST-NOT.
4. **The workflow** — "TDD: write the failing test first, confirm RED, then implement
   to GREEN". Claude honors an explicit RED→GREEN→REFACTOR instruction.
5. **The verification gate** — paste the exact commands that must be green, so Claude
   self-checks before returning.
6. **The commit boundary** — "git add ONLY these 4 files (NOT `.venv-gz`, NOT
   `.superpowers`); commit with message X; do NOT push, do NOT tag." Human-gated
   push/merge is repo policy (`codex-execution-workflow.md` step 5).
7. **The report shape** — "report files changed, test pass counts, exact commands
   run, and any blocker honestly."

**Write the contract to a file** (`.superpowers/<gate>-brief.md`) and point Claude at
it: `claude -p "Read <brief> and implement it exactly…"`. A file brief survives longer
than an inline prompt and is reusable across `--continue` / Codex fallback.

### Reasoning knobs
- `ultrathink` keyword in the prompt → deepest thinking for that turn.
- `--effort` now takes `low | medium | high | xhigh | max` (v2.1.207 added `xhigh`).
  Use `high`/`xhigh` for governance-logic reasoning, `low` for mechanical edits.
- `MAX_THINKING_TOKENS=0` disables thinking for trivial deterministic tasks (faster).

---

## 2. Do the exploration YOURSELF first (orchestrator pattern)

The highest-leverage move: **Hermes does the recon, Claude does the bounded write.**
Before delegating, Hermes should:

- Locate the unmet work (read the seam files, run the failing gate, confirm what's
  already merged to `origin/master` — see `acgs-workspace` skill "establish ground
  truth first").
- Confirm the env runs (build the `.venv-gz`, run one test).
- Write the file brief with all seven contract elements.

Then Claude gets a 20-minute bounded job instead of a 2-hour open exploration. This
directly caused the G1.6 success after two failed open-ended runs.

---

## 3. Verify independently — never trust the self-report

Rule 12 from the skill, sharpened for this repo:

- Re-run the EXACT gate yourself after Claude returns. A green claim needs literal
  output you produced.
- gove-zone gates (via `.venv-gz`): `pytest tests/ -q`, `ruff check src tests`,
  `ruff format --check src tests`, and the G1.3 coverage gate
  `pytest --cov=gove_zone.kernel --cov-branch --cov-fail-under=100 -q`.
- Set `TMPDIR="$HOME/.cache/gz-tmp"` — `/tmp` is a quota-capped tmpfs that throws
  phantom `Errno 122` failures under the suite's temp-file load.
- `git status --short` to catch files Claude created but didn't mention, and to ensure
  the commit excludes `.venv-gz/` and build artifacts.
- Codex's sandbox misreports FastAPI TestClient tests as hanging when they pass —
  re-run locally (`codex-execution-workflow.md`).

---

## 4. Governance guardrails (this repo is security-sensitive)

Per `AGENTS.md` and `codex-execution-workflow.md`, some work MUST stay with Claude
planning + human verification and must NOT be auto-accepted or routed to an
unsupervised agent:

- receipt / policy / audit / signing / executor logic (`packages/gove-zone/src/gove_zone/{receipt,executor,kernel,audit,signing,policy,replay*,tenant,integration}.py`);
- anything that could weaken fail-closed behavior or bypass receipt validation;
- sealed / constitutional-hash / `@generated` files;
- `.claude/hooks/acgs-emit-receipt.py`, `.claude/settings.json`, `.github/workflows/**`.

For these, use the existing `@governance-reviewer` and `@workspace-boundary-reviewer`
subagents as a review pass, and keep `--permission-mode` at `default`/`plan` (not
`acceptEdits`) so edits surface for human review.

**The in-repo receipt hook is real.** When Claude writes a file inside this repo, the
`PreToolUse:Write` hook `acgs-emit-receipt.py` emits a governance receipt into
`.gove-zone/audit.jsonl` and fails closed (exit 2) if it can't import `gove_zone`. In a
fresh worktree you MUST install gove-zone into the pinned `.venv`
(`uv pip install --python .venv/bin/python -e "packages/gove-zone[crypto,schema]"`) or
every Claude write is blocked. Do NOT weaken the hook to work around this — repair the
env.

---

## 5. Use the scaffolding this repo already has

Don't reinvent — invoke:

- **Subagents** (`.claude/agents/`): `@governance-reviewer`, `@workspace-boundary-reviewer`.
  In interactive mode: "Use @governance-reviewer to audit the audit.py change."
- **Slash commands** (`.claude/commands/`): `/feature-development`, `/refactoring`,
  `/add-new-workspace-python-package`.
- **Skills** (`.claude/skills/`): `phase-gate`, `pr-evidence`, `source-driven-development`,
  `maintain-acgs`, `deploy-drift-check`, `pr-queue`, `govern-zone` — auto-invoked by
  natural language matching the task.
- **Pursuit workflows** (`.claude/workflows/*.js`): `final-goal-pursuit.js` holds the
  authoritative G-gate `CRITERIA` array (gate text + verify commands). Read it to pick
  the next unmet, agent-implementable increment. Others: `multi-package-verify.js`,
  `review-branch-adversarial.js`, `claim-verify-pipeline.js`.

---

## 6. Parallel / fan-out systemic improvement

For sweeping, independent improvements (lint-class fixes, docstring passes, test
backfill across packages):

- **`/batch`** (interactive) auto-creates 5–30 worktrees for parallel changes.
- **Manual parallel:** N tmux sessions, each `claude -p` in its own worktree, sized
  `--max-turns` at ~8–12/task. Monitor with `tmux capture-pane`.
- **Background agents:** `claude --bg "<task>"` returns immediately; manage with
  `claude agents`. Good for long autonomous gate work you don't babysit.
- Always keep each parallel unit within ONE subproject boundary (never stage across
  submodule gitlinks — `AGENTS.md` git discipline).

---

## 7. Cost / turn budgeting

- `--max-turns`: ~8–12 per bounded task; a 4-task batch needs 40–50, not 30. Watch for
  `"subtype":"error_max_turns"` in JSON output.
- `--max-budget-usd`: hard spend cap (min ~$0.05 for prompt-cache creation).
- `--output-format json` → parse `total_cost_usd`, `num_turns`, `session_id`,
  `subtype` for spend tracking and resumption.
- `--fallback-model` for overload resilience in print mode.
- `--continue` / `--resume <id>` / `--fork-session` for stateful multi-step work —
  remember each fresh `claude -p` is otherwise stateless and will misread prior-run
  files as "pre-existing untracked."

---

## 8. When a delegation returns exit 0 but nothing changed

Checklist (all three bit us on the G1.6 run):

1. **rtk auto-rewrite hook** — historically a `PreToolUse:Bash` hook `rtk hook claude`
   in `~/.claude/settings.json` rewrote every command and trapped Claude in loops.
   FIXED 2026-07-12 (removed). If reintroduced by `rtk init -g`, remove it or set
   `RTK_DISABLED=1`.
2. **Broken receipt hook** — `acgs-emit-receipt.py` fails closed if `gove_zone` isn't in
   the pinned `.venv`; every in-repo Write dies exit 2. Fix: install gove-zone into
   `.venv` (§4).
3. **Sandbox / out-of-repo path** — writing to `/tmp` is governance-ungated but a
   sandbox may block it; in-repo paths are the gated, correct target.

Diagnose with `git status` + re-run a trivial write smoke test
(`claude -p "create ./.superpowers/proof.txt containing X, then cat it"`).

---

## 9. Canonical command snippets

```bash
# Bounded gate implementation (the G1.6 pattern)
cd <worktree>
claude -p "Read .superpowers/<gate>-brief.md and implement it exactly. TDD: failing \
test first, then implement to green. Use packages/gove-zone/.venv-gz/bin/python for \
pytest/ruff — do NOT run uv run or make. Commit ONLY the deliverable files; do NOT \
push. Report files changed, pass counts, commands run, and any blocker." \
  --permission-mode acceptEdits --max-turns 60 --output-format json

# Read-only strategy / next-increment triage
claude -p "You are a govern-zone tech lead. Read final-goal-pursuit.js CRITERIA and \
the repo. Identify the next UNMET, agent-implementable G-gate (skip human-gated ones). \
Return JSON: gate_id, why_unmet, seam_files, tdd_plan, verify_commands, risk." \
  --allowedTools "Read,Glob,Grep" --output-format json --max-turns 20

# Governance-sensitive change (plan mode, reviewer subagent, human-gated)
claude -p "Plan (do not edit) a fail-closed fix for <X> in gove_zone. Then use \
@governance-reviewer to critique the plan. Output the plan + review, no code." \
  --permission-mode plan --allowedTools "Read,Grep,Glob" --max-turns 15

# PR review
claude -p "Review this PR for bugs, fail-closed regressions, missing negative-path \
tests, and scope creep across submodule boundaries." --from-pr <n> \
  --allowedTools "Read,Bash(git *)" --max-turns 10
```

---

## 10. Maintenance

When any of these change, update this doc AND the `acgs-workspace` skill:
- Claude Code CLI surface (new flags/effort levels) — re-check `claude --help`.
- The `.venv-gz` / receipt-hook env dance (ideally: fix acgs-lite `tool.uv.sources`
  upstream so `uv sync` just works, then retire the workaround).
- The G-gate `CRITERIA` in `final-goal-pursuit.js`.
