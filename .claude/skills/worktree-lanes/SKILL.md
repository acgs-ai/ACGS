---
name: worktree-lanes
description: Use when opening, running, or cleaning up parallel `claude -w` worktree lanes — lane naming, one-lane-per-package rule, nested-repo prohibition, cleanup after merge.
---

# Parallel Worktree Lanes (govern-zone)

> Always-On: Conventions for running parallel work in isolated git worktrees via
> `claude -w <lane-name> --tmux`. Complements `.claude/rules/headless-delegation.md`
> (per-lane invocation contract) and `~/.claude/rules/multi-agent-git-safety.md`
> (per-agent worktree isolation). The point of a lane is isolation: one package,
> one branch, one worktree — so parallel agents never collide on a shared index.

## When to open a lane

Open a lane when two or more pieces of work are genuinely independent and would
otherwise fight over the same working tree / `.git/index`. A single-package,
single-topic change does not need a lane — just work on a feature branch.

## Lane naming

- Branch + lane name: **`feat-<pkg>-<topic>`** (kebab-case), e.g.
  `feat-gove-zone-ttl-prune`, `feat-acgi-ai-console-auth`.
  Use the package's short name for `<pkg>` (`gove-zone`, `acgi-ai`,
  `acgs-lite`, `acgs-swarm`, `clinicalguard`). Keep `<topic>` to 1–3 words.
- One lane == one branch == one worktree. The branch is created off
  `origin/master` (fetch first — see `~/.claude/CLAUDE.md` "Git Workflow /
  Branching") so lanes don't inherit a stale or pre-squash lineage.

## One lane per package — hard rule

- **Never run two lanes editing the same package or nested repo at once.** They
  will collide on that package's files and index. One package per lane; distinct
  branches; the parent merges after each lane verifies (mirrors
  `headless-delegation.md` § Parallelism).
- Split multi-package work by subproject boundary and give each boundary its own
  lane. Do not let a lane reach across into another package's tree.

## Where lanes live

- Worktrees live under **`.claude/worktrees/<lane-name>/`** (git-ignored
  operational state; a linked worktree, not a second clone).
- Create:  `claude -w <lane-name> --tmux`  (opens the lane in its own tmux
  window with an isolated worktree + branch).
- Each lane loads this repo's local instructions itself (`CLAUDE.md`,
  `AGENTS.md`, `.claude/rules/`) — the scope gate applies inside the lane too.

## Nested repos are NEVER worktree'd from the parent

`packages/acgs-lite`, `packages/Acgs-Swarm`, and `packages/clinicalguard` are
independent git repos registered in `.gitmodules` (see
`.claude/rules/repo-boundaries.md`). **Do not create a parent worktree that
tries to branch or edit inside a nested repo** — a parent worktree cannot own a
nested repo's history, and you would stage gitlink pointer drift.

To work inside a nested repo in parallel, `cd` into that package and use the
nested repo's own worktree (`~/.claude/scripts/agent-worktree.sh enter` from
inside the package), or simply work on a branch inside the package. Commit from
inside the nested repo; update the parent pointer only as a separate, explicit
step.

## Cleanup after merge

Once a lane's branch is merged (human-gated push/merge — agents prepare, humans
merge), remove the worktree so it doesn't linger as foreign dirty state:

```bash
git worktree remove .claude/worktrees/<lane-name>
git worktree prune                 # drop stale administrative entries
# delete the merged branch only after confirming it's merged:
git branch -d feat-<pkg>-<topic>
```

Never `git worktree remove --force` a lane with uncommitted work you did not
create — treat unfamiliar dirty state as another agent's (see
`~/.claude/rules/multi-agent-git-safety.md`). Prefer
`~/.claude/scripts/agent-worktree.sh prune`, which only removes clean,
not-ahead worktrees.

## Per-lane invocation contract

For a headless (non-interactive) lane, follow `.claude/rules/headless-delegation.md`:
bounded `--max-turns`, an explicit `--allowedTools` allowlist, Bash restricted to
the exact gate command, and the parent re-runs the gate to verify — a lane's own
pass claim is an artifact to check, never auto-accepted.
