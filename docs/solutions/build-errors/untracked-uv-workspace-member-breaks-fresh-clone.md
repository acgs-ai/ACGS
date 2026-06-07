---
title: Registered uv workspace member untracked in git breaks fresh-clone uv sync
date: 2026-06-07
category: build-errors
module: packages/research-engine
problem_type: build_error
component: tooling
symptoms:
  - "A path listed in `[tool.uv.workspace] members` (and in `uv.lock`) shows as `??` (untracked) in `git status`"
  - "`uv sync` / workspace resolution fails on a fresh clone or CI checkout while passing on the dev machine that authored it"
  - "`git ls-files packages/<member>/pyproject.toml` returns nothing even though the member is referenced by workspace config"
root_cause: incomplete_setup
resolution_type: environment_setup
severity: high
tags: [uv, workspace, monorepo, pyproject, uv-lock, git-hygiene, fresh-clone, tooling]
related_components: [development_workflow, testing_framework]
---

# Registered uv workspace member untracked in git breaks fresh-clone uv sync

## Problem
A uv workspace member (`packages/research-engine/`, the `delve` package) was declared in the root `pyproject.toml` `[tool.uv.workspace] members` list and present in `uv.lock` as an editable source, but the directory was never committed to git. The workspace config and the git tree disagreed: every fresh clone (and every CI checkout) gets a `pyproject.toml` that points at a member path that does not exist in the tree, so `uv sync` / workspace resolution fails for everyone except the machine that authored the package.

## Symptoms
- A path in `[tool.uv.workspace] members` (and `uv.lock`) shows as `??` untracked in `git status`.
- `uv sync` resolves fine locally but breaks on a clean clone or CI checkout.
- `git ls-files packages/<member>/pyproject.toml` returns nothing despite the member being referenced.

## What Didn't Work / Why it hides
The bug is invisible on the machine that created the package, which is exactly why it survives:
- **Local `uv sync` passes** — the member directory physically exists on disk, so uv resolves it. The inconsistency is between *git* and *config*, not on the filesystem.
- **In-repo pytest and type-checkers pass** — they run against the present-on-disk code, never noticing it is untracked.
- **CI may also stay silent** — if no workflow path was wired to run that member, nothing checks out the committed tree and exercises it. The first real victim is whoever next clones the repo.

So none of the usual gates (typecheck, unit tests, local install) fail. Only a checkout of the *committed* tree (fresh clone / CI) reproduces it.

## Solution
Detect by cross-checking git against workspace config, then either commit the member or deregister it.

Detect:
```bash
# every members entry / uv.lock editable source must have a git-tracked pyproject
git status --short | grep '^??' | grep packages/        # untracked package dirs
git ls-files packages/research-engine/pyproject.toml     # empty == not committed
```

Fix (commit the member) — scope the add, scan for secrets, prove it works, commit narrowly:
```bash
git add --dry-run packages/research-engine/              # confirm scope (caches excluded by its .gitignore)
grep -rnE 'sk-ant-|tvly-|AKIA[0-9A-Z]{16}' packages/research-engine && echo SECRETS || echo clean
git add packages/research-engine/                        # ONLY this dir
git diff --cached --name-only | grep -v '^packages/research-engine/'   # must be empty
uv run --package delve python -m pytest packages/research-engine/tests -q   # 64 passed
git commit -m "feat(research-engine): commit registered-but-untracked workspace member"
```

Before vs after:
```
pyproject.toml members:  packages/research-engine   ✓ (present both before and after)
git tree:                packages/research-engine   ✗ before  →  ✓ after
```

If the member genuinely cannot be committed yet, do the opposite: **deregister** it (comment it out of `members`) so the workspace resolves. The repo already has this precedent — `pyproject.toml` comments out `packages/clinicalguard` exactly because the submodule is uninitialized locally and would break `uv run` and the governance hook.

## Why This Works
Root cause is an incomplete repo setup: a registered member path was declared in config but its files were never added to git. uv reads `members` from the committed `pyproject.toml`; on a clean checkout the path is empty, so resolution fails. Committing the files reconciles config with the tree — config promises a member, and now the tree delivers it. (Deregistering reconciles it the other way: the tree no longer needs to deliver what config no longer promises.)

## Prevention
- **Add a manifest-vs-git guard** to CI / `make verify`: every `[tool.uv.workspace] members` entry and every `uv.lock` editable source must resolve to a git-tracked `pyproject.toml`. Sketch:
  ```bash
  # fail if a declared member has no committed pyproject
  python3 - <<'PY'
  import tomllib, subprocess, sys
  members = tomllib.load(open("pyproject.toml","rb"))["tool"]["uv"]["workspace"]["members"]
  tracked = set(subprocess.check_output(["git","ls-files"],text=True).splitlines())
  missing = [m for m in members if f"{m}/pyproject.toml" not in tracked]
  if missing:
      print("untracked workspace members:", missing); sys.exit(1)
  PY
  ```
- **Review habit:** when committing a new package, grep `git status` `??` paths against `pyproject.toml` members + `uv.lock` before declaring done. A path in config but `??` in git is the tell.
- **Distinguish the two failure shapes** in this monorepo: *registered-but-untracked* (silent broken clone, this doc) vs *full orphan* (untracked AND in no manifest/CI — e.g. `packages/ai-governance-research/` before it was committed and wired into `lint-docs`). The first breaks installs silently; the second ships ungated code.
- **Multi-agent git hazard (caused a mis-attributed commit while fixing this):** in a worktree where multiple agents commit to the same branch, never `git add <whole-file>` for a file that was already ` M` (modified) at session start — you sweep another agent's pre-existing drift into your commit. Here `git add Makefile` pulled in pre-existing `research-engine` `PYTHON_PACKAGES`/`test-py`/`lint-py` registration that belonged in a different commit. Use `git add -p`, or revert-then-edit, when the target file is already dirty. Do not rebase to fix the attribution if a concurrent agent's commits are interleaved.

## Related Issues
- `MONOREPO.md` (members table) is **stale** — it lists `packages/research-engine/` as a tracked member and calls `packages/ai-governance-research/` "parent-tracked", both contradicted by `git status` at the time of this fix. Correct it when convenient (`/ce-compound-refresh MONOREPO.md`).
- `pyproject.toml` — the commented-out `packages/clinicalguard` member is the existing exclusion precedent referenced above.
- `CLAUDE.md` "Hard constraints" #2 (nested git repos) — adjacent: untracked-member drift is a distinct failure from submodule-pointer drift.
- `docs/solutions/workflow-issues/correctness-gated-self-improve-loop-mechanics.md` — only loosely related (one workspace-resolution aside about acgs-lite importing a stale site-packages copy).
- No matching GitHub issue (`gh` searched: 0 results).
