---
name: pr-queue
description: Use when checking which ACGS PRs are ready for human merge, sweeping open pull requests for CI status / conflicts / review state, or before asking the user to merge — e.g. "what PRs are waiting", "merge readiness", "PR backlog", "is #NNN green".
---

# PR Queue — merge-readiness sweep

Read-only sweep of open PRs against `master`, plus the verify-pass marker state that gates `gh pr merge`.

## Run

```bash
bash .claude/skills/pr-queue/pr-queue.sh            # dislovelhl/ACGS, base master
bash .claude/skills/pr-queue/pr-queue.sh --repo o/r --base main
```

## Reading the output

- `READY-FOR-HUMAN-MERGE` — CI green, no conflicts, not draft. Surface these to the user; merging is human-gated (or verify-gated via `record-verify-pass.sh` on the exact HEAD).
- `CI-RED` / `CONFLICTS` / `CI-PENDING` / `DRAFT` / `CHANGES-REQ` — blocked; fix cause before escalating.
- `verify-marker` line — whether `gh pr merge` is currently permitted from *this* worktree.

## Constraints

- Never merge, close, comment, or re-run checks from this skill — report only.
- A `MERGED` PR status does not prove content reached master (stacked-PR trap); verify with tree-diff when it matters.
- Queued-forever checks usually mean the self-hosted runner is down — run `~/.claude/scripts/runner-health.sh`.
