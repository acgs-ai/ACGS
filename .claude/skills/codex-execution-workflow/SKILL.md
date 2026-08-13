---
name: codex-execution-workflow
description: Use when routing substantive govern-zone work through Codex (`codex exec` / codex:rescue) — the plan→execute→verify→human-gate loop, config, and what never goes to Codex unsupervised.
---

# Codex Execution Workflow (govern-zone default)

> Default operating loop for substantive work in this workspace: **Claude plans and
> researches, Codex executes, Claude verifies, humans push/merge.** Codex is the
> EXT-C lane from `~/.claude/rules/model-routing.md` — an independent implementation
> engine, never an unsupervised committer.

## The loop

1. **Plan (Claude).** Scope the task, split by subproject boundary, name the exact
   files/gates. Use the scope gate (`scope-detect.py`) for multi-package work.
2. **Research (Claude).** Reproduce the failure or pin the requirement from primary
   source: CI failure logs, the failing gate run locally, the code + tests named in
   `docs/CLAIMS.md`. Hand Codex *evidence*, not a guess.
3. **Execute (Codex).** Give Codex a precise, file-scoped prompt. Two lanes:
   - `codex exec "<prompt>"` — headless, non-interactive. Add `--sandbox read-only`
     for review/diagnosis; `--sandbox workspace-write` only when it must edit.
   - `codex:rescue` agent (`Agent(subagent_type="codex:codex-rescue")`) — sanctioned
     in-harness EXT-C lane; edits land in its sandbox for Claude to re-verify.
   - CI already runs a `codex-review` check on every PR.
4. **Verify (Claude).** Re-run the exact gate locally — a green claim needs literal
   output. Codex output is an artifact to check, never auto-accepted (its sandbox
   reports FastAPI TestClient tests as hanging when they pass — re-run locally).
5. **Human gate.** `git push` and `gh pr merge` are human gates. Agents prepare a
   verified, CI-green branch; a human pushes/merges. Do not retry a blocked
   push/merge — surface it (see `~/.claude/CLAUDE.md` "When Blocked By A Permission").

## Never route to Codex unsupervised

Per `model-routing.md` "Never Downgrade": security review, auth/CSP/fail-closed
governance logic, sealed / constitutional-hash / generated files, release/merge
verdicts, and multi-package architecture stay with Claude (T2). Codex may draft;
Claude verifies these itself. Porting security/adversary tests to a changed API is
security-sensitive — Claude reviews Codex's port, does not merge it blind.

## Config (verified ready)

- `codex-cli` logged in via ChatGPT (`codex login status`).
- `omc ask codex "<prompt>"` → artifact in `.omc/artifacts/ask/`.
- Cap adversarial rework (Codex review → fix → re-review) at 2 cycles, then re-scope.

## Where this fits

Backlog work: run `pr-queue` / `gh pr list` → for each PR, verify its gate locally;
if a real code failure remains, route the fix through this loop; if the branch is
already prepped, report it as human-push/merge-gated. See the memory index for
current PR state.
