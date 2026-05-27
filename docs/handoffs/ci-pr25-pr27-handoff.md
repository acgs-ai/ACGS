# CI Handoff — PR #25 + PR #27 (constitutional-hash workflow)

**Date:** 2026-05-13  
**Branches:** feat/submodule-token-runbook-v0, docs/submodule-token-runbook-v1  
**PRs:** https://github.com/dislovelhl/govern-zone/pull/25, https://github.com/dislovelhl/govern-zone/pull/27  
**Status:** BLOCKED — requires admin action on repo secret (same as PR #24, see ci-pr24-handoff.md)

---

## Root Cause

Identical to PR #24. See `docs/handoffs/ci-pr24-handoff.md` for full explanation.

Summary: `SUBMODULE_TOKEN` is non-empty but lacks `Contents: Read` on the parent `dislovelhl/govern-zone` repo. Passing it as `token:` to `actions/checkout@v4` overrides `github.token` for the parent-repo fetch, causing git to return 401:

```
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

The `|| github.token` fallback does not trigger because the secret value is non-empty.

Dropping `submodules: recursive` + `token:` fixes the auth failure but causes the drift detector to report 201 REMOVED entries — the lock file at `docs/constitutional-hashes.lock` pins 201 markers from submodule paths (`packages/acgs-lite/`, `packages/clinicalguard/`). Submodule checkout is required for drift detection to pass.

---

## Evidence

| PR | Run ID | Result | Error |
|----|--------|--------|-------|
| #25 | 25772741025 | FAIL | `fatal: could not read Username` (checkout, exit 128) |
| #25 | 25790313810 | FAIL | 201 hash entries REMOVED (after partial fix dropping `token:`) |
| #27 | 25779262109 | FAIL | `fatal: could not read Username` (checkout, exit 128) |
| #27 | (queued at time of revert) | — | reverted before second run completed |

Partial fix commits applied and reverted:
- PR #25: fix `18bd7de` → revert `66620c5` (current tip)
- PR #27: fix `5df4042` → revert `fc72cf3` (current tip)

---

## Required Admin Action

Same as PR #24. Rotate `SUBMODULE_TOKEN` at:  
`https://github.com/dislovelhl/govern-zone/settings/secrets/actions`

The new token must be a **fine-grained PAT** with **`Contents: Read`** on all four repos:

- `dislovelhl/govern-zone` (parent — currently missing this scope)
- `dislovelhl/acgs-lite`
- `dislovelhl/clinicalguard`
- `dislovelhl/Acgs-Swarm`

After rotation, **no branch changes are needed**. Both branches are in their original pre-fix state and will pass on the next CI run trigger.

---

## What Was Tried

1. Diagnosed auth failure from run logs for both PRs — identified SUBMODULE_TOKEN as root cause.
2. Confirmed secret exists (created 2026-05-12T16:56:45Z) via `gh api repos/dislovelhl/govern-zone/actions/secrets`.
3. Coordinated with w1 who confirmed identical root cause on PR #24.
4. Applied fix to drop `submodules: recursive` + `token:` on both branches (commits `18bd7de`, `5df4042`).
5. New CI run on PR #25 (25790313810) confirmed checkout passes but drift detector fails: 201 entries REMOVED.
6. Reverted both partial fixes (commits `66620c5`, `fc72cf3`) — both branches back to original state.

---

## Next Steps

1. **Admin**: Rotate `SUBMODULE_TOKEN` with the four-repo scope above (one rotation unblocks all three PRs).
2. **After rotation**: Re-trigger CI on PRs #25 and #27 via `gh run rerun --failed` or push a no-op commit.
3. **Verify**: `gh pr checks 25 -R dislovelhl/govern-zone` and `gh pr checks 27 -R dislovelhl/govern-zone` should each show 2/2 passing.
