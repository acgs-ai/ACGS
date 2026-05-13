# CI Handoff — PR #24 feat/roadmap-duo (constitutional-hash workflow)

**Date:** 2026-05-13  
**Branch:** feat/roadmap-duo  
**PR:** https://github.com/dislovelhl/govern-zone/pull/24  
**Status:** BLOCKED — requires admin action on repo secret

---

## Root Cause

The `constitutional-hash` workflow fails because `SUBMODULE_TOKEN` is **invalid or expired**.

The secret exists in the repo (created 2026-05-12T16:56:45Z) but is not a valid credential. When `actions/checkout@v4` receives a non-empty token value, it uses it for **all** git fetch operations — including the initial parent repo fetch (`dislovelhl/govern-zone`). Because the token lacks access to the parent repo, git returns a 401 and reports:

```
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

The `|| github.token` fallback in the workflow expression **does not trigger** because the secret is non-empty (falsy evaluation requires empty string or null, but an expired token is non-empty).

The lock file at `docs/constitutional-hashes.lock` pins 201 constitutional hash markers from submodule files (`packages/acgs-lite/`, `packages/clinicalguard/`). Submodule checkout is therefore required for the drift detector to pass — so removing `submodules: recursive` from the workflow only swaps one failure for another (drift detection reports 201 REMOVED entries).

---

## Evidence

| Run ID | Result | Error |
|--------|--------|-------|
| 25772694428 | FAIL | `fatal: could not read Username` (checkout step, exit 128) |
| 25790276544 | FAIL | 201 hash entries REMOVED (after partial fix attempt that dropped `token:`) |

The partial fix (`529dde3`, reverted in `c999d8a`) confirmed that removing `token:` allows the parent repo to check out successfully using `github.token`, but then the drift detector fails because submodule files are absent.

---

## Required Admin Action

Rotate `SUBMODULE_TOKEN` at:  
`https://github.com/dislovelhl/govern-zone/settings/secrets/actions`

The new token must be a **fine-grained PAT** with **`Contents: Read`** on all four repos:

- `dislovelhl/govern-zone` (the parent — needed because `token:` overrides `github.token` for the parent fetch too)
- `dislovelhl/acgs-lite`
- `dislovelhl/clinicalguard`
- `dislovelhl/Acgs-Swarm`

After rotation, **no branch changes are needed**. The existing `constitutional-hash.yml` workflow on `feat/roadmap-duo` (and PRs #25, #27) will pass automatically on the next run trigger.

---

## What Was Tried

1. Diagnosed auth failure from run logs — identified SUBMODULE_TOKEN as root cause.
2. Applied a fix to drop `submodules: recursive` + `token:` from `constitutional-hash.yml` (commit `529dde3`).
3. New CI run (25790276544) confirmed checkout now works but drift detector fails: 201 entries REMOVED from lock.
4. Reverted the incomplete fix (commit `c999d8a`) — branch is back to original state.

---

## Coordinating Note

w2 independently diagnosed the same root cause for PRs #25 and #27. The fix is identical: rotate `SUBMODULE_TOKEN` with parent-repo scope. All three PRs (#24, #25, #27) will unblock from a single secret rotation — no branch-level changes required.

---

## Next Steps

1. **Admin**: Rotate `SUBMODULE_TOKEN` with the four-repo scope above.
2. **After rotation**: Re-trigger CI on PR #24 via `gh run rerun --failed` or push a no-op commit.
3. **Verify**: `gh pr checks 24 -R dislovelhl/govern-zone` should show 2/2 passing.
