# Runbook v1: SUBMODULE_TOKEN — Failure Mode Taxonomy & Recovery

> **Scope:** Expand v0 with concrete failure-mode diagnosis, fallback trap mechanics, scope checklist, and reproduction recipe.
>
> **Last updated:** 2026-05-13

---

## Relationship to v0

This document supplements v0, not replaces it. v0 covers:
- **Purpose** — why SUBMODULE_TOKEN exists (cross-repo auth for private submodules)
- **Current form** — fine-grained PAT storage location
- **Workflows** — which CI jobs use the pattern
- **Verification procedure** — how to list and inspect runs

v1 adds:
- **Failure-mode taxonomy** (§1) — map observable symptoms to root causes
- **Fallback trap analysis** (§2) — why `|| github.token` fails with invalid tokens
- **Scope checklist** (§3) — exact enumeration of repos requiring `contents: read`
- **Reproduction recipe** (§4) — gh CLI commands to diagnose failures
- **Patch options** (§5) — safer fallback patterns for the workflow

Read v0 first; use v1 for diagnosis and recovery depth.

---

## 1. Failure-Mode Taxonomy

When CI fails during `actions/checkout@v4`, the observable symptom maps to exactly one root cause and one minimal recovery action.

| Observable Error | Step | Root Cause | Recovery Action |
|---|---|---|---|
| `fatal: could not read Username for 'https://github.com': terminal prompts disabled` | Parent repo initial fetch | SUBMODULE_TOKEN invalid, expired, or non-empty string that fails auth | Verify token value and expiry under GitHub Settings → Developer settings → Personal access tokens. Re-create if expired. |
| `fatal: repository 'https://github.com/dislovelhl/clinicalguard.git/' not found` | Submodule clone (clinicalguard) | SUBMODULE_TOKEN absent OR lacks `contents: read` on dislovelhl/clinicalguard | Add dislovelhl/clinicalguard to PAT's repository allow-list under GitHub Settings. Verify fine-grained PAT scope. |
| `fatal: repository 'https://github.com/dislovelhl/acgs-lite.git/' not found` | Submodule clone (acgs-lite) | acgs-lite is now private; SUBMODULE_TOKEN lacks `contents: read` on it | Add dislovelhl/acgs-lite to PAT's repository allow-list. (Not needed as of 2026-05-13; acgs-lite is public.) |
| `fatal: repository 'https://github.com/dislovelhl/Acgs-Swarm.git/' not found` | Submodule clone (Acgs-Swarm) | Acgs-Swarm is now private; SUBMODULE_TOKEN lacks `contents: read` on it | Add dislovelhl/Acgs-Swarm to PAT's repository allow-list. (Not needed as of 2026-05-13; Acgs-Swarm is public.) |
| Checkout succeeds, but `git submodule update` fails or hangs | Submodule init | Submodule pointer (in `.gitmodules` or git config) references a commit that no longer exists | Update `.gitmodules` to point to an existing commit in the submodule repo. |
| Checkout succeeds, lint/test runs but produces "module not found" for submodule content | Runtime | Submodule directory exists but is empty (sparse checkout or partial init) | Run `git submodule foreach 'git status'` to inspect checkout state. Re-run `git submodule update --recursive --init` if any are detached or empty. |

### Critical Finding (2026-05-13)

PR #24, #25, #26 all fail at the **first step** (parent repo initial fetch), not the submodule clone:

```
[command]/usr/bin/git -c protocol.version=2 fetch --no-tags --prune --no-recurse-submodules --depth=1 origin +<sha>:refs/remotes/pull/N/merge
##[error]fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

This is **not** a submodule problem — it is a parent-repo authentication failure. The token in `secrets.SUBMODULE_TOKEN` either:
1. Is expired
2. Is a non-empty string that failed GitHub's authentication check
3. Was revoked or invalidated

The `|| github.token` fallback in the workflow **does not trigger** because `secrets.SUBMODULE_TOKEN` is a non-empty string. GitHub does not treat invalid/expired tokens as "falsy" — they are treated as present-but-unusable, so the fallback never executes.

---

## 2. The `|| github.token` Fallback Trap

### How it works (intended behavior)

The workflow uses:

```yaml
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```

In GitHub Actions expressions, `||` is a logical-OR operator. If the left side is **falsy** (empty string, null, false, 0), the right side is evaluated and used instead.

**Expected:** If `SUBMODULE_TOKEN` secret is unset, `${{ secrets.SUBMODULE_TOKEN }}` evaluates to empty string (falsy), so `github.token` is used.

### How it breaks (observed failure)

If `SUBMODULE_TOKEN` is set to **any non-empty string** — including an expired token, revoked token, or malformed string — the expression evaluates the left side as **truthy** and uses it:

```yaml
# If SUBMODULE_TOKEN = "ghp_ExpiredOr InvalidStringHere"
token: ${{ "ghp_ExpiredOr InvalidStringHere" || github.token }}
# Result: "ghp_ExpiredOr InvalidStringHere" (non-empty, truthy)
# The fallback never executes.
```

GitHub's auth layer then receives the invalid token and returns:

```
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

The fallback only executes if the secret is **explicitly unset** (does not exist in the secret store) or is an empty string.

### Safe alternative patterns

**Option 1: Explicit null check in YAML**

```yaml
token: ${{ secrets.SUBMODULE_TOKEN != '' && secrets.SUBMODULE_TOKEN != null && secrets.SUBMODULE_TOKEN || github.token }}
```

This is verbose but explicit: check that the token is neither empty nor null before using it. If it is either, the entire left expression short-circuits to false, and `github.token` is used.

**Option 2: GitHub Actions environment variable + conditional**

```yaml
- uses: actions/checkout@v4
  with:
    submodules: recursive
    token: ${{ env.SUBMODULE_TOKEN || github.token }}
  env:
    SUBMODULE_TOKEN: ${{ secrets.SUBMODULE_TOKEN }}
```

Using an environment variable does not change the semantics but makes the flow more explicit. The token is still stored as-is; the fallback still only triggers if it is falsy.

**Option 3 (Recommended): Use a GitHub App instead of a PAT**

Fine-grained PATs are time-limited and require manual rotation. GitHub Apps use short-lived tokens and can be installed at the org level with minimal ceremony. The workflow would then use:

```yaml
token: ${{ steps.app-token.outputs.token }}
```

where `steps.app-token` is the result of `actions/create-github-app-token@v1`. This eliminates the fallback entirely because the app token is always generated fresh. (Deferred to future rotation cycle; see v0 §Rotation Procedure.)

### Why Option 1 is necessary (not sufficient)

Option 1 is a **temporary band-aid**. It prevents an expired token from poisoning the fallback, but it does not prevent the token from expiring in the first place. The real solution is automated rotation (GitHub App) or a manual rotation schedule with clear expiry logging.

---

## 3. Fine-Grained PAT Scope Checklist

`SUBMODULE_TOKEN` must be a fine-grained Personal Access Token (or GitHub App) with `contents: read` on **every repository that is a private submodule**. As of 2026-05-13, that is exactly one repo. However, the token is created with a scope list, and future privatization of acgs-lite or Acgs-Swarm will require scope updates.

### Current submodules and privacy status

| Submodule Path | Repository | Privacy | Requires `contents: read` in token? |
|---|---|---|---|
| `packages/acgs-lite` | dislovelhl/acgs-lite | **Public** | No |
| `packages/Acgs-Swarm` | dislovelhl/Acgs-Swarm | **Public** | No |
| `packages/clinicalguard` | dislovelhl/clinicalguard | **Private** | **YES** |
| (parent repo) | dislovelhl/govern-zone | **Public** | No (fallback covers parent) |

### Required scope configuration

When creating or updating `SUBMODULE_TOKEN`:

1. **Create a fine-grained PAT** under GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens.
2. **Grant `contents: read`** (minimum permission).
3. **Add to repository allow-list:**
   - dislovelhl/clinicalguard (private — mandatory)
   - dislovelhl/acgs-lite (public — optional but recommended for defense-in-depth)
   - dislovelhl/Acgs-Swarm (public — optional but recommended)
   - dislovelhl/govern-zone (the parent repo itself — required because `|| github.token` only provides fallback for public clones; the parent is public but explicit scoping ensures no auth failures)
4. **Set expiry:** 30–90 days. Record the expiry date in a team calendar or runbook follow-up.
5. **Store in GitHub Actions secret:** `Settings → Secrets and variables → Actions → SUBMODULE_TOKEN`.

### Asymmetry note

dislovelhl/clinicalguard is the only **private** repo in the tree. The fine-grained PAT must explicitly list it. If it is missing from the allow-list, the clone fails with `repository not found` (404).

Public repos (acgs-lite, Acgs-Swarm, govern-zone parent) can be cloned with `github.token` alone, but explicit listing in the PAT's allow-list prevents a fallback dependency on the parent workflow's default token, which may have tighter scope.

---

## 4. Reproduction Recipe

When CI fails during checkout, diagnose the root cause using these `gh` CLI commands. Run from the repository root.

### List recent workflow runs and find a failed run ID

```bash
gh run list --workflow=constitutional-hash.yml --limit=5 \
  --json conclusion,databaseId,status,headBranch,createdAt \
  --jq '.[] | select(.conclusion != "success") | .databaseId'
```

This returns the database IDs of recent failed runs. Pick the most recent one:

```bash
FAILED_RUN_ID=<databaseId>
```

### Inspect the checkout step log for the parent repo fetch

```bash
gh run view "$FAILED_RUN_ID" --log-failed
```

This prints the full log of the first failed step. Look for one of these patterns:

- `fatal: could not read Username` — parent repo auth failure (token invalid/expired)
- `fatal: repository '...clinicalguard.git/' not found` — submodule clone failure (token lacks scope)
- `fatal: repository '...acgs-lite.git/' not found` — acgs-lite is private and token lacks scope

### Narrow to just the checkout step

```bash
gh run view "$FAILED_RUN_ID" --log-failed 2>&1 | grep -A 20 "actions/checkout@v4"
```

### If the error is "could not read Username"

The token is invalid or expired. Verify the token under GitHub Settings:

```bash
# This command requires GitHub CLI authentication and won't work from here,
# but the manual steps are:
# 1. Go to https://github.com/settings/tokens?type=fine_grained
# 2. Find the token listed as SUBMODULE_TOKEN in dislovelhl/govern-zone
# 3. Check "Expiration" field
# 4. If expired, regenerate a new token and update the Actions secret
```

Programmatically (requires `gh auth` setup with org-admin scopes):

```bash
# List all fine-grained tokens (requires gh extension or manual GitHub UI)
# This is not directly available via gh CLI in standard v2.x;
# use the GitHub UI at https://github.com/settings/tokens
```

### If the error is "repository not found"

The token lacks `contents: read` on the named repo. Verify the token's repository allow-list:

```bash
# Again, this requires manual inspection in the GitHub UI:
# 1. Go to https://github.com/settings/tokens?type=fine_grained
# 2. Click the SUBMODULE_TOKEN entry
# 3. Scroll to "Repository access" and confirm it includes:
#    - dislovelhl/clinicalguard
#    - (optionally) dislovelhl/acgs-lite, dislovelhl/Acgs-Swarm
```

### Trigger a manual workflow dispatch to test the fix

After updating the token, re-run the workflow:

```bash
gh workflow run constitutional-hash.yml --ref=master
```

Then monitor:

```bash
# Poll the status
gh run list --workflow=constitutional-hash.yml --limit=1 \
  --json conclusion,status,databaseId --jq '.[0]'
```

When conclusion is `success`, the token is working.

### Log the successful run ID and timestamp

```bash
SUCCESS_RUN_ID=$(gh run list --workflow=constitutional-hash.yml --limit=1 \
  --json databaseId --jq '.[0].databaseId')
echo "SUBMODULE_TOKEN verified working. Run ID: $SUCCESS_RUN_ID"
gh run view "$SUCCESS_RUN_ID" --log 2>&1 | head -50 | grep -E "conclusion|created"
```

Save this as evidence in a follow-up commit or team log.

---

## 5. Patch Options for the Workflow

The current fallback pattern:

```yaml
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```

has a known failure mode: an invalid non-empty `SUBMODULE_TOKEN` will not trigger the fallback and will fail the checkout step.

### Recommended immediate fix

Use Option 1 (explicit null check) to make the fallback more robust:

```yaml
token: ${{ secrets.SUBMODULE_TOKEN != '' && secrets.SUBMODULE_TOKEN != null && secrets.SUBMODULE_TOKEN || github.token }}
```

This ensures that if `SUBMODULE_TOKEN` is invalid, expired, or empty, the fallback to `github.token` executes.

**Trade-off:** Still requires manual rotation every 30–90 days. Better than Option 0 (current), but not production-grade.

### Recommended long-term fix

Replace the PAT with a GitHub App and use `actions/create-github-app-token@v1` to generate a short-lived token at workflow runtime.

```yaml
- id: app-token
  uses: actions/create-github-app-token@v1
  with:
    app-id: ${{ secrets.SUBMODULE_GITHUB_APP_ID }}
    private-key: ${{ secrets.SUBMODULE_GITHUB_APP_PRIVATE_KEY }}
    owner: dislovelhl

- uses: actions/checkout@v4
  with:
    submodules: recursive
    token: ${{ steps.app-token.outputs.token }}
```

**Trade-off:** Requires org-admin to install the GitHub App. Zero manual rotation. Production-grade. **Deferred to Phase B/4 rotation cycle; see v0 §Rotation Procedure.**

---

## Summary Checklist

When SUBMODULE_TOKEN fails:

1. **Identify the error type** using §4 (reproduction recipe).
2. **If "could not read Username"**: token is invalid/expired. Check expiry and regenerate.
3. **If "repository not found"**: token lacks `contents: read` on the named repo. Update allow-list.
4. **Verify the fix** by running `gh workflow run constitutional-hash.yml --ref=master` and monitoring the result.
5. **Log the successful run ID** as evidence in a follow-up commit.
6. **(Deferred)** Plan PAT→GitHub App rotation in next maintenance cycle.
