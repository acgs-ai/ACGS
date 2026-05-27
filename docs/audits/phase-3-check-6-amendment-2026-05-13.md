# Phase 3 Audit — Check 6 Amendment (Workflow Permissions Re-Inspection)

**Date:** 2026-05-13
**Author:** Check 6 amendment agent (post PR #28 re-run)
**Trigger:** Re-run of PR #28 (commit 203bccae) discovered the 4 SUBMODULE_TOKEN-consumer workflows exist at workspace-root `.github/workflows/`, not at `ACGS/.github/workflows/` as the initial audit checked. Permissions on these workflows had not been inspected. This amendment closes that deferral.

## Workflows inspected

| Workflow | Path | Verdict |
|---|---|---|
| constitutional-hash.yml | .github/workflows/constitutional-hash.yml | FAIL |
| python-acgs-lite.yml | .github/workflows/python-acgs-lite.yml | FAIL |
| python-acgs-swarm.yml | .github/workflows/python-acgs-swarm.yml | FAIL |
| python-clinicalguard.yml | .github/workflows/python-clinicalguard.yml | FAIL |

---

## Per-Workflow Detail

### 1. constitutional-hash.yml

**1. Top-level `permissions:` block:**
```yaml
permissions:
  contents: read
```

**2. Per-job `permissions:` blocks:** None. Single job `verify` inherits top-level.

**3. `id-token: write`:** Not present anywhere.

**4. `contents:` value:** `read` (top-level).

**5. `pull-requests:` value:** Not set (unset = default, which GitHub resolves to `read` on non-fork PRs, `none` on fork PRs).

**6. `secrets.SUBMODULE_TOKEN` usage:** 1 reference. Used in `actions/checkout@v4` `token:` field.

**7. `actions/checkout` invocations:**
- Version: `actions/checkout@v4`
- Token: `${{ secrets.SUBMODULE_TOKEN || github.token }}`
- Submodules: `recursive`

**8. Truthy-fallback pattern:** **RED — PRESENT.**
```yaml
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```
Per `github_actions_token_fallback_trap`: the `||` fallback fires on **missing** secret only, never on a broken/invalid/expired secret. If `SUBMODULE_TOKEN` is set but invalid (e.g. rotated, revoked, wrong scope), the expression evaluates to the non-empty broken value and `github.token` is never used. The checkout step will silently fail to clone private submodules with a 401/403, not fall back gracefully.

---

### 2. python-acgs-lite.yml

**1. Top-level `permissions:` block:**
```yaml
permissions:
  contents: read
```

**2. Per-job `permissions:` blocks:** None. Single job `test` inherits top-level.

**3. `id-token: write`:** Not present anywhere.

**4. `contents:` value:** `read` (top-level).

**5. `pull-requests:` value:** Not set (unset).

**6. `secrets.SUBMODULE_TOKEN` usage:** 1 reference. Used in `actions/checkout@v4` `token:` field.

**7. `actions/checkout` invocations:**
- Version: `actions/checkout@v4`
- Token: `${{ secrets.SUBMODULE_TOKEN || github.token }}`
- Submodules: `recursive`

**8. Truthy-fallback pattern:** **RED — PRESENT.**
```yaml
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```
Same vulnerability as constitutional-hash.yml. Comment in workflow says "falls back to github.token so public-only forks still work" — this comment is incorrect about the failure mode. The fallback only fires when the secret is entirely absent, not when it is invalid.

---

### 3. python-acgs-swarm.yml

**1. Top-level `permissions:` block:**
```yaml
permissions:
  contents: read
```

**2. Per-job `permissions:` blocks:** None. Single job `test` inherits top-level.

**3. `id-token: write`:** Not present anywhere.

**4. `contents:` value:** `read` (top-level).

**5. `pull-requests:` value:** Not set (unset).

**6. `secrets.SUBMODULE_TOKEN` usage:** 1 reference. Used in `actions/checkout@v4` `token:` field.

**7. `actions/checkout` invocations:**
- Version: `actions/checkout@v4`
- Token: `${{ secrets.SUBMODULE_TOKEN || github.token }}`
- Submodules: `recursive`

**8. Truthy-fallback pattern:** **RED — PRESENT.**
```yaml
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```
Same vulnerability pattern. Cross-references constitutional-hash.yml comment via "See SUBMODULE_TOKEN note in constitutional-hash.yml" — meaning the misleading fallback rationale propagated to all 3 consumer workflows.

---

### 4. python-clinicalguard.yml

**1. Top-level `permissions:` block:**
```yaml
permissions:
  contents: read
```

**2. Per-job `permissions:` blocks:** None. Single job `test` inherits top-level.

**3. `id-token: write`:** Not present anywhere.

**4. `contents:` value:** `read` (top-level).

**5. `pull-requests:` value:** Not set (unset).

**6. `secrets.SUBMODULE_TOKEN` usage:** 1 reference. Used in `actions/checkout@v4` `token:` field.

**7. `actions/checkout` invocations:**
- Version: `actions/checkout@v4`
- Token: `${{ secrets.SUBMODULE_TOKEN || github.token }}`
- Submodules: `recursive`

**8. Truthy-fallback pattern:** **RED — PRESENT.**
```yaml
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```
Comment notes "clinicalguard is the actual private repo that motivates this token" — confirming that a broken SUBMODULE_TOKEN would silently fail to clone this repo rather than falling back to `github.token`.

---

## Findings

**All 4 workflows fail on the truthy-fallback check (criterion #8).**

**Consistent pattern across all 4 workflows:**
- `permissions: contents: read` at top-level — correct, least-privilege.
- No `id-token: write` anywhere — correct, no OIDC issuance.
- No `pull-requests: write` — correct.
- No per-job permission overrides — jobs inherit the lean top-level block.
- All use `actions/checkout@v4` with `submodules: recursive` — appropriate.
- All use `token: ${{ secrets.SUBMODULE_TOKEN || github.token }}` — **uniformly vulnerable**.

**The RED flag: truthy-fallback trap.** The `||` operator in GitHub Actions expression syntax evaluates to the right-hand value only when the left-hand value is falsy (empty string, null, false). A secret that is set but invalid (expired PAT, revoked token, wrong repository scope) is a non-empty string — it evaluates as truthy. The `|| github.token` branch is **never reached** when `SUBMODULE_TOKEN` is configured but broken. The checkout step will receive the invalid token and fail with a 401/403 on private submodule clones. This is a silent failure mode: CI appears to be using a fallback safety net that does not activate under the most common real-world breakage scenario (token rotation/expiry).

**Drift between workflows:** None detected. All 4 workflows are consistent in both their least-privilege permission configuration and their uniform use of the truthy-fallback pattern. The misleading comment explaining the fallback ("so public-only forks still work") was written in constitutional-hash.yml and referenced by the other three via "See SUBMODULE_TOKEN note in constitutional-hash.yml", meaning the incorrect rationale propagated uniformly.

**Positive findings:**
- No workflow grants `contents: write`, `actions: write`, `packages: write`, or any other elevated permission.
- No workflow enables OIDC token issuance (`id-token: write`).
- All workflows use pinned action versions (`@v4`, `@v5`, `@v3`).
- Concurrency groups with `cancel-in-progress: true` are correctly configured on all 4.

---

## Recommendation

**Check 6 verdict should be revised from PARTIAL to FAIL.**

The truthy-fallback pattern is present in all 4 workflows. Per the `github_actions_token_fallback_trap` memory note, this is the canonical failure mode where an invalid-but-set PAT silently kills the intended fallback. The comments in the workflows explicitly describe a fallback guarantee that the implementation does not provide.

**Required remediation (not implemented in this amendment — read-only inspection):**

Replace the truthy-fallback pattern in all 4 workflows with an explicit conditional:

```yaml
# Option A: remove the fallback entirely (private submodules require the token; fail loudly if missing)
token: ${{ secrets.SUBMODULE_TOKEN }}

# Option B: explicit fork detection (if public-fork support is genuinely needed)
token: ${{ github.event.pull_request.head.repo.full_name == github.repository && secrets.SUBMODULE_TOKEN || github.token }}
```

Option A is recommended: if `SUBMODULE_TOKEN` is absent or invalid, the checkout step should fail loudly on the first step rather than silently producing a broken build that may pass lint/test on cached or partial state.

Additionally, update or remove the misleading comment in constitutional-hash.yml that describes the `||` fallback as reliable for public-only forks.
