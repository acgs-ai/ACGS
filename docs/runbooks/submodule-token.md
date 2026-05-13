# Runbook v0: SUBMODULE_TOKEN

> **Scope:** verify + document only. Rotation steps (PAT→GitHub App) are
> deferred to the user manual cycle this sprint. See §Rotation Procedure.
>
> **Last updated:** 2026-05-12

---

## Purpose

`SUBMODULE_TOKEN` is a GitHub Actions repository secret that grants CI jobs
read access to private submodule repositories during `actions/checkout@v4`
with `submodules: recursive`.

The primary motivation is `packages/clinicalguard`, which is a private
repository. GitHub Actions' default `github.token` is scoped to the workflow's
own repository and cannot authenticate against cross-repo submodule clones.
Without `SUBMODULE_TOKEN`, the checkout step fails with:

```
fatal: repository 'https://github.com/dislovelhl/clinicalguard.git/' not found
```

All four CI workflows fall back gracefully to `github.token` when
`SUBMODULE_TOKEN` is unset (via `${{ secrets.SUBMODULE_TOKEN || github.token }}`),
so public-only forks continue to work. However, any job that needs to clone
`packages/clinicalguard` will fail in the checkout step when the token is
absent or has insufficient scope.

---

## Current Form

`SUBMODULE_TOKEN` is currently configured as a **fine-grained Personal Access
Token (PAT)** stored as a GitHub Actions repository secret under:

`Settings → Secrets and variables → Actions → SUBMODULE_TOKEN`

The token must have `contents: read` permission on every submodule repository
that is private. At minimum: `dislovelhl/clinicalguard`.

> **Security note:** Do not include token values, partial fingerprints, or
> expiry dates in this runbook or in any committed file. Treat the token as
> a credential.

---

## Workflows Using SUBMODULE_TOKEN

All four CI workflows use the same pattern:

```yaml
- uses: actions/checkout@v4
  with:
    submodules: recursive
    token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```

| Workflow | Path |
|---|---|
| `constitutional-hash` | `.github/workflows/constitutional-hash.yml` |
| `python-acgs-lite` | `.github/workflows/python-acgs-lite.yml` |
| `python-acgs-swarm` | `.github/workflows/python-acgs-swarm.yml` |
| `python-clinicalguard` | `.github/workflows/python-clinicalguard.yml` |

Each workflow carries a comment referencing `constitutional-hash.yml` as the
canonical explanation for the token pattern.

---

## Verification Procedure

Run these commands from the repository root to collect recent run IDs and
confirm status. The path-filtered workflows only trigger when their watched
paths change, so use `--limit=5` to find the most recent completed run.

```bash
# constitutional-hash — triggers on every PR/push to master
gh run list --workflow=constitutional-hash.yml --limit=3 \
  --json conclusion,databaseId,status,headBranch

# python-acgs-lite — triggers when packages/acgs-lite/** changes
gh run list --workflow=python-acgs-lite.yml --limit=5 \
  --json conclusion,databaseId,status,headBranch

# python-acgs-swarm — triggers when packages/Acgs-Swarm/** changes
gh run list --workflow=python-acgs-swarm.yml --limit=5 \
  --json conclusion,databaseId,status,headBranch

# python-clinicalguard — triggers when packages/clinicalguard/** changes
gh run list --workflow=python-clinicalguard.yml --limit=5 \
  --json conclusion,databaseId,status,headBranch
```

To inspect the failure log for a specific run:

```bash
gh run view <databaseId> --log-failed
```

**Expected outcome when SUBMODULE_TOKEN is valid:**
`conclusion: "success"` on the checkout step for all workflows.

**Expected outcome when SUBMODULE_TOKEN is absent/expired/insufficient:**
Checkout step fails with `fatal: repository '...clinicalguard.git/' not found`.
See §Failure Modes.

### Run IDs recorded at v0 authoring (2026-05-12)

| Workflow | Run ID | Branch | Conclusion | Notes |
|---|---|---|---|---|
| `constitutional-hash` | `25760063072` | `master` | success | Token functioning |
| `python-acgs-lite` | `25689767900` | `master` | failure | Submodule clone failed — clinicalguard 404 |
| `python-acgs-swarm` | `25689767873` | `master` | failure | Submodule clone failed — clinicalguard 404; also baseline ruff red (Stage 0a) |
| `python-clinicalguard` | `25689767986` | `master` | failure | Submodule clone failed — clinicalguard 404 |

**Interpretation:** `constitutional-hash` passed because it does not depend on
`packages/clinicalguard` content beyond the submodule pointer. The three
package-specific workflows failed because SUBMODULE_TOKEN lacks `contents: read`
on `dislovelhl/clinicalguard` (or the token has expired). This is the primary
gap this runbook documents.

---

## Rotation Procedure

> **Deferred.** Full PAT→GitHub App rotation steps (creation, installation,
> secret update, old-PAT revocation) are explicitly out of scope for this
> sprint (Phase B/3 Stage 1b). Rotation will be executed by the user in the
> next manual maintenance cycle.

When rotation is scheduled, the procedure will cover:

1. Create a new fine-grained PAT (or GitHub App) with `contents: read` on all
   private submodule repos.
2. Update the `SUBMODULE_TOKEN` secret under `Settings → Secrets and variables
   → Actions`.
3. Trigger a `workflow_dispatch` on `constitutional-hash.yml` to verify the
   new token resolves the checkout step.
4. Revoke the old PAT.
5. Record the new run IDs as evidence in a follow-up PR.

These steps are intentionally not expanded here. Expanding them requires the
user to be logged in with org-admin credentials and performing the secret
rotation interactively.

---

## Failure Modes

### Token absent or unset

All four workflows fall back to `github.token`. Checkout with
`submodules: recursive` proceeds but fails when it reaches
`packages/clinicalguard`:

```
fatal: repository 'https://github.com/dislovelhl/clinicalguard.git/' not found
```

Only `constitutional-hash` may still pass (it does not exercise clinicalguard
content). The three package-specific workflows fail at the checkout step.

### Token expired

Same symptom as token absent. The GitHub API returns 401/404 and git reports
the repository as not found. Check the token expiry under
`Settings → Developer settings → Personal access tokens`.

### Token has insufficient scope

If the token exists but lacks `contents: read` on a specific submodule repo,
the clone fails with the same 404 error. Add the missing repo to the token's
repository allow-list.

### Token has correct scope but submodule pointer is stale

The checkout succeeds but the submodule is checked out at a detached HEAD that
no longer exists (force-pushed or deleted). Symptom: `git submodule update`
fails after clone. Fix: update the submodule pointer in the parent repo to a
valid commit.

### Multiple submodule repos go private simultaneously

If additional packages become private (e.g., `acgs-lite`, `Acgs-Swarm`), the
token's repository allow-list must be updated to include those repos, or
`python-acgs-lite` and `python-acgs-swarm` will also begin failing at
checkout.
