# ADR: SUBMODULE_TOKEN PAT Scope Strategy

## Status

Accepted (documented strategy following CI failures on PRs #25, #26, #27;
2026-05-13)

## Context

Several CI workflows in `.github/workflows/` must check out git submodules as
part of their jobs:

| Workflow | File | Submodules checked out |
|---|---|---|
| Constitutional hash verification | `constitutional-hash.yml` | `ACGS/`, `Acgs-Swarm/` |
| acgs-lite Python CI | `python-acgs-lite.yml` | `packages/acgs-lite/` |
| Acgs-Swarm Python CI | `python-acgs-swarm.yml` | `packages/Acgs-Swarm/` |
| ClinicalGuard Python CI | `python-clinicalguard.yml` | `packages/clinicalguard/` |

These workflows use a fine-grained Personal Access Token (PAT) stored as the
repository secret `SUBMODULE_TOKEN`. The PAT is passed to
`actions/checkout` via `token: ${{ secrets.SUBMODULE_TOKEN }}` so that the
action can authenticate against private submodule repositories that the default
`GITHUB_TOKEN` cannot reach.

### The failure mode (PRs #25, #26, #27)

CI failed at exit 128 with an authentication error during `actions/checkout`.
Root cause: the PAT was scoped to only the three submodule repositories
(`acgs-lite`, `Acgs-Swarm`, `clinicalguard`) and was missing `Contents: Read`
permission on the parent repository (`dislovelhl/govern-zone`). When
`actions/checkout` clones the parent repo using the PAT before initialising
submodules, it fails if the PAT cannot read the parent.

### The truthy-fallback trap

A common defensive pattern is:

```yaml
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```

This pattern is silently broken. The `||` fallback in GitHub Actions expression
syntax evaluates the left side as a boolean — an empty string is falsy, but any
non-empty string is truthy. A PAT that is set in the secret store (even an
invalid or expired one) is a non-empty string, so it is always truthy. The
`github.token` fallback never fires for a broken PAT, only for a
completely-absent secret.

The result: a misconfigured `SUBMODULE_TOKEN` silently masks the
`github.token` fallback, and the workflow fails with an opaque exit 128 rather
than a clear "secret not found" error.

## Decision

Adopt the following PAT scope and usage strategy for `SUBMODULE_TOKEN`:

### Required PAT scopes

The `SUBMODULE_TOKEN` PAT must have `Contents: Read` on every repository it
will touch during a workflow run, including:

1. The parent repository: `dislovelhl/govern-zone`
2. Every submodule repository checked out by the workflow

Current required repositories:

| Repository | Required scope |
|---|---|
| `dislovelhl/govern-zone` | `Contents: Read` |
| `dislovelhl/acgs-lite` (or upstream) | `Contents: Read` |
| `dislovelhl/Acgs-Swarm` (or upstream) | `Contents: Read` |
| `dislovelhl/clinicalguard` (or upstream) | `Contents: Read` |

When a new submodule is added to `.gitmodules`, the PAT must be updated to
include `Contents: Read` on the new repository before the workflow is merged.

### Loud-failure token pattern

Use the explicit token reference without fallback:

```yaml
- uses: actions/checkout@v4
  with:
    token: ${{ secrets.SUBMODULE_TOKEN }}
    submodules: recursive
```

Do not use:

```yaml
# AVOID — truthy fallback never fires for a broken-but-set PAT
token: ${{ secrets.SUBMODULE_TOKEN || github.token }}
```

If `SUBMODULE_TOKEN` is absent from the secret store, the explicit form fails
loudly with a "secret not found" error that is immediately diagnosable. The
truthy-fallback form masks the error and may appear to succeed (if
`github.token` has sufficient permissions) or fail with an opaque exit code
(if it does not).

### PAT rotation runbook

When rotating `SUBMODULE_TOKEN`:

1. Create or update the fine-grained PAT in the GitHub account settings with
   the required `Contents: Read` scopes on all repositories listed above.
2. Navigate to `dislovelhl/govern-zone` → Settings → Secrets → Actions.
3. Update `SUBMODULE_TOKEN` with the new PAT value.
4. Trigger a manual workflow run on `constitutional-hash.yml` (the broadest
   submodule consumer) to verify checkout succeeds before closing the rotation.
5. Record the rotation date and expiry in the internal runbook at
   `docs/runbooks/submodule-token.md` (Stage 1b deliverable).

## Alternatives considered

### Use `github.token` for all workflows

Rejected. `GITHUB_TOKEN` is scoped to the repository in which the workflow
runs. It cannot authenticate against private submodule repositories in other
GitHub accounts or organisations. This is the fundamental reason a PAT is
required.

### Use a machine-user OAuth token instead of a fine-grained PAT

Not adopted at this stage. A machine-user token would require creating and
managing a separate GitHub account. Fine-grained PATs are auditable per-repo
and can be rotated without touching any other credential surface.
Re-evaluate if the submodule count grows beyond six or if the PAT rotation
overhead becomes a recurring operational burden.

### Use `secrets.X || github.token` as a safety net

Rejected. As documented in the §Context above, this pattern provides no safety
net for a broken-but-set PAT. It adds apparent resilience while actually
masking the failure mode that caused PRs #25–#27. The loud-failure pattern is
strictly preferable.

### Use SSH deploy keys per submodule

Not adopted. Deploy keys require one key per submodule per repository, are
harder to rotate atomically, and do not compose with `actions/checkout`'s
`submodules: recursive` mode without additional steps. Fine-grained PATs
covering multiple repositories are simpler to manage for this use case.

## Consequences

Positive:

- A misconfigured or expired `SUBMODULE_TOKEN` produces an immediate,
  diagnosable "secret not found" or "authentication failed" error rather than
  a silent fallback or opaque exit 128.
- The required PAT scope list is explicit and documented here; adding a
  submodule triggers a clear checklist item (update PAT scopes before merge).
- Rotation procedure is defined and can be executed without re-deriving the
  scope requirements each time.

Tradeoffs:

- Fine-grained PATs have an expiry date. Rotation must be tracked proactively;
  expiry during a release window will block CI.
- Every new private submodule requires a PAT update before the first
  workflow merge. This adds a pre-merge checklist step.
- The loud-failure pattern means CI fails hard if the secret is absent or
  expired, with no graceful degradation. This is the intended behaviour.

## References

- `.github/workflows/constitutional-hash.yml` — broadest submodule consumer
- `.github/workflows/python-acgs-lite.yml`
- `.github/workflows/python-acgs-swarm.yml`
- `.github/workflows/python-clinicalguard.yml`
- `docs/workspace-PLAN.md` §Component 3 — Submodule Token Follow-ups
- ADR-0003 — Monorepo Topology and Submodule Strategy (establishes why
  submodules exist and why a PAT is required)
- GitHub Actions documentation: "Encrypted secrets" and fine-grained PAT
  scopes
