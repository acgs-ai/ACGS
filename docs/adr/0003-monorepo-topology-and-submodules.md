# ADR: Monorepo Topology and Submodule Strategy

## Status

Accepted (established by monorepo unification PR #21; workspace-PLAN.md
landed PR #24, 2026-05-12)

## Context

`govern-zone` began as a collection of loosely related packages under a single
repository root. Over time, several packages were promoted to independent git
repositories with their own CI, PyPI publish cycles, and test suites. At the
same time, a TypeScript frontend (`acgi-ai/`) was added that required a
separate package manager and build graph.

This created a dual-toolchain problem: Python packages needed `uv` workspaces
and per-package virtual environments; TypeScript needed `pnpm` workspaces and
Turborepo for build caching. Neither tool manages the other's dependency
surface. A naive merge into one lock-file would break both.

The decision to adopt git submodules for independently-published packages
(rather than monorepo path-dependencies or vendoring) preserves each package's
independent release cadence while keeping the parent repo as an integration
surface for cross-package CI.

The full topology is documented in `CLAUDE.md` §Layout and
`docs/workspace-PLAN.md`.

## Decision

Adopt a hybrid monorepo topology with two parallel dependency graphs and git
submodules for independently-published packages:

### Python surface — `uv` workspace

A `uv` workspace rooted at `govern-zone/` aggregates all Python packages
declared in `pyproject.toml` members. Each package retains its own
`pyproject.toml` and can be published to PyPI independently. The workspace
provides a shared virtual environment for cross-package development without
requiring editable installs of each package manually.

Packages in the `uv` workspace:

| Package | Path | PyPI status |
|---|---|---|
| `acgs-lite` | `packages/acgs-lite/` | Published |
| `Acgs-Swarm` | `packages/Acgs-Swarm/` | Research; not published |
| `clinicalguard` | `packages/clinicalguard/` | Internal |
| `legalguard` | `packages/legalguard/` | Internal |
| `acgs-cft-governance-pack` | `packages/acgs-cft-governance-pack/` | Internal |
| `acgs_governance_eval_mvp` | `acgs_governance_eval_mvp/` | Internal |
| `hermes_acgs_bundle` | `hermes_acgs_bundle/` | Internal |

### TypeScript surface — `pnpm` + Turborepo

A `pnpm` workspace rooted at `govern-zone/` covers `acgi-ai/` (React 19,
Vite, Tailwind 4, Biome). Turborepo provides task caching for `lint`,
`build`, and `test` tasks. The TypeScript graph is entirely separate from the
Python graph — no shared lock file, no cross-tool dependency.

### Root `Makefile` as unified entry point

`make install`, `make verify`, `make build`, `make all`, and `make clean`
delegate to the appropriate sub-tool for each surface. This provides a single
command surface for CI and for developers who work across both stacks without
requiring knowledge of which tool owns which package.

### Git submodules for independently-published packages

`packages/acgs-lite/`, `packages/Acgs-Swarm/`, and `packages/clinicalguard/`
are registered as git submodules in `.gitmodules`. This means:

- Each package has its own commit history, branch model, and CI pipeline.
- The parent repo pins a specific commit SHA per submodule. Submodule pointer
  drift must be committed in the parent as a separate, intentional step.
- CI checkout requires `SUBMODULE_TOKEN` (a fine-grained PAT) to clone private
  submodule repos. See ADR-0004 for the PAT scope strategy.
- Never commit parent-repo and submodule changes in the same commit.
- Always run `git add <submodule-path>` from inside the submodule, then update
  the parent pointer separately.

## Alternatives considered

### Single lock file (all packages in one `uv` or `pnpm` workspace)

Rejected. `uv` and `pnpm` cannot share a lock file. Forcing all packages into
one tool would require either vendoring the TypeScript build into Python or
treating the Python packages as TypeScript workspace members, neither of which
is viable. The dual-workspace approach keeps each tool in its own domain.

### Vendoring submodule packages as path dependencies

Rejected. Path dependencies prevent independent PyPI publishing. `acgs-lite`
is already published on PyPI. Breaking its independent release cadence
would require coordinated version bumps across all consumers. Submodules
preserve independent versioning.

### Git subtrees instead of submodules

Rejected. Subtrees merge history into the parent repo, making it harder to
push upstream changes to the package's own remote. Submodules keep histories
separated and make the upstream relationship explicit via the `.gitmodules`
pointer.

### Turborepo for the full Python + TypeScript graph

Rejected. Turborepo is a Node.js tool and has no native understanding of `uv`
workspaces, `pytest`, or Python packaging. Using it as the sole task runner
would require wrapping every Python command in a `package.json` script, adding
indirection with no benefit for the Python surface.

## Consequences

Positive:

- Each package can be tested, linted, and published independently without
  affecting the others.
- `make verify` provides a single CI entry point that fans out to each
  package's local gate.
- Submodule pointers give reproducible builds: a specific parent commit
  always maps to specific submodule SHAs.
- `acgs-lite` published floor (`requires-python >= "3.10"`) is preserved
  independently of the workspace development floor (3.11).

Tradeoffs:

- Two package managers (`uv` + `pnpm`) must both be installed on every
  developer machine and every CI runner.
- Submodule checkout requires `SUBMODULE_TOKEN` with correct scopes on all CI
  workflows (see ADR-0004).
- Submodule pointer drift is a silent hazard: a `git add -A` in the parent
  will silently stage a submodule pointer change if the submodule's HEAD moved.
  Always stage explicitly by file path.
- Turborepo task cache is only effective for the TypeScript surface; Python
  test caching is handled separately by `pytest` or per-package CI caching.

## References

- `CLAUDE.md` §Layout — canonical package table and toolchain assignments
- `docs/workspace-PLAN.md` — Phase B/3 component sequencing and topology
  rationale
- `docs/PLAN-MONOREPO.md` — monorepo unification plan (PR #21)
- `.gitmodules` — submodule registrations
- `Makefile` — unified build entry point
- ADR-0004 — SUBMODULE_TOKEN PAT scope strategy (covers CI checkout of
  submodule repos)
