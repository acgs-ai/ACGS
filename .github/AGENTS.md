<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-07-11 -->

# .github

## Purpose
This directory contains GitHub platform configuration for ACGS. The canonical
SaaS-beta boundary deliberately separates read-only pull-request verification
from push-only deployment workflows that require an exact approved commit and a
protected environment. A workflow definition is configuration, not evidence
that a deployment ran or that any environment is production-ready.

## Key Files
| File | Description |
|------|-------------|
| `AGENTS.md` | Directory-local instructions for GitHub configuration. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `workflows/` | CI, security, evidence, release, and deployment workflows (see `workflows/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Read `workflows/AGENTS.md` before changing a workflow and keep the repository's
  default branch name as `master`.
- Preserve the privilege split: canonical PR workflows verify untrusted changes
  with read-only permissions, while deployment workflows run only after a push
  to `master`, exact-approved-SHA authorization, and protected-environment gates.
- Keep `.github/workflows/saas-beta-required.yml` free of path filters so the
  aggregate required gate cannot be skipped. Path filters remain appropriate
  for explicitly scoped package and surface workflows when their contracts say so.
- Keep canonical action references pinned to reviewed immutable 40-hex commit
  SHAs. Do not add `pnpm/action-setup`; canonical Node workflows activate the
  integrity-qualified pnpm selector through Corepack.
- Never add long-lived credentials or service-account JSON. Console deployment
  uses short-lived GCP Workload Identity Federation; deployment secrets belong
  in protected GitHub environments.
- Preserve generated-file manual regions below their `<!-- MANUAL: ... -->`
  marker when regenerating these instruction files.

### Testing Requirements
- Run `actionlint` against every changed workflow.
- Run the closest workflow contract test. Changes to canonical SaaS-beta gates
  require `tests/saas_beta/test_ci_gate_contract.py` in the reviewed locked
  interpreter and the exact Gate 01 evidence-interpreter check.
- Confirm referenced package scripts, infrastructure files, and action inputs
  exist. A passing local check does not establish a live deployment result.

### Common Patterns
- `console.yml`, `marketing.yml`, and `storybook.yml` are PR-only verification
  workflows; their `*-deploy.yml` counterparts are push-only privileged lanes.
- Console deployment targets Cloud Run, marketing deployment targets
  Cloudflare Workers Static Assets, and buyer-evidence Storybook targets GitHub
  Pages. These targets have different authority and trust boundaries.
- The aggregate SaaS-beta workflow is one ordered, GitHub-hosted, read-only gate
  with no path filters and no deployment authority.

## Dependencies

### Internal
- Root and package manifests, hash-locked Python requirements, and
  `tests/saas_beta/test_ci_gate_contract.py`.
- `acgi-ai/` build scripts and browser tests for the three web-surface workflows.
- `infra/` Cloud Run and Cloudflare Workers Assets configuration.

### External
- GitHub-hosted and explicitly documented self-hosted runners.
- GitHub protected environments and repository variables for exact-SHA approval.
- Corepack/Node, uv/Python, GCP Workload Identity Federation, Cloudflare Workers,
  and GitHub Pages actions.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
