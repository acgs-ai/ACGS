<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-07-11 -->

# workflows

## Purpose
This directory defines ACGS verification, evidence, security, release, and
deployment automation. The canonical SaaS-beta workflows use a strict privilege
split: pull-request workflows verify without deployment authority, while
deployment workflows accept only pushes to `master`, require an exact approved
commit SHA, and enter protected environments before mutation. Their presence is
not proof that a deployment, release, or external assurance result occurred.

## Key Files
| File | Description |
|------|-------------|
| `saas-beta-required.yml` | Path-unfiltered, read-only aggregate PR gate; Gate 16 is the final self-contract check. |
| `console.yml` | PR-only console build and browser verification. |
| `console-deploy.yml` | Push-only Cloud Run publication/deployment after `CONSOLE_PRODUCTION_APPROVED_SHA` matches the candidate SHA. |
| `marketing.yml` | PR-only marketing build and Cloudflare Workers Assets contract verification. |
| `marketing-cloudflare.yml` | Push-only Workers Assets deployment after `MARKETING_PRODUCTION_APPROVED_SHA` matches the candidate SHA. |
| `storybook.yml` | PR-only buyer-evidence Storybook build. |
| `storybook-deploy.yml` | Push-only GitHub Pages deployment after `STORYBOOK_PRODUCTION_APPROVED_SHA` matches the candidate SHA. |
| `python-acgs-control-plane.yml` | Hosted, hash-locked control-plane verification. |
| `python-gove-zone.yml` | Hosted, hash-locked governed-runtime verification. |
| `tthw.yml` | Scheduled/manual time-to-hello-world evidence check using the reviewed toolchain. |
| `constitutional-hash.yml`, `constitutional-hash-hosted.yml` | Self-hosted authority plus hosted redundant constitutional-hash checks. |
| `readiness-evidence.yml`, `readiness-evidence-hosted.yml` | Self-hosted authority plus hosted redundant readiness-evidence checks. |
| `tests-root.yml`, `tests-root-hosted.yml`, `tests-docs.yml` | Root and documentation verification lanes. |
| `python-*.yml` | Path-scoped package checks; inspect the target package's local instructions before changes. |
| `release.yml` | Tag-driven release packaging/publication; a workflow file alone is not release evidence. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Treat `master` as the canonical branch. Do not silently substitute `main`.
- Preserve the canonical PR/deploy split. `console.yml`, `marketing.yml`, and
  `storybook.yml` are read-only PR verification; their deploy counterparts are
  push-only and must retain exact-approved-SHA plus protected-environment gates.
- Keep `saas-beta-required.yml` free of `paths` and `paths-ignore`. It must remain
  one ordered GitHub-hosted job with no secrets, persisted checkout credentials,
  deployment permissions, or advisory gates. Keep Gate 16 as its final step.
- Preserve Gate 01's reviewed pytest argv exactly. Sanitize inherited
  `VIRTUAL_ENV` and `PYTHONPATH` in its step-specific shell, and keep
  `UV_OFFLINE`, `UV_NO_INDEX`, and `UV_NO_CACHE` scoped to Gate 01.
- In canonical SaaS-beta workflows, pin actions to reviewed immutable 40-hex
  commit SHAs. Do not add `pnpm/action-setup`; activate the manifest's
  integrity-qualified pnpm selector through Corepack and reject integrity bypasses.
- Marketing uses Cloudflare Workers Static Assets through
  `infra/cloudflare/workers/wrangler.toml`, not a Cloudflare Pages project.
- Workflow configuration is not proof of deployment, release, or external assurance.
- Never replace GCP Workload Identity Federation with a stored service-account
  key, expose deployment secrets to PR code, or infer a deployment result from
  workflow configuration.
- Path-filtered package, experiment, and redundant workflows have narrower
  contracts; do not copy their trigger or runner assumptions into the aggregate gate.

### Testing Requirements
- Run `actionlint .github/workflows/<changed-file>.yml` for every workflow edit.
- For the aggregate workflow, run the exact Gate 01 command with the locked
  `.venv-evidence` interpreter and run:
  `tests/saas_beta/test_ci_gate_contract.py::test_all_owned_scope_gates_are_required`.
- Run `tests/saas_beta/test_evidence_bootstrap.py::test_clean_sibling_hash_locked_bootstraps_and_round_trip`
  after evidence-inventory or reviewed-command changes.
- Confirm the aggregate contract still has exactly 16 gates and that Gate 16 is
  the final step. Do not weaken or skip a failing invariant to satisfy CI.

### Common Patterns
- Canonical frontend workflows use Node 24.18.0, an integrity-qualified pnpm
  9.15.4 selector, Corepack enforcement, and frozen-lockfile installs.
- Canonical PR workflows grant read-only contents permission and have no
  production environment or secret access.
- Canonical deployment workflows start only on `master` pushes, split verify,
  authorize, and mutate jobs, and compare a protected repository/environment
  variable to `github.sha` before privileged work.
- Console targets Cloud Run using short-lived GCP identity; marketing targets
  Cloudflare Workers Assets; Storybook targets GitHub Pages.
- Hosted redundant workflows improve runner availability but do not replace the
  explicitly documented authoritative checks.

## Dependencies

### Internal
- `tests/saas_beta/test_ci_gate_contract.py` and
  `tests/saas_beta/test_evidence_bootstrap.py` for fail-closed textual and runtime contracts.
- `requirements/saas-beta/*.lock`, package manifests, and package-local validation instructions.
- `acgi-ai/package.json`, its reviewed package-manager selector, and browser/build scripts.
- `infra/cloudrun/`, `infra/Dockerfile.console`, and
  `infra/cloudflare/workers/wrangler.toml` plus reviewed headers/redirects.

### External
- Immutable GitHub Actions revisions, GitHub-hosted runners, and protected environments.
- GCP Workload Identity Federation and Cloud Run.
- Cloudflare Workers Static Assets and GitHub Pages.
- Node/Corepack/pnpm, uv/Python, Docker Buildx, and provider CLIs pinned by each workflow.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
