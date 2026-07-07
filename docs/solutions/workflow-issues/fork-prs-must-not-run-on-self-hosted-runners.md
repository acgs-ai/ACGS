---
title: "Fork PRs must not run on self-hosted runners — job-level same-repo guard"
date: 2026-07-07
category: workflow-issues
module: CI / GitHub Actions (govern-zone monorepo)
problem_type: workflow_issue
component: development_workflow
severity: high
applies_when:
  - "A workflow has a `pull_request` trigger and any job with `runs-on: [self-hosted, ...]`"
  - "Adding a new workflow or a new job to an existing pull_request-triggered workflow"
  - "The repository is public, so anyone can open a PR from a fork"
tags: [ci, github-actions, self-hosted-runner, security, fork-pr, pull_request]
---

# Fork PRs must not run on self-hosted runners

## Problem

This is a public repository, and many workflows combine a `pull_request`
trigger with `runs-on: [self-hosted, Linux, X64]`. A `pull_request` job checks
out and executes the PR head — untrusted fork code — so without a guard, anyone
could open a fork PR and run arbitrary code on the maintainer's self-hosted
runner machine.

## Solution

Every self-hosted job in a `pull_request`-triggered workflow carries a
job-level guard:

```yaml
if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
```

- Same-repo PRs (branch pushed by a collaborator) still run — the head repo
  equals the base repo.
- Fork PRs skip the self-hosted job entirely.
- `push` / `schedule` / `workflow_dispatch` behavior is unchanged (the first
  clause is true for non-PR events). Jobs that already had
  `if: github.event_name == 'push'` were composed with `&&`, preserving their
  logic.

Applied 2026-07-07 to 22 jobs across 16 workflows (console, constitutional-hash,
deploy-agent-bus-analyzer, eval, marketing, marketing-cloudflare, the eight
`python-*` package gates, readiness-evidence, tests-root). The `-hosted` twin
workflows and other `ubuntu-latest`-only workflows need no guard.

## Enforcement

`tests/test_workflow_security_invariants.py::test_pull_request_workflows_guard_self_hosted_jobs_against_forks`
fails if any `.github/workflows/*.yml` with a `pull_request` trigger contains a
self-hosted job without this exact guard on a job-level `if:`. This test runs
in the root tests gate, so a new unguarded job cannot land silently.

## Limitations

- The guard skips fork-PR jobs; it does not make fork code safe to run.
  Repository settings such as "Require approval for all outside collaborators"
  under Actions → General are complementary, human-gated controls and are NOT
  covered by this change.
- Skipped required checks: if a self-hosted check is a required status check,
  a fork PR will show it as skipped/pending. Fork contributions would need a
  maintainer to push the branch into the repo (or a ubuntu-latest twin
  workflow) to get a green gate.
- The invariant test is a line-based parser, not a full YAML parser (pyyaml is
  not a workspace dependency). It expects the guard on a single-line job-level
  `if:`; multi-line `if: |` blocks would need the test updated.
- OR-composition (mitigated): a substring check alone would accept a vacuous
  `if: true || (<guard>)`. The test therefore strips the guard from the `if:`
  expression and rejects any remaining `||` — the guard must be the whole
  expression or a top-level AND conjunct. This is deliberately over-strict:
  a safe-but-OR-containing sibling clause like `(guard) && (a || b)` also
  fails and must be rewritten (e.g. into a separate condition).
