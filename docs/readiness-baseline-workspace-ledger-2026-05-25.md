# govern-zone Readiness Baseline Workspace Ledger — 2026-05-25

Scope: `/home/martin/finished work/govern-zone`

Branch: `feat/acgs-conductor-adapter-spike`

Purpose: freeze the workspace state before readiness-baseline changes. This is
an ownership and safety ledger, not a cleanup plan. It records what can be
touched for the readiness baseline and what must remain untouched unless a later
owner-specific task explicitly narrows the scope.

## Collection Commands

```bash
pwd
git rev-parse --show-toplevel
git branch --show-current
git status --short
git submodule status --recursive
find . -path '*/.git' -prune -print | sort
git submodule foreach --recursive 'echo $name; git status --porcelain=v1 | wc -l'
```

## Summary

| Scope | Current evidence | Safe action |
|---|---|---|
| Root repo | 211 dirty paths: 93 tracked dirty, 118 untracked | Do not reset, clean, bulk format, or broad-stage. Only add narrowly scoped readiness-baseline docs/tests/fixes. |
| Registered initialized submodules | `packages/acgs-lite`, `packages/Acgs-Swarm`, `external/UI-TARS-desktop`, `external/everything-claude-code`, `external/natural_language_autoencoders` all report 0 dirty paths | Leave untouched unless a package-local task explicitly targets them. |
| Registered uninitialized submodule | `packages/clinicalguard` has no `.git` marker; `git submodule status` shows leading `-99a7416...` | Treat as unavailable. Do not claim parent verification covers it. |
| Ignored adjacent/nested workspaces | Many nested `.git` roots exist under `ACGS/`, `ACGS-pr52-review/`, `ca-legal-agent-skills/`, `clinicalguard-privacy-hardening/`, `craft-agents-oss/`, `eab-production-hardening/`, and `external/openswarm/` | Out of readiness-baseline write scope. Do not inspect deeply or modify unless separately requested. |

## Root Dirty-State Buckets

| Bucket | Dirty path count | Likely owner | Safe action | Risk if touched |
|---|---:|---|---|---|
| `acgi-ai/` | 138 | Prior console/readiness agents plus user WIP | Touch only files needed for console auth contract, Node 24 gate, and evidence matrix references. Avoid broad frontend cleanup. | Very high: broad edits can mix UI, deploy, auth, CSP, evidence, and generated API work. |
| `packages/gove-zone/` | 23 | Prior runtime/governance agents plus user WIP | Touch only audit-lock portability test and minimal lock boundary if needed. | High: runtime kernel changes can alter policy/audit semantics. |
| `packages/agent-bus-analyzer/` | 16 | Prior evidence/API agents plus user WIP | Leave untouched for this goal unless readiness verification exposes a direct blocker. | Medium-high: API/schema drift can invalidate console contracts. |
| `acgs_governance_eval_mvp/` | 10 | Prior evaluation/benchmark agents plus user WIP | Leave untouched for this goal unless verification requires a docs-only claim clarification. | Medium: benchmark/evaluation claims can be overread as external proof. |
| `scripts/` | 5 | Prior readiness/release evidence agents | Touch only if evidence matrix or verification packet needs a narrow generator/checker. | Medium: root scripts feed release/readiness evidence. |
| `tests/` | 5 | Prior readiness test agents | Add narrow root tests only for readiness drift guards. Avoid sweeping test rewrites. | Medium: tests currently encode evidence boundaries. |
| `docs/` | 4 | Prior architecture/readiness/research agents | Safe place for ledger, evidence matrix, and final evidence packet. Preserve claim-safe wording. | Low-medium: docs can still overclaim if language is loose. |
| `.github/` | 4 | Prior CI/readiness agents | Avoid changing workflows until Node/clinicalguard contract is locally proven. | High: workflow edits change deploy/readiness claims. |
| `.claude/` | 2 | Local agent/runtime config | Leave untouched. | High: local hooks/settings may be user-specific. |
| Root files (`README.md`, `Makefile`, `MONOREPO.md`, `.gitignore`) | 4 | Prior monorepo/readiness agents plus user WIP | Touch only with direct readiness objective and test coverage. | High: these define public claims and fan-out gates. |

## Repository Ledger

| Repository path | Branch / ref | Dirty files | Untracked files | Likely owner | Safe action | Risk if touched | Disposition |
|---|---|---:|---:|---|---|---|---|
| `.` | `feat/acgs-conductor-adapter-spike` | 93 | 118 | Mixed prior agents and user WIP | Add only scoped readiness-baseline artifacts and targeted tests/fixes. | High: root state mixes docs, frontend, Python packages, workflows, and generated artifacts. | Commit only scoped readiness-baseline changes later; leave unrelated paths untouched. |
| `packages/acgs-lite` | detached at `a6c58c42` | 0 | 0 | Submodule owner / public package lane | No writes. | High: independent repo and PyPI-facing API. | Leave untouched. |
| `packages/Acgs-Swarm` | `fix/swebench-eval-command-test` | 0 | 0 | Submodule owner / swarm research lane | No writes. | High: independent repo and research runtime. | Leave untouched. |
| `packages/clinicalguard` | uninitialized `-99a7416...` | n/a | n/a | Private clinicalguard owner | Do not verify as present; document conditional status. | High: parent can falsely appear green while clinical surface is absent. | Deferred until `SUBMODULE_TOKEN` or local initialization exists. |
| `external/UI-TARS-desktop` | `main` | 0 | 0 | External submodule owner | No writes. | Medium: external dependency surface, unrelated to readiness baseline. | Leave untouched. |
| `external/everything-claude-code` | `main` | 0 | 0 | External submodule owner | No writes. | Medium: external dependency surface, unrelated to readiness baseline. | Leave untouched. |
| `external/natural_language_autoencoders` | `main` | 0 | 0 | External submodule owner | No writes. | Medium: external research dependency, unrelated to readiness baseline. | Leave untouched. |
| `ACGS/` and nested repos below it | multiple nested `.git` roots discovered | not enumerated in this goal | not enumerated in this goal | Adjacent checkout owners | Out of scope. | High: separate repo family with its own instructions and WIP. | Leave untouched. |
| `ACGS-pr52-review/` | nested `.git` discovered | not enumerated in this goal | not enumerated in this goal | Adjacent review checkout owner | Out of scope. | High: PR review workspace. | Leave untouched. |
| `ca-legal-agent-skills/` | nested `.git` discovered | not enumerated in this goal | not enumerated in this goal | Legal package owner | Out of scope for govern-zone readiness baseline. | High: legal-domain release rules differ from parent. | Leave untouched. |
| `clinicalguard-privacy-hardening/` | nested `.git` discovered | not enumerated in this goal | not enumerated in this goal | Clinical/privacy hardening owner | Out of scope for parent baseline. | High: clinical/privacy claims require separate owner evidence. | Leave untouched. |
| `craft-agents-oss/` | nested `.git` discovered | not enumerated in this goal | not enumerated in this goal | Adjacent package owner | Out of scope. | Medium-high: unrelated product surface. | Leave untouched. |
| `eab-production-hardening/` | nested `.git` discovered | not enumerated in this goal | not enumerated in this goal | EAB hardening owner | Out of scope. | Medium-high: separate production-hardening repo. | Leave untouched. |
| `external/openswarm/` | nested `.git` discovered | not enumerated in this goal | not enumerated in this goal | External/adjacent owner | Out of scope. | Medium: external checkout, unrelated to current baseline. | Leave untouched. |

## Safe Write Envelope For This Goal

Allowed after this ledger:

- Add readiness-baseline docs under `docs/`.
- Add narrowly scoped tests for:
  - console production session/status contract,
  - `gove-zone` audit import/locking portability,
  - Node 24 fail-fast or explicit support behavior,
  - conditional `clinicalguard` status,
  - legacy typecheck signal separation,
  - enterprise admin adjunct claim status.
- Apply minimal implementation changes only after the relevant failing test has
  been observed.

Not allowed:

- `git reset`, `git clean`, destructive stash, or broad formatting.
- Mixed unrelated commits or bulk staging.
- Submodule writes.
- Architecture rewrites.
- New product features.
- Production, GA, legal/compliance, security-certified, or WCAG-certified claims.

## Current Readiness Interpretation

The root checkout has enough local readiness scaffolding to support targeted
verification work, but its dirty state means every readiness claim must name the
exact command and artifact used. Existing local green checks must not be treated
as production evidence, legal signoff, independent security validation, or
accessibility certification.
