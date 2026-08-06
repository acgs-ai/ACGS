---
name: govern-zone
description: Use when working anywhere in the govern-zone (acgs-ai/ACGS) monorepo — coding conventions, package/console scaffolding workflows, CI-gate alignment, and readiness-evidence upkeep.
---

# govern-zone Development Patterns

> Originally generated from repository analysis; maintained by hand since — there is no
> generator for this file.

## Overview

This skill covers the core development patterns, coding conventions, and operational workflows for the `govern-zone` repository. The codebase is primarily Python (with some frontend JavaScript/TypeScript), organized as a monorepo with multiple Python packages and a frontend app. It emphasizes strong workspace hygiene, contract-driven development, and robust CI/CD practices. This guide will help you contribute new features, maintain packages, manage readiness evidence, and keep the repository clean and production-ready.

`CLAUDE.md` and `AGENTS.md` at the repo root are authoritative, and `MONOREPO.md` is the
registry of record for what exists and what is gated where. Where this skill and a
package-local `CLAUDE.md` / `AGENTS.md` disagree, the package-local file wins inside its own
directory.

## Hard Constraints

Read these before changing anything. They are not style preferences.

1. **Constitutional hashes are sealed.** Files carrying a constitutional-hash marker,
   `@generated`, `DO NOT EDIT`, or lock-file semantics must not be hand-edited. Change the
   generator and regenerate; `scripts/verify_constitutional_hashes.py` gates every PR.
2. **Nested git repos are real boundaries.** `packages/acgs-lite`, `packages/Acgs-Swarm`,
   `packages/clinicalguard`, and `packages/ACGS-agency-agents` are independent repos
   registered in `.gitmodules`. Run `git add` / `git commit` **from inside the package**,
   never from the parent. Parent gitlink pointer drift is out of scope unless that *is* the
   task. `packages/acgs-control-plane` is **not** among them — it is an ordinary tracked
   directory (`040000 tree`), so stage it from the parent like any other path. Confirm
   against `.gitmodules` and `git ls-tree` rather than assuming; extraction to a submodule
   is proposed but not landed.
3. **`acgs-lite` is published to PyPI.** Do not break its public API or its published
   `requires-python = ">=3.10"` floor. The workspace-local floor is 3.11; the difference is
   deliberate.
4. **The console origin is privileged.** Never extend public-only patterns (CDN fonts,
   third-party scripts, anonymous endpoints) into `acgi-ai/src/routes/console/**`. See
   `acgi-ai/CLAUDE.md` and `acgi-ai/DEPLOY.md` §4–§7.
5. **Never weaken fail-closed governance.** Do not bypass receipt validation, let execution
   precede audit, treat `DENY`/`ESCALATE` as executable, or drop actor/action/policy binding
   checks.
6. **Claim safety.** Never describe ACGS as compliance-certified, regulator-approved,
   formally verified, or production-ready without external evidence. Safe wording: "local
   receipt-gated kernel", "alpha / production-shaped foundation", "tamper-evident JSONL
   audit chain", "opt-in Ed25519 signing mode". Numeric claims (test counts, benchmarks)
   require literal command output.
7. **Stage explicit paths only.** Never `git add -A` or `git add .` in this workspace.
   `git push` and `gh release` are human-gated — prepare the branch and hand off.

## Verification Gates

Run the package-local gate before claiming work complete. A passing unit test does not prove
handler wiring — trace one request from the dispatcher to the handler.

```bash
# Root documentation smoke
uv run python -m pytest tests/docs --import-mode=importlib -q

# gove-zone runtime — the main kernel gate
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q

# Root docs invariants
make lint-docs

# Frontend / console — run inside acgi-ai/
pnpm run lint && pnpm run typecheck && pnpm run test

# Whole workspace — only when intentionally validating every package
make verify
```

Fast kernel proof commands:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/smoke-audit.jsonl"
uv run --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
```

## Coding Conventions

### File Naming

- **Python modules:** `snake_case`, with a leading underscore for private helpers.
  - Example: `replay_store.py`, `benchmark_adapters.py`, `_locking.py`
- **Python package directories:** kebab-case on disk, `snake_case` for the importable module.
  - Example: `packages/gove-zone/src/gove_zone/`
- **Frontend (JS/TS):** `PascalCase.tsx` for React components, `camelCase.ts` for modules.
  - Example: `UserDashboard.tsx`, `src/api/client.ts`

### Imports

- **Python:** Use relative imports within packages.
  ```python
  from .utils import fetch_data
  ```
- **Frontend:** Standard ES module imports, often relative.
  ```javascript
  import { fetchUser } from './api/client'
  ```

### Exports

- **Python:** Named exports via explicit imports in `__init__.py`.
  ```python
  # __init__.py
  from .replay_store import ReplayStore
  ```
- **Frontend:** Named exports.
  ```javascript
  export function useUserData() { ... }
  ```

### Commit Patterns

- Conventional Commits: `feat`, `fix`, `docs`, `test`, `chore`, `ci`, `refactor`, with an
  optional scope. (`impl` appears a handful of times in older history; do not use it.)
- Example: `fix(gateway): correct package registration in pyproject.toml`
- The default branch is `master`, **not** `main`. Open PRs with `--base master`.

---

## Workflows

### Add New Workspace Python Package

**Trigger:** When introducing a new governed agent runtime or analyzer package.  
**Command:** `/new-python-package`

1. Create a new directory under `packages/{package}/`.
2. Add `pyproject.toml`, `README.md`, `.gitignore`, and `Makefile`.
3. Implement source files in `src/{package}/`.
4. Add tests in `tests/`.
5. Register the package in the root `pyproject.toml` under `[tool.uv.workspace].members`.
6. Update `tests/test_monorepo_invariants.py` to include the new member.
7. Add or update `.github/workflows/python-{package}.yml` for CI.

**Example:**
```bash
mkdir -p packages/my-new-agent/src/my_new_agent
touch packages/my-new-agent/pyproject.toml
echo "# My New Agent" > packages/my-new-agent/README.md
# ...etc
```

---

### Add New Frontend Console Surface

**Trigger:** When adding a new operator-facing page or feature to the `acgi-ai` console.  
**Command:** `/new-console-page`

1. Create a new route file in `acgi-ai/src/routes/console/{Feature}.tsx`.
2. Register the route in `acgi-ai/src/routes/Console.tsx` (and sometimes `App.tsx`). A new
   page without routing plumbing in the same commit is an orphan and will be rejected.
3. Update or add API client in `src/api/client.ts` and types in `src/api/types.ts`.
4. Add React Query hooks in `src/api/hooks.ts`.
5. Add or update MSW mock data and handlers in `src/mocks/data/` and `src/mocks/handlers.ts`.
6. Add or update CSS in `src/App.css`.
7. Add/extend invariant or smoke scripts in `scripts/`.
8. Update `package.json` test scripts if needed.

**Example:**
```tsx
// acgi-ai/src/routes/console/MyFeature.tsx
export function MyFeaturePage() {
  // ...
}
```

---

### Spec, Plan, and Implement Feature with Contracts and Tests

**Trigger:** When delivering a new major feature with traceable requirements and acceptance.  
**Command:** `/new-feature-spec-plan`

1. Draft feature spec and requirements in `specs/{feature}/`.
2. Write implementation plan, data model, and contracts (JSON Schema, OpenAPI).
3. Add `tasks.md` with granular task breakdown.
4. Implement backend package (see "Add New Workspace Python Package").
5. Implement frontend surface (see "Add New Frontend Console Surface").
6. Add/extend tests for backend and frontend.
7. Add/extend acceptance/README.md documenting evidence and acceptance.
8. Update readiness docs and evidence packet.

**Example:**
```markdown
# specs/agent-bus-analysis/spec.md
## Overview
...
```

---

### CI Gate Tighten or Fix

**Trigger:** When fixing failing CI, aligning root/package gates, or updating verification scope.  
**Command:** `/ci-align`

1. Update `Makefile` to include/exclude packages in lint/test/typecheck fan-out.
2. Update root `pyproject.toml` workspace.members.
3. Update or add `.github/workflows/*.yml` for affected packages.
4. Update `tests/test_monorepo_invariants.py` to match current package inventory.
5. Fix or update package-level test/lint/typecheck scripts as needed.

A required status check is satisfied by `success`, `skipped`, **or** `neutral`. A job skipped
by an `if:` conditional reports Success and will not block a merge. Read the run; never treat
a green context as proof the gate executed.

---

### Change Receipt, Policy, Audit, Signing, or Executor Behavior

**Trigger:** When touching the security-sensitive modules under
`packages/gove-zone/src/gove_zone/` — `receipt`, `executor`, `kernel`, `audit`, `replay`,
`replay_store`, `signing`, `policy`, `tenant`, `integration`.

1. Read the implementation and its tests before touching any claim.
2. Add or update negative-path tests asserting the guarded side effect did **not** run — an
   empty call list, not merely a raised exception.
3. Prove dispatcher-level wiring, not just direct unit calls.
4. Run the gove-zone package gate.
5. Only then update `docs/DECISION_RECEIPT_SPEC.md`, `docs/SECURITY_MODEL.md`, and
   `docs/CLAIMS.md`.
6. State explicitly whether unsigned mode, signing mode, policy-bundle binding, expiry,
   actor binding, audit replay, or executor enforcement changed.

---

### Add or Update Readiness Evidence and Boundaries

**Trigger:** When updating readiness docs, adding evidence, or changing preflight/launch gating.  
**Command:** `/refresh-readiness-evidence`

1. Update `docs/readiness-evidence-matrix-*.md` and `docs/readiness-evidence-packet-*.md`.
2. Update scripts like `scripts/build_release_evidence.py` and `scripts/platform_readiness_report.py`.
3. Update or add tests for readiness evidence and preflight in `tests/`.
4. Update `acgi-ai/DEPLOY.md`, `PRODUCTION-LAUNCH.md`, and related docs.
5. Add or update Makefile targets for evidence/report generation.

Readiness gates assert **literal doc strings**. If a gate fails after a doc edit, restore the
literal — never edit the gate to match the new prose.

---

### Update or Add .gitignore for Tool or Build Artifacts

**Trigger:** When preventing accidental commit of tool outputs, caches, or local artifacts.  
**Command:** `/update-gitignore`

1. Edit `.gitignore` or `packages/{package}/.gitignore` to add new patterns.
2. Document rationale in commit message.
3. Review with `git status` or similar.

**Example:**
```
# .gitignore
__pycache__/
*.pyc
dist/
```

---

### Remove or Extract Inactive or Experimental Package

**Trigger:** When cleaning up the workspace by removing unmaintained or experimental packages.  
**Command:** `/remove-package`

1. Delete the package directory and all files under it.
2. Remove the package from root `pyproject.toml` workspace.members if present.
3. Update docs or manifests referencing the package.
4. Archive externally if needed.
5. If extracting to a private repo, register it in `.gitmodules` and confirm the CI
   `SUBMODULE_TOKEN` carries Contents: Read on the new repo **before** merging — otherwise
   the submodule-aware gates red every subsequent PR.

---

## Testing Patterns

- **Framework:** [vitest](https://vitest.dev/) (frontend JS/TS), pytest (Python)
- **Pattern:** frontend tests are `*.test.ts` / `*.test.tsx`; Python tests are `test_*.py`
- **Python:** Tests are placed in `tests/` directories within each package and at the repo root for monorepo invariants.
- **Example (TS):**
  ```typescript
  // receipt.test.ts
  import { expect, test } from 'vitest'
  import { formatReceipt } from './receipt'

  test('formats a denied receipt', () => {
    expect(formatReceipt({ decision: 'DENY' })).toContain('DENY')
  })
  ```
- **Example (Python):**
  ```python
  # packages/gove-zone/tests/test_replay_store.py
  from gove_zone.replay_store import ReplayStore

  def test_replay_store_rejects_tampered_chain() -> None:
      ...
  ```

---

## Commands

| Command                 | Purpose                                                         |
|-------------------------|-----------------------------------------------------------------|
| /new-python-package     | Scaffold and register a new Python package in the workspace     |
| /new-console-page       | Add a new operator-facing console page or feature               |
| /new-feature-spec-plan  | Deliver a new feature from spec to acceptance                   |
| /ci-align               | Align or fix CI gates, Makefile, and invariants                 |
| /refresh-readiness-evidence | Update readiness docs, evidence, and preflight scripts      |
| /update-gitignore       | Add or update .gitignore for tool/build artifacts               |
| /remove-package         | Remove or extract an inactive or experimental package           |
