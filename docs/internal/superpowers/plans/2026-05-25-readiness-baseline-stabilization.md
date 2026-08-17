> **Internal engineering document.** Not part of the public release artifact.

# Readiness Baseline Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]` / `- [x]`) syntax for tracking.

**Goal:** Stabilize govern-zone so readiness claims are evidence-grounded before any new feature work.

**Architecture:** Keep the change set narrow: documentation first, then static/contract tests, then minimal implementation only where a failing test proves a boundary gap. Preserve existing local-vs-production proof boundaries and do not touch submodules or adjacent checkouts.

**Tech Stack:** Markdown docs, Node/pnpm static checks for `acgi-ai`, Python/pytest for root and `packages/gove-zone`, Makefile guardrails.

---

## File Structure

- Created: `docs/readiness-baseline-workspace-ledger-2026-05-25.md`
  - Freezes root and nested repo state before code changes.
- Create: `docs/readiness-evidence-matrix-2026-05-25.md`
  - Separates Local, Staging, Production, Legal/compliance, Security, and Accessibility evidence.
- Create: `docs/readiness-evidence-packet-2026-05-25.md`
  - Final commands, pass/fail results, environment, limitations, blockers, and supported/unsupported claims.
- Modify: `acgi-ai/scripts/check-auth-boundary.mjs`
  - Add production console session/status contract checks.
- Potentially modify: `acgi-ai/src/lib/session.ts`, `acgi-ai/src/surfaces/console/App.tsx`
  - Only if the new auth-boundary contract fails and proves a required behavior gap.
- Create: `packages/gove-zone/tests/test_audit_portability.py`
  - Import/locking portability boundary test.
- Modify: `packages/gove-zone/src/gove_zone/audit.py`
  - Minimal lock abstraction so unsupported platforms do not fail at module import.
- Modify: `tests/test_node24_gate.py`, `scripts/run_acgi_node24_gate.sh`, maybe `Makefile`
  - Make Node 24 behavior explicit and fail-fast.
- Modify: `tests/test_root_typecheck_gate.py`, `Makefile`
  - Keep strict typecheck signal separate from legacy/informational skips if current wording is not explicit enough.
- Modify: `scripts/check_governance_stack_index.py`, `docs/governance-stack-index.md`, maybe `MONOREPO.md`
  - Lock `clinicalguard` conditional status and enterprise admin adjunct readiness status.

## Task 1: Evidence Matrix

- [x] **Step 1: Write `docs/readiness-evidence-matrix-2026-05-25.md`**

Include a table with columns:

```markdown
| Area | Environment | Current evidence | Verification command/source | Confidence | Not proven | Required next proof |
|---|---|---|---|---|---|---|
```

Rows must cover Local, Staging, Production, Legal/compliance, Security, Accessibility, Clinical, Enterprise admin adjunct, and Browser evidence.

- [x] **Step 2: Verify claim wording**

Run:

```bash
rg -n "production-ready|compliance-ready|security-certified|WCAG certified|regulator-grade|GA" docs/readiness-evidence-matrix-2026-05-25.md
```

Expected: no output.

## Task 2: Console Auth Contract

- [x] **Step 1: Add failing static contract to `acgi-ai/scripts/check-auth-boundary.mjs`**

Require the contract to state:

```text
Production console access must be backed by edge/server auth status, not demo sessionStorage.
If no production session/status bridge exists, the check must fail closed with a clear message.
```

Add checks for one of these explicit proof surfaces:

```js
const hasProductionStatusBridge =
  /auth\/status|session\/status|operator context|forward-auth status/i.test(sessionSource) ||
  /auth\/status|session\/status|operator context|forward-auth status/i.test(consoleAppSource)
```

Use a failure message that names `/console` and production session/status.

- [x] **Step 2: Run RED**

Run:

```bash
pnpm -F acgi-ai run test:auth-boundary
```

Expected: fail if the production status bridge is not currently represented.

- [x] **Step 3: Implement the smallest passing contract**

Prefer documentation/static contract first. Only change runtime behavior if the failing test proves the existing implementation cannot represent production auth correctly.

- [x] **Step 4: Run GREEN**

Run:

```bash
pnpm -F acgi-ai run test:auth-boundary
```

Expected: pass.

## Task 3: `gove-zone` Audit Portability

- [x] **Step 1: Write failing test `packages/gove-zone/tests/test_audit_portability.py`**

Test intent:

```python
def test_audit_module_import_does_not_require_fcntl(monkeypatch):
    # Simulate platforms where fcntl cannot be imported before reloading audit.py.
```

The test must prove module import does not require `fcntl`.

- [x] **Step 2: Run RED**

Run:

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests/test_audit_portability.py --import-mode=importlib -q
```

Expected: fail while `audit.py` imports `fcntl` at module load.

- [x] **Step 3: Add minimal lock abstraction**

Move `fcntl` import behind a function or small context manager. Unsupported platforms may raise a clear runtime error when appending if no safe lock is available. Do not claim Windows support unless append behavior is tested there.

- [x] **Step 4: Run GREEN and regression tests**

Run:

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests/test_audit_portability.py packages/gove-zone/tests/test_cli.py packages/gove-zone/tests/test_kernel_dispatch.py --import-mode=importlib -q
```

Expected: pass.

## Task 4: Verification Drift Guards

- [x] **Step 1: Tighten Node 24 guard test first**

Update `tests/test_node24_gate.py` to require a clear fail-fast message and a Makefile surface that does not silently use Node 22 for acgi-ai readiness claims.

- [x] **Step 2: Run RED/GREEN for Node guard**

Run:

```bash
uv run python -m pytest tests/test_node24_gate.py --import-mode=importlib -q
```

- [x] **Step 3: Lock `clinicalguard` conditional status**

Update `scripts/check_governance_stack_index.py` and `docs/governance-stack-index.md` if needed so the index explicitly says parent CI skips `clinicalguard` unless initialized and must not count that as clinical deploy readiness.

- [x] **Step 4: Lock typecheck signal separation**

Update `tests/test_root_typecheck_gate.py` only if `Makefile` wording does not clearly separate configured strict mypy from skipped/unconfigured packages.

- [x] **Step 5: Lock enterprise adjunct status**

Ensure `docs/governance-stack-index.md` keeps `acgs-enterprise-ai-manager/frontend/` as build-proof-only, deferred/archive-or-integrate, and not a readiness source of truth.

## Task 5: Final Verification Packet

- [x] **Step 1: Run targeted gates**

Run:

```bash
pnpm -F acgi-ai run test:auth-boundary
uv run --package gove-zone python -m pytest packages/gove-zone/tests/test_audit_portability.py packages/gove-zone/tests/test_cli.py packages/gove-zone/tests/test_kernel_dispatch.py --import-mode=importlib -q
uv run python -m pytest tests/test_node24_gate.py tests/test_root_typecheck_gate.py --import-mode=importlib -q
make lint-docs
```

- [x] **Step 2: Run readiness evidence gates**

Run:

```bash
make platform-readiness
make release-evidence
```

Run `make verify-js-node24` only if the local host has `fnm` and Node 24 available; otherwise record the exact blocker.

- [x] **Step 3: Write `docs/readiness-evidence-packet-2026-05-25.md`**

Include:

```markdown
## Commands Run
## Environment
## Pass/Fail Results
## Known Limitations
## Remaining Blockers
## Claims Supported Now
## Claims Still Unsupported
## Advisor Opinion vs Current Verification
```

## Self-Review

- Spec coverage: ledger is complete before code changes; matrix, auth test, audit portability test, drift guards, and final evidence packet are mapped to tasks.
- Placeholder scan: no TODO/TBD placeholders are used as implementation instructions.
- Type/contract consistency: Node tasks stay in root/acgi-ai; audit portability stays in `packages/gove-zone`; governance/status tasks stay in docs/root scripts.

## Completion note — 2026-05-25 refresh

This plan has been executed and the durable evidence packet was refreshed for the
current `feat/agent-bus-analyzer` checkout. The current local readiness snapshot
is `30/31 pass`, `0 fail`, `1 pending`; production launch remains blocked on
external deployment, auth, assurance, accessibility, and hosted Storybook proof.
