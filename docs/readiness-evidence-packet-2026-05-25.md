# govern-zone Readiness Evidence Packet — 2026-05-25

Scope: `/home/martin/finished work/govern-zone`

Branch: `feat/acgs-conductor-adapter-spike`

This packet records current verification evidence for the readiness-baseline
stabilization pass. It separates fresh command evidence from advisor opinion and
does not claim live production deployment, legal approval, security validation,
or full accessibility conformance.

## Environment

| Item | Value |
|---|---|
| Shell default Node | `v22.19.0` |
| Exact frontend readiness Node | `v24.15.0` through `fnm` |
| pnpm | `9.15.4` |
| Python | `3.14.4` |
| uv | `0.11.7` |
| Initial root dirty state | 211 dirty paths: 93 tracked dirty, 118 untracked |
| Post-run root dirty state | 219 dirty paths: 94 tracked dirty, 125 untracked |
| Registered initialized submodules | Clean during ledger collection |
| `packages/clinicalguard` | Uninitialized/unavailable in this checkout |

## Commands Run

| Command | Result | Evidence |
|---|---|---|
| `git status --short` | Pass for inspection; dirty state recorded | Root had broad dirty state before changes; no destructive cleanup performed |
| `git submodule status --recursive` | Pass for inspection | Registered public/external submodules visible; `packages/clinicalguard` unavailable |
| `git submodule foreach --recursive 'echo $name; git status --porcelain=v1 \| wc -l'` | Pass | Initialized registered submodules reported 0 dirty paths |
| `rg -n "production-ready\|compliance-ready\|security-certified\|WCAG certified\|regulator-grade\|GA" docs/readiness-evidence-matrix-2026-05-25.md` | Pass by no matches | Evidence matrix avoids banned overclaim terms |
| `pnpm -F acgi-ai run test:auth-boundary` | Pass | Auth boundary contract check passed; shell default emitted Node 22 warning, so this is targeted local contract evidence only |
| `uv run --package gove-zone python -m pytest packages/gove-zone/tests/test_audit_portability.py packages/gove-zone/tests/test_cli.py packages/gove-zone/tests/test_kernel_dispatch.py --import-mode=importlib -q` | Pass | `10 passed` |
| `uv run python -m pytest tests/test_node24_gate.py tests/test_root_typecheck_gate.py tests/test_readiness_evidence_boundaries.py --import-mode=importlib -q` | Pass | `6 passed` |
| `make lint-docs` | Pass | Governance stack index check passed |
| `make platform-readiness` | Pass with pending item | `24/25 pass`, `0 fail`, `1 pending`; pending item is hosted Storybook buyer evidence |
| `make release-evidence` | Pass with pending item | Bundle written to `dist-release-evidence` with `24/25 pass`, `0 fail`, `1 pending` |
| `make verify-js-node24` | Pass | Wrapper used Node `v24.15.0`, pnpm `9.15.4`, and completed full `pnpm -F acgi-ai run test:all` |
| `uv run ruff check packages/gove-zone/src/gove_zone/audit.py packages/gove-zone/tests/test_audit_portability.py` | Pass | Ruff clean |
| `(cd packages/gove-zone && uv run mypy src tests/test_audit_portability.py)` | Pass | No issues found in 17 source files |
| `git diff --check` | Pass | No whitespace errors |

## Changes Made In This Pass

| File | Purpose |
|---|---|
| `docs/readiness-baseline-workspace-ledger-2026-05-25.md` | Freezes root and nested repo ownership/status before code changes |
| `docs/readiness-evidence-matrix-2026-05-25.md` | Separates Local, Staging, Production, Legal/compliance, Security, Accessibility, Clinical, Enterprise, and Browser evidence |
| `docs/superpowers/plans/2026-05-25-readiness-baseline-stabilization.md` | Records the task-by-task execution plan |
| `acgi-ai/scripts/check-auth-boundary.mjs` | Adds a static contract check that `/console` production access must name an edge/server session-status bridge |
| `acgi-ai/src/lib/session.ts` | Adds an explicit production session/status contract string without changing demo-session behavior |
| `packages/gove-zone/tests/test_audit_portability.py` | Proves `gove_zone.audit` import does not require `fcntl` at module load |
| `packages/gove-zone/src/gove_zone/audit.py` | Moves `fcntl` behind a minimal lock context so import is portable; append still requires a platform lock primitive |
| `tests/test_readiness_evidence_boundaries.py` | Locks Node 22 warning language, clinicalguard skip semantics, enterprise adjunct status, and baseline docs |
| `docs/integration-readiness-task-map.md` | Clarifies Node 22 warning is not readiness evidence |
| `docs/governance-stack-index.md` | Clarifies clinicalguard parent-CI skip is not clinical verification and enterprise adjunct is build-proof-only until archived or integrated |

## Known Limitations

- The workspace remains dirty by design; unrelated pre-existing WIP was left untouched.
- `packages/clinicalguard` is not initialized, so parent verification does not prove clinical-domain readiness.
- `gove-zone` import no longer requires `fcntl`, but append behavior on platforms without `fcntl` is still a documented block, not Windows support.
- `pnpm -F acgi-ai run test:auth-boundary` under shell-default Node 22 is only targeted static contract evidence; frontend readiness evidence comes from `make verify-js-node24`.
- Hosted Storybook buyer evidence remains pending.
- No credentialed staging or production deployment was performed.
- No legal review, third-party security review, or manual accessibility review was performed.

## Remaining Blockers

| Blocker | Status | Required proof |
|---|---|---|
| Hosted Storybook buyer evidence | Pending | Official Storybook runtime or equivalent hosted buyer-evidence URL plus live manifest proof |
| Production deployment | Not proven | Credentialed deploy, postdeploy verifier output, DNS/HTTPS/headers/assets evidence, browser/API proof |
| Production console authenticated access | Contract clarified, live behavior not proven | Edge/server auth status bridge evidence from deployed console route |
| Clinical vertical | Not proven | Initialize `packages/clinicalguard`, run package-local gates, collect owner evidence |
| Legal/compliance | Not proven | Authorized legal/compliance review artifact |
| Security validation | Not proven beyond local static checks | External security review or pentest report |
| Accessibility | Static foundation only | Manual screen-reader and rendered-browser accessibility evidence |

## Claims Supported Now

- The current workspace state has been documented before readiness-baseline code changes.
- Evidence claims are separated by Local, Staging, Production, Legal/compliance, Security, Accessibility, Clinical, Enterprise, and Browser domains.
- `/console` auth-boundary checks now require an explicit production session/status contract rather than relying only on demo sessionStorage semantics.
- `gove_zone.audit` can be imported when `fcntl` is unavailable at module import time.
- Node 22 warning output is no longer treated as readiness evidence in the readiness docs.
- `clinicalguard` and enterprise admin adjunct readiness status are explicit and claim-safe.
- Local readiness evidence regenerated successfully: `24/25 pass`, `0 fail`, `1 pending`.
- Full frontend readiness suite passed under exact Node 24.

## Claims Still Unsupported

- Live production is deployed and verified.
- The project is legally approved or compliance-approved.
- The project has completed independent security validation.
- The UI has completed full manual accessibility conformance review.
- `gove-zone` supports Windows audit append behavior.
- `packages/clinicalguard` is verified by the parent checkout.
- Hosted Storybook buyer evidence is live.

## Advisor Opinion vs Current Verification

Claude and agy were used as advisory inputs only. Their findings helped
prioritize evidence boundaries, dirty-worktree risk, production console auth,
`fcntl` portability, Node drift, `clinicalguard`, and enterprise adjunct status.
The supported claims in this packet come only from current repository
inspection, files changed in this pass, and commands listed above.
