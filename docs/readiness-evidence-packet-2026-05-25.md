# govern-zone Readiness Evidence Packet — 2026-05-25

Scope: `/home/martin/finished work/govern-zone`

Branch: `feat/agent-bus-analyzer`

Freshness rule: treat this packet as current only after rerunning the generated readiness, release-evidence, and preflight commands on the target commit.

This packet records current verification evidence for the readiness-baseline and
production-launch preparation work. It separates local proof from external proof
and does not claim live production deployment, legal approval, security
validation, SOC2 assurance, regulatory approval, or full accessibility
conformance.

## Environment

| Item | Value |
|---|---|
| Shell default Node | `v22.19.0` |
| pnpm | `9.15.4` |
| Python | `3.14.4` |
| uv | `0.11.7` |
| Root branch | `feat/agent-bus-analyzer` |
| Root status at snapshot | Clean: `git status --short` returned 0 entries |
| Initialized registered submodules | Clean: UI-TARS, everything-claude-code, natural_language_autoencoders, Acgs-Swarm, acgs-lite all reported 0 dirty paths |
| `packages/Acgs-Swarm` pointer | `fa9fcd6` with strict core-primitives mypy gate |
| `packages/clinicalguard` | Registered but uninitialized/unavailable in this checkout (`git submodule status` leading `-`) |

## Commands Run

| Command | Result | Evidence |
|---|---|---|
| `git status --short --branch` | Pass | `## feat/agent-bus-analyzer`; no dirty entries before this packet refresh |
| `git submodule status --recursive` | Pass for inspection | Initialized submodules present and clean; `packages/clinicalguard` remains uninitialized |
| `git submodule foreach --recursive 'printf "%s " "$name"; git status --porcelain=v1 \| wc -l'` | Pass | Initialized registered submodules each reported `0` dirty paths |
| `make platform-readiness` | Pass with pending external item | `33/34 pass`, `0 fail`, `1 pending`; pending item is `hosted-storybook-buyer-evidence` |
| `make release-evidence` | Pass with pending external item | Bundle written to `dist-release-evidence`; `33/34 pass`, `0 fail`, `1 pending` |
| `make production-launch-preflight` | Blocked as expected | Current clean commit; readiness `33/34 pass`, `0 fail`, `1 pending`; live verifier still fail; external proof blockers remain |
| `make verify` | Pass | Full root JS/Python lint/type/test fan-out completed after the Acgs-Swarm strict core mypy change |
| `uv run python -m pytest tests/test_root_typecheck_gate.py -q` | Pass | `4 passed`; includes Acgs-Swarm strict core mypy gate check |
| `cd packages/Acgs-Swarm && uv run mypy` | Pass | `Success: no issues found in 16 source files` |
| `cd packages/Acgs-Swarm && uv run python -m pytest tests/test_governance_receipts.py --import-mode=importlib -q` | Pass | `97 passed` |
| `pnpm -F acgi-ai run build:console && pnpm -F acgi-ai run test:auth-boundary` | Pass | Production console bundle built and the auth-boundary gate passed after `/auth/status` bridge wiring; live provider/session proof still requires deployed edge/server evidence |
| `pnpm -F acgi-ai run test:security && pnpm -F acgi-ai run test:session-sync && pnpm -F acgi-ai run test:cloudrun-renderer` | Pass | Security invariants, demo-session sync, and deploy renderer contracts still pass with the production session bridge |
| `uv run python -m pytest tests/test_platform_readiness_report.py tests/test_readiness_evidence_boundaries.py tests/test_production_launch_preflight.py --import-mode=importlib -q` | Pass | `12 passed`; readiness/preflight tests accept the updated auth boundary |
| `uv run --package gove-zone python -m pytest packages/gove-zone/tests/test_audit_portability.py packages/gove-zone/tests/test_cli.py packages/gove-zone/tests/test_kernel_dispatch.py --import-mode=importlib -q` | Pass in prior readiness-baseline run | `10 passed`; import portability is proven, not Windows append support |
| `make verify-js-node24` | Pass | Wrapper used Node `v24.15.0`, pnpm `9.15.4`, and completed full `pnpm -F acgi-ai run test:all` after the Storybook runtime phrase fix |

## Changes Represented By Current Evidence

| Area | Current state |
|---|---|
| Release evidence | Local evidence bundle now reports `33/34 pass`, `0 fail`, `1 pending` |
| Typecheck fan-out | Every registered Python package has a configured mypy gate; Acgs-Swarm now contributes a strict core-primitives source scope |
| Production preflight | Local preflight reports clean/stale status, readiness summary, live verifier status, evidence-chain consistency, and external blocker IDs |
| Console deployment/auth | Static fail-closed Cloud Run, Caddy, and auth-boundary contracts exist; `/auth/status` now gives the production SPA route guard a same-origin forward-auth session bridge; live auth behavior remains unproven |
| Runtime framework bridge | `gove-zone` normalizes common agent-framework tool-call shapes and can enforce reviewed policy bundles before side effects |
| Hosted buyer evidence | Local buyer-evidence gallery, Storybook publication scaffold, and hosted Storybook handoff exist; live Storybook proof remains pending |

## Known Limitations

- No credentialed staging or production deployment was performed in this packet refresh.
- `packages/clinicalguard` is not initialized, so parent verification does not prove clinical-domain readiness.
- `gove-zone` import no longer requires `fcntl`, but append behavior on platforms without a safe file-lock primitive is not claimed as supported.
- The default shell Node is `v22.19.0`; Node 24 remains the required frontend release toolchain, and the Node 24 wrapper was rerun successfully for this refresh.
- Hosted Storybook buyer evidence remains pending until official/runtime or equivalent hosted proof, DNS/HTTPS, and live manifest verification exist.
- No legal review, SOC2 audit, third-party penetration test, regulatory review, or manual accessibility/screen-reader review was performed.

## Remaining Blockers

| Blocker | Status | Required proof |
|---|---|---|
| Production deployment | Not proven | Credentialed Vercel/Cloud Run deploy, workflow run URLs, postdeploy verifier output, DNS/HTTPS/header/assets evidence, browser/API proof |
| Production console authenticated access | Local contracts only | Edge/server auth status bridge evidence from deployed `/console` route and authenticated operator flow |
| Legal/compliance | Not proven | Authorized legal/compliance review artifact for public claim matrix and domain claims |
| Third-party security validation | Not proven | Independent security review or penetration-test report plus remediation evidence |
| Accessibility | Static foundation only | Manual screen-reader/WCAG review and rendered-browser accessibility evidence |
| Hosted Storybook buyer evidence | Pending | Live `storybook.acgs.ai` DNS/HTTPS and `/manifest.json` proof with expected buyer-evidence stories and conservative claim boundary |
| Clinical vertical | Not proven | Initialize `packages/clinicalguard`, run package-local gates, collect clinical/PHI owner evidence |

## Claims Supported Now

- The current root checkout was clean before this packet refresh.
- Initialized registered submodules were clean before this packet refresh; `packages/clinicalguard` remained uninitialized.
- Local readiness evidence regenerated successfully: `33/34 pass`, `0 fail`, `1 pending`.
- Full local verification passed after the Acgs-Swarm strict core mypy update.
- The production console SPA no longer depends on demo `hasSession()` after edge auth; it awaits `/auth/status`, which Caddy serves only after `AUTH_UPSTREAM` accepts the request.
- Production launch preflight correctly remains blocked until live deploy, auth, assurance, accessibility, and hosted Storybook proof are attached.
- The repo has machine-readable local handoffs for production authority, live verification, blocker reporting, cutover planning, production evidence drafting/validation, and hosted Storybook proof collection.

## Claims Still Unsupported

- Live production is deployed and verified.
- The project is legally approved, SOC2-audited, regulator-reviewed, or compliance-approved.
- The project has completed independent security validation.
- The UI has completed full manual accessibility conformance review.
- `gove-zone` supports Windows audit append behavior.
- `packages/clinicalguard` is verified by the parent checkout.
- Hosted Storybook buyer evidence is live.
