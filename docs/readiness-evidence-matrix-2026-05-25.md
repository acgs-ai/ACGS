# govern-zone Readiness Evidence Matrix — 2026-05-25

Scope: `/home/martin/finished work/govern-zone` on branch
`feat/acgs-conductor-adapter-spike`.

This matrix separates evidence by environment and assurance domain. It is not a
production, compliance, security, or accessibility attestation. Local green
checks are local readiness evidence only.

## Evidence Matrix

| Area | Environment/domain | Current evidence | Verification command/source | Confidence | Not proven | Required next proof |
|---|---|---|---|---|---|---|
| Workspace state | Local | Root ledger freezes current dirty state: 211 dirty paths, 93 tracked dirty, 118 untracked; initialized registered submodules reported clean; `packages/clinicalguard` unavailable | `docs/readiness-baseline-workspace-ledger-2026-05-25.md`; `git status --short`; `git submodule status --recursive`; `git submodule foreach --recursive 'git status --porcelain=v1 \| wc -l'` | High for current checkout snapshot | Ownership of every pre-existing dirty file; whether all dirty files are intended for one change set | Owner-specific diff review before staging or committing any non-baseline file |
| Root local gates | Local | Root Makefile exposes `verify`, `platform-readiness`, `release-evidence`, and `verify-js-node24`; existing docs say these are readiness evidence | `Makefile`; `README.md`; `docs/integration-readiness-task-map.md`; future rerun in final evidence packet | Medium until rerun after this goal's changes | That all local gates still pass after new tests/fixes | Fresh command output from this session after targeted changes |
| Frontend console | Local | `acgi-ai` has static gates for auth boundary, router, session sync, CSP, performance, production evidence templates, and readiness scripts | `acgi-ai/package.json`; `acgi-ai/scripts/check-auth-boundary.mjs`; `acgi-ai/scripts/check-router-contract.mjs`; `pnpm -F acgi-ai run test:all` | Medium until targeted auth contract rerun | Browser-rendered behavior, live Cloud Run behavior, credentialed auth status | Targeted auth-boundary test plus rendered browser/postdeploy evidence for deployment claims |
| Console auth | Production boundary | Caddy `forward_auth` and `AUTH_UPSTREAM` are represented in static checks; SPA route guard still depends on `hasSession()` | `acgi-ai/infra/Caddyfile`; `acgi-ai/src/surfaces/console/App.tsx`; `acgi-ai/src/lib/session.ts`; `pnpm -F acgi-ai run test:auth-boundary` | Medium-low until contract test is tightened | That a production operator can enter `/console` after edge auth without a demo session | Explicit production session/status contract and live deploy proof from authenticated console route |
| Runtime kernel audit | Local | `packages/gove-zone` has hash-chain audit tests and CLI replay tests; `audit.py` currently imports `fcntl` at module load | `packages/gove-zone/src/gove_zone/audit.py`; `packages/gove-zone/tests/test_cli.py`; `packages/gove-zone/tests/test_kernel_dispatch.py` | Medium until portability test is added | Import behavior on non-POSIX platforms; Windows append support | Import portability test and, separately, real Windows CI if Windows support is claimed |
| Node toolchain | Local | `acgi-ai/package.json` requires Node `>=24 <25`; `scripts/run_acgi_node24_gate.sh` activates Node 24 via `fnm` | `tests/test_node24_gate.py`; `scripts/run_acgi_node24_gate.sh`; `make verify-js-node24` | Medium | That every developer shell fails fast before any Node 22 readiness claim | Fresh Node 24 gate run or recorded host blocker; explicit guard wording |
| Python typecheck | Local | Root `typecheck-py` runs every registered package's configured mypy scope, now including the strict `packages/Acgs-Swarm` core-primitives source scope | `Makefile`; `tests/test_root_typecheck_gate.py`; `acgs-cft-governance-pack/pyproject.toml`; `acgs_governance_eval_mvp/pyproject.toml`; `packages/Acgs-Swarm/pyproject.toml` | Medium | Full strict typing across every optional/research/script/test surface | Separate scope-widening of `packages/Acgs-Swarm` optional runtime, research, script, and test modules |
| `clinicalguard` | Clinical/private submodule | `.gitmodules` pins `packages/clinicalguard`; current checkout has no `.git` marker and submodule status has leading `-` | `git submodule status --recursive`; `MONOREPO.md`; `.github/workflows/python-clinicalguard.yml`; `docs/governance-stack-index.md` | High for unavailable-current-checkout status | Clinical deploy readiness, PHI/privacy runtime behavior, professional-review evidence | Initialize with valid `SUBMODULE_TOKEN`, run package-local clinical gates, collect owner evidence |
| Enterprise admin adjunct | Local build only | `acgs-enterprise-ai-manager/frontend/` is a pnpm workspace member and documented as build-proof-only legacy/admin adjunct | `pnpm-workspace.yaml`; `MONOREPO.md`; `docs/governance-stack-index.md` | Medium | That the adjunct consumes shared evidence APIs or is safe as a source of truth | Decision record: archive, defer, or integrate with shared evidence API; then package-local gate |
| Staging deployment | Staging | Cloud Run service templates and render checks exist for preview/staging/production manifests | `acgi-ai/infra/cloudrun/service.staging.yaml`; `acgi-ai/scripts/render-cloudrun-service.mjs`; `pnpm -F acgi-ai run test:cloudrun-renderer` | Low until credentialed deploy | Actual staged revision health, headers, auth, assets, browser routes | Credentialed staging deploy, postdeploy verifier output, rendered browser/API evidence |
| Production deployment | Production | Production evidence template, live verifier, blocker report, and cutover plan scaffolds exist | `acgi-ai/production-evidence.example.json`; `acgi-ai/scripts/verify-production-live.mjs`; `acgi-ai/scripts/build-production-blocker-report.mjs`; `make release-evidence` | Low until live artifacts exist | Live production deploy, DNS, Cloud Run/Vercel revision, served asset integrity, authenticated console access | Completed production evidence manifest plus live verifier JSON and postdeploy logs |
| Legal/compliance | Legal/compliance | Claim matrix and claim-safe docs exist; docs explicitly require legal review for stronger claims | `acgi-ai/claim-matrix.json`; `acgi-ai/CLAIM_VALIDATION.md`; `docs/governance-stack-index.md` | Medium for engineering claim discipline | Legal signoff, SOC 2 audit, regulator validation, domain-specific legal review | Signed legal/compliance review artifact from authorized reviewer |
| Security | Security | Static security invariants, CSP checks, auth-boundary checks, security page, and security.txt exist | `pnpm -F acgi-ai run test:security`; `pnpm -F acgi-ai run test:csp`; `acgi-ai/public/.well-known/security.txt` | Medium for local static checks | Third-party pentest, vulnerability management attestation, runtime exploit resistance | External security review/pentest report and remediation evidence |
| Accessibility | Accessibility | Static accessibility foundation check and A11Y doc exist | `acgi-ai/A11Y.md`; `pnpm -F acgi-ai run test:a11y` | Medium for static foundation only | Manual screen-reader evidence, full WCAG conformance, rendered browser accessibility behavior | Manual assistive-tech test report and browser-based accessibility audit |
| Browser/user evidence | Local scaffold | E2E HTTP shell, visual baseline foundation, buyer evidence gallery, and Storybook publication scaffold exist | `pnpm -F acgi-ai run test:e2e-http`; `pnpm -F acgi-ai run test:visual`; `pnpm -F acgi-ai run test:buyer-evidence`; `pnpm -F acgi-ai run test:storybook-publication` | Medium for scaffold, low for browser reality | Real browser rendering, screenshots, hosted Storybook, visual regression results | Playwright/browser screenshots, hosted buyer evidence URL, visual diff artifacts |

## Current Supported Claims

- The repository has a documented local readiness fan-out and claim-safe evidence
  vocabulary.
- The current workspace is dirty and must be treated as mixed WIP until staged
  narrowly.
- Local checks can support local readiness claims only after they are rerun in
  this session.
- `packages/clinicalguard` is not available in this checkout and must not be
  counted as parent-verified.

## Unsupported Claims

- Live production deployment completed.
- Legal/compliance approval completed.
- External security validation completed.
- Full WCAG conformance completed.
- Windows runtime support for `gove-zone` audit append behavior.
- Hosted buyer evidence or rendered browser proof completed.
