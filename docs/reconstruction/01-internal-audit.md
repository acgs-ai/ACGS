# Internal Audit — ACGS / govern-zone Monorepo

> Platform-reconstruction program, document 1 of 6.
> Basis: origin/master tree (commit `34137f6`), audited 2026-07-05 by four parallel
> read-only audit lanes (core packages, satellite packages, frontend + CI/deploy,
> docs/roadmaps). Method: package manifests + README/CLAUDE/AGENTS first, then
> source structure, sampled modules, TODO/FIXME grep, test counts, CI cross-reference.

## 1. What this project is

Identity (README.md, llms.txt): a **vendor-neutral, receipt-gated governance layer for
AI-agent side effects**. It sits at the executor boundary below any agent framework,
enforces policy before execution, emits a verifiable Decision Receipt, and makes
executors fail closed without a valid receipt.

Core invariant, verbatim across README / ARCHITECTURE / SECURITY_MODEL /
DECISION_RECEIPT_SPEC: **No valid Decision Receipt, no side effect.**

Self-declared status: alpha (`0.1.0.dev0` / `0.1.0a1`), explicitly **not**
production-certified. `docs/CLAIMS.md` maintains a 30-row claim→evidence→safe-wording
ledger with explicit "not claimed" rows — the knowledge surface is unusually honest
and self-auditing.

## 2. Package inventory and layer map

| Surface | Layer | Maturity signal | CI gate | Audit verdict |
|---|---|---|---|---|
| `packages/gove-zone/` | **Kernel** (policy, receipts, audit, signing, executor, adapters) | 41 modules / ~13.2k LOC, 67 test files / 634 tests, 0 TODO, 90% cov floor | ruff + mypy strict + pytest (3.11/3.12) | Keep — platform core |
| `packages/acgs-lite/` (submodule) | Shared governance lib | PyPI v2.10.1, py≥3.10 floor | lint+pytest (3.10–3.12), PAT-gated | Keep — published base of swarm/clinical spine |
| `packages/Acgs-Swarm/` (submodule) | Research (swarm) | depends acgs-lite≥2.8.1 | lint+pytest, PAT-gated | Keep as research |
| `packages/clinicalguard/` (submodule, private) | Domain agent (clinical) | private; CI soft-fails w/o PAT | best-effort | Keep; fix soft-fail gate |
| `acgs_governance_eval_mvp/` | **Eval** | 102 .py / 14.2k LOC, 36 test files | doubly gated (eval.yml + python-eval-mvp.yml) | Keep as core eval engine |
| `packages/agent-bus-analyzer/` | **Observability** | 48 .py / 6.4k LOC, 31 test files, mypy, Dockerfile + Cloud Run deploy artifacts | lint+mypy+test+OpenAPI smoke | Keep as core observability |
| `acgs-cft-governance-pack/` | Integrations (Terraform/GCP) | 17 .py / 915 LOC, 8 test files, 0 TODO | lint+test+CLI smoke | Keep as plugin |
| `hermes_acgs_bundle/` | Integrations (Hermes) | 4 .py / 1.2k LOC, 2 test files, no README | **test-only CI** (no lint/mypy) | Merge into eval-mvp as host adapter |
| `packages/research-engine/` (delve) | Research tooling | 23 .py / 2.2k LOC, py.typed, mypy strict | full gate | Keep as plugin (off-mission) |
| `packages/ai-governance-research/` | Research knowledge base | Markdown + Makefile, no code | none (correct) | Fold into docs/ |
| `acgs-enterprise-ai-manager/` | Frontend (orphan) | Vue 3 skeleton, **no backend, no tests, no CI** | **none** | **Archive** |
| `automation/` | Ops | 5 .py / 816 LOC; proposals/approved/workflows dirs **empty** | indirect (tests-root) | Dormant plugin |
| `acgi-ai/` | **Console + marketing frontend** | React 19/Vite; ~70 gate scripts; 2 real deploy pipelines | test:all (~55 gates) + deploys | Keep — the product surface |
| `experiments/iii-governance-lab/` | Experiment (edge governance) | TS worker + Python worker, static CI | static gate | Keep as experiment |
| `external/*` (4 submodules) | Vendored | unpopulated pins | none | Keep as pins |

Layer map that falls out of the audit: **kernel** (gove-zone) · **shared lib spine**
(acgs-lite → Acgs-Swarm / clinicalguard) · **eval** (eval-mvp) · **observability**
(agent-bus-analyzer) · **integrations** (cft-pack, hermes, MCP gateway, framework
adapters) · **research** (research-engine, ai-governance-research) · **ops**
(automation, scripts, workflows) · **frontend** (acgi-ai marketing + console).

## 3. The kernel (gove-zone) in detail

Strongest asset in the estate:

- Fail-closed governance plane: policy (`policy.py`, `yaml_policy.py`), receipts
  (`receipt.py`, `decision.py`, `consumption.py`), hash-chained audit + replay
  (`audit.py`, `replay*.py`), signing/verification (`signing.py`, `verifier.py`),
  execution gates (`executor.py`, `kernel.py`, `integration.py`), integrations
  (`adapters/` autogen/langgraph/mcp_gateway, `a2a.py`, `mcp.py`, `tenant.py`,
  `sandbox.py`).
- **Zero runtime dependencies** by design (stdlib only; crypto/pydantic/yaml/langchain/mcp
  as lazy optional extras). Zero TODO/FIXME/NotImplementedError in `src/`.
- CI is the most rigorous gate in the repo: ruff check + format, mypy `--strict`,
  pytest with `--cov-fail-under=90`, 3.11/3.12 matrix.
- Debt: version skew (`pyproject.toml` `0.1.0a1` vs README `0.1.0.dev0`); largest
  modules trending big (`cli.py` 1152 LOC, `consumption.py` 999, `mcp_gateway.py` 876);
  bare install runs with reduced guarantees unless deployer pins `crypto`/`schema` extras.

**Structural fact for the blueprint:** gove-zone imports nothing from any sibling
package — a leaf in the dependency graph, hub in the conceptual graph. Two independent
"governance/receipt" lineages coexist (gove-zone `Receipt`/`DecisionReceipt` vs
acgs-lite primitives) with no code-level link. Unify-or-separate is a top blueprint
decision (needs acgs-lite source checkout to settle).

## 4. Cross-cutting duplication (consolidation candidates)

1. **Pre/post-tool governance gate implemented 3×** — eval-mvp `governed_mcp_v0`
   (canonical), hermes bundle (Hermes host), cft-pack (Terraform host). Extract one
   gate/evidence core; make hosts thin adapters.
2. **Chain-hashed JSONL evidence writers duplicated ~4×** (eval-mvp, hermes, cft-pack,
   plus kernel's own audit chain) — and agent-bus-analyzer already consumes this shape.
   One evidence/Merkle library is the obvious shared primitive.
3. **Demo consoles scattered** — 3 static HTML panels + 1 orphan Vue app; the real
   console lives in acgi-ai. Consolidate or archive.
4. **Uneven per-package CI templates** — hermes is test-only while peers run
   mypy-strict. Normalize the gate template.
5. **Research pair** — research-engine (code) + ai-governance-research (docs) belong
   together in a research plugin ring, off the critical path.

## 5. Frontend and deployment reality

`acgi-ai/` is a build-time split into two bundles: public **marketing** (Cloudflare
Pages, report-only CSP, **hard 200 KiB gzip budget ~95% consumed**) and privileged
**console** (GCP Cloud Run via WIF, Caddy-served, enforced CSP `script-src 'self'`,
fail-closed `AUTH_UPSTREAM`, 350 KiB budget). ~70 `check-*.mjs` contract gates chained
into `test:all` (~55 serial gates).

Deployment reality across the whole estate:

- **Only two deploy pipelines exist** (marketing → CF Pages; console → Cloud Run).
  Every Python package is merge-only; acgs-lite's PyPI publish is manual.
- Both deploys are push-to-master only and reference a GitHub `production`
  environment that workflow headers admit is **decorative until a human creates it
  with required reviewers** — the human gate may be unarmed.
- **Single self-hosted runner is the SPOF**: nearly all 23 workflows AND both deploys
  run on one box; timeouts already bumped 15→30 min under contention; Playwright deps
  hand-provisioned.
- **No staging environment is deployed** (`service.staging.yaml` / `service.preview.yaml`
  exist unused); no IaC for the CF Pages project or GCP WIF pool.
- `acgs-enterprise-ai-manager/frontend` is a pnpm workspace member with **no CI gate at all**.
- agent-bus-analyzer has Cloud Run deploy artifacts but no deploy workflow.

## 6. Test estate and sealed surfaces

- Root `tests/` = 14 invariant/readiness guards + `tests/docs/` smoke; the historical
  root-tests CI gap is **closed** (tests-root.yml + hosted twin). Caveat: five
  readiness/evidence tests (`test_platform_readiness_report`,
  `test_release_evidence_bundle`, `test_production_blocker_evidence`,
  `test_production_launch_preflight`, `test_readiness_evidence_boundaries`) are
  `--ignore`d and run in **no CI**.
- `docs/constitutional-hashes.lock`: 222 entries pinned to `608508a9bd224290`, all in
  nested repos (acgs-lite, clinicalguard). The **parent-tracked hash inventory is
  empty**, so the constitutional-hash CI gate is a no-op today; clinicalguard's hash
  verification is advisory when the PAT lacks scope.
- Typecheck policy is deliberately two-tier: strict-gated = gove-zone,
  agent-bus-analyzer, research-engine; all others informational-only.

## 7. Documented intent vs reality — gap register

| # | Gap | Severity for reconstruction |
|---|---|---|
| 1 | "Verifiable reference monitor" asserted by tests, not proof; formal track (TLA+, real Z3) unbuilt — current Z3 is an unwired stub in eval-mvp | High — G1b gate |
| 2 | "Trustless / third-party verifiable" north star has zero transparency-log / external-verifier code (G2 `[proposed]`) | High |
| 3 | Constitutional-hash CI guards an empty parent inventory (no-op control) | High — reads as active control |
| 4 | Single-use receipts + signing implemented but **opt-in / off by default**; bare `DecisionReceipt.verify()` defaults `require_signature=False` | High — invariant binds only if integrator wires it |
| 5 | Roadmap sprawl: 3 root roadmaps + docs/ROADMAP.md + 3 overlapping PLAN docs, none archived; no phase marked done despite kernel being ~built | Medium |
| 6 | Stale pointers: root ROADMAP + parent CLAUDE.md cite a root `PLAN.md` that does not exist; parent CLAUDE.md layout table omits 4 real packages incl. gove-zone | Medium — misdirects agents/contributors |
| 7 | AUTHZ-ROADMAP rests on a single-author unreplicated preprint (arXiv:2605.05440); validating week-2 benchmark gate never run | Medium |
| 8 | Docs/code imbalance: 147 markdown vs 94 package .py files at parent level | Low |
| 9 | Clinicalguard CI soft-fails without PAT — a red private package can pass CI silently | Medium |
| 10 | gove-zone version string skew (`0.1.0a1` vs `0.1.0.dev0`) | Low |

## 8. Inputs handed to the reconstruction blueprint (doc 04)

1. The platform already has a de-facto layer architecture (§2); reconstruction is
   mostly **formalizing + consolidating**, not rebuilding. The kernel is solid.
2. Decide the **two-lineage question**: gove-zone kernel vs acgs-lite spine —
   unify receipt primitives or declare acgs-lite the published SDK and gove-zone the
   enforcement kernel with a receipt-format contract between them.
3. Extract the **shared evidence/receipt-chain library** (consolidation #2) — it is
   the platform's common denominator and the emerging-standards attachment point.
4. Production path requires: staging env, IaC for deploy prereqs, ≥1 more CI runner,
   armed `production` environment reviewers, deploy pipeline for agent-bus-analyzer,
   packaging/publish automation for Python packages.
5. Defaults hardening: signing + single-use receipts on by default (or a loud
   "dev-mode" banner), populate or remove the constitutional-hash parent gate,
   un-ignore the readiness tests in CI.
6. Estate hygiene: archive orphan Vue app, merge hermes into eval-mvp, normalize CI
   templates, create docs/archive/ and collapse the plan/roadmap sprawl to one
   roadmap of record.
