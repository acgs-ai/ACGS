# Governance stack index

Scope: `/home/martin/finished work/govern-zone` on branch
`feat/acgs-conductor-adapter-spike`.

Purpose: provide one routing surface for the platform's policy/evidence
contract, local verification owner, and deploy/live-proof caveat. This is a
claim-safe index for development and review. Local green gates are deployment
readiness evidence, not production evidence; live deployment proof is not complete until
credentialed deploy workflows, post-deploy checks, and rendered browser/API
evidence have run.

## Stack routing table

| Layer | Package/path | Policy/evidence contract | Primary local gate | Live/deploy proof status |
|---|---|---|---|---|
| Runtime kernel | `packages/gove-zone/` | fail-closed tool-call mediation, path/state policies, receipts, replay, hash-chain audit, local AgentDojo/InjecAgent/ToolEmu-style benchmark fixtures | `uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q`; `(cd packages/gove-zone && uv run mypy .)` | Local runtime and fixture evidence only; not deployed as a managed service in this checkout |
| Public library | `packages/acgs-lite/` | PyPI-facing governance API, legitimacy decisions, MACI separation, framework adapters, public API compatibility | `(cd packages/acgs-lite && make lint typecheck test)` through root fan-out | Published package surface exists, but this parent checkout does not prove a new release or production adoption |
| Multi-agent governance | `packages/Acgs-Swarm/` | Peer validation, signed votes, settlement evidence, trust dynamics, swarm governance receipts | `(cd packages/Acgs-Swarm && python -m pytest tests/ --import-mode=importlib)` through root fan-out | Local/research evidence only; public benchmark/replication claims stay separately qualified |
| Observer/evidence API | `packages/agent-bus-analyzer/` | Observer-only trace API, bus OpenAPI export, receipt proof packets, gove-zone audit-tail import, deployment signing metadata, Phoenix trace cross-links | `(cd packages/agent-bus-analyzer && PYTHONPATH=src python -m pytest --import-mode=importlib)`; schema export drift check | Cloud Run templates and postdeploy-smoke CLI exist; live smoke requires external credentials and a rendered revision |
| Evaluation MVP | `acgs_governance_eval_mvp/` | Hash-addressed evaluation report ingestion, claim-safe status, source-tagged benchmark evidence, tenant-scoped `/evidence/evaluation-reports` query | `(cd acgs_governance_eval_mvp && uv run python -m pytest --import-mode=importlib -q)` | Local API/evidence chain only unless deployed behind the console gateway |
| Buyer/operator interface | `acgi-ai/` | Privileged console, public trust surface, receipt proof journey, evaluation evidence cards, strict CSP/bundle/auth/deploy contracts | `pnpm -F acgi-ai test`; `pnpm -F acgi-ai build` | Local build/test proof only; production console proof still needs Cloud Run deploy, live asset checks, and browser screenshots |
| Infrastructure governance pack | `acgs-cft-governance-pack/` | Terraform/CFT plan governance and pre-apply evidence for infrastructure changes | `(cd acgs-cft-governance-pack && uv run python -m pytest --import-mode=importlib -q)` | Local pack evidence only; no live Terraform apply evidence here |
| Hermes/Phoenix integration | `hermes_acgs_bundle/` | External runtime-governance boundary, Phoenix/OpenTelemetry cross-links, governed trace bundles | Package-local pytest through root Python fan-out when enabled | Integration design and local traces only; no live collector proof in this checkout |
| Legal vertical | `ca-legal-agent-skills/` | Matter isolation, citation discipline, legal release gates, lawyer-review escalation, per-matter audit evidence | Path-local runtime/test gates owned by the legal package lane | Domain pack evidence is separate; do not make legal compliance claims from parent local tests |
| Legal runtime adjunct | `ACGS/packages/legalguard/` | Legal-domain agent/runtime adjunct; should consume shared receipts rather than creating a parallel truth source | `(cd ACGS/packages/legalguard && python -m pytest tests/ -v --import-mode=importlib)` when the ignored adjacent checkout is present | Ignored adjacent checkout, not parent-tracked by the root repo; package-owner local evidence only until promoted into the root registry/deploy surface |
| Clinical vertical | `clinicalguard-privacy-hardening/` and `packages/clinicalguard/` | PHI/privacy controls, clinical safety escalation, professional-review boundaries | Private submodule/path-filtered gate when initialized; parent CI needs `SUBMODULE_TOKEN`; parent CI skip is not clinical verification | Private checkout can be unavailable; do not claim clinical deploy readiness without live owner evidence |
| Enterprise admin adjunct | `acgs-enterprise-ai-manager/frontend/` | Candidate admin/CRUD surface; must not compete with the `acgi-ai` evidence console as source of truth | `pnpm -F acgs-enterprise-manager-frontend build` | Parent-tracked workspace member with build proof only; legacy/admin adjunct until owners archive or integrate with the shared evidence API |
| Parent orchestration | `MONOREPO.md`, `Makefile`, `.github/workflows/`, `docs/integration-readiness-task-map.md` | Registry of package ownership, CI routing, local gate fan-out, and caveats for claim-safe status reporting | `make verify`; `make lint-docs`; `python3 scripts/check_governance_stack_index.py` | Parent can prove local readiness and routing coherence, not independent live deployment |

## Evidence vocabulary

- **Policy owner**: the package that decides, denies, escalates, or records a
  governed action.
- **Evidence owner**: the package that stores or projects the receipt, report,
  trace, signature, or hash-chain record.
- **Gate owner**: the package-local command that proves the contract did not
  regress.
- **Live proof owner**: the deploy target or external service needed to prove
  that local evidence is served from a real rendered revision.

## Claim boundaries

- Use "local evidence", "claim-safe fixture evidence", "deployment readiness",
  or "credentialed deploy pending" unless a live proof artifact exists.
- Do not describe this checkout as externally certified for compliance,
  regulator validated, or production equivalent.
- AgentDojo, InjecAgent, and ToolEmu adapters in this checkout are local
  fixture/result adapters. They do not prove full upstream benchmark execution.
- Console/browser claims require rendered-browser evidence, not only TypeScript
  build output.
- Backend deployment claims require deployed health, signed receipt lookup, and
  postdeploy smoke output from the target revision.
- Ignored adjacent checkout rows are current-worktree routing notes, not root
  CI coverage.

## Update rule

When a package gains or loses a policy/evidence contract, update this file,
`MONOREPO.md` if package ownership changed, and
`docs/integration-readiness-task-map.md` if the change resolves a tracked gap.
Then run:

```bash
make lint-docs
python3 scripts/check_governance_stack_index.py
```
