---
title: Governance stack index
description: Policy, evidence, and verification ownership map for govern-zone packages.
---

# Governance stack index

This index maps each governed surface to its policy or evidence contract and the
local verification gate that supports conservative readiness claims. It is local
evidence only. Do not claim production deployment unless the relevant deploy
workflow, live URL, post-deploy checks, and signed production evidence exist.

## Ownership map

| Surface | Policy or evidence contract | Local gate | Claim boundary |
|---|---|---|---|
| `packages/gove-zone/` | Fail-closed runtime gate, policy bundle decisions, receipts, replay, and hash-chain audit storage | `uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q` | Local runtime proof; not PyPI release or production host proof |
| `packages/agent-bus-analyzer/` | Observer-only bus proof API, trace store, signed receipt packets, and source-tagged Phoenix links | `cd packages/agent-bus-analyzer && pytest -q && ruff check . && mypy src/` | Read-only evidence surface; not an authorization path |
| `acgs_governance_eval_mvp/` | Evaluation evidence ingestion, tenant-scoped report reads, and claim-safe status | `uv run python -m pytest acgs_governance_eval_mvp/tests --import-mode=importlib -q` | Local evaluation evidence; upstream benchmark execution remains source-tagged |
| `acgi-ai/` | Marketing and privileged console UX, bus schema client, auth boundary, CSP, and buyer evidence cards | `pnpm -F acgi-ai run test:all` | Local readiness only until live Cloud Run/Vercel proof is attached |
| `automation/` | Policy proposals, workflow templates, and automation validation scripts | `python -m pytest automation/tests -q` | Repository automation proof; not legal approval |
| `acgs-cft-governance-pack/` | CFT governance pack policy fixtures and tests | `cd acgs-cft-governance-pack && python -m pytest tests -q` | Package-local proof only |
| `hermes_acgs_bundle/` | Hermes middleware and evidence panel integration | `python -m pytest hermes_acgs_bundle/tests -q` | Integration proof only |
| Submodules in `packages/acgs-lite`, `packages/Acgs-Swarm`, and `packages/clinicalguard` | Independent package contracts and constitutional markers | Package-local gates from each nested repo | Respect submodule boundaries and PyPI compatibility |

## Cross-cutting rules

- Fail-closed behavior must be documented for every enforcement path.
- Hash-chain evidence must name the owning package and verification command.
- Source-tagged benchmark or trace evidence must identify whether it is local,
  fixture-backed, upstream-suite, or live production evidence.
- Legal review of claim matrix items remains external until explicit approval
  evidence is attached.

## How to run locally

```bash
make verify
python3 scripts/platform_readiness_report.py
```
