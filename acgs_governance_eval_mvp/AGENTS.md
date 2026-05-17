# AGENTS.md - acgs_governance_eval_mvp

## Purpose

Runtime governance layer for AI agents and tool calls. Wraps a deterministic
`adapter -> gates -> hooks -> service -> audit + metrics` pipeline so every
external action is validated against an authority gate, a policy recall gate,
and a governance recall gate before any side effect happens. The package is
the minimum viable governance harness used by the rest of govern-zone.

## Subdirectory Map

- `governance/` - core pipeline (adapters, gates, hooks, audit, metrics, service, cli, policies, schema)
- `scripts/` - bench harness (pass-rate, coverage) and scope check tooling
- `tests/` - pytest suite covering pipeline + integration + audit-chain invariants
- `docs/` - reference docs and design notes

## Reference Material

- `INTEGRATING.md` (~11k) - integration guide; five-minute quickstart, validate/guard lifecycle, full reason-code catalog
- `METADATA.md` (~3.6k) - canonical keys read off `request.metadata` (e.g. `policy_citations`, `cross_tenant_delegation`, `maci_required_role`)
- `README.md` - short top-of-tree overview and install commands

## Entry Points

- Public Python API: `governance.adapters.tools.GovernedToolAdapter.validate(payload)`
- Public HTTP API: `governance.service.api:app` (FastAPI; `POST /govern/validate`, `GET /govern/explain/{event_id}`, `/audit/query`, `/audit/verify-chain`, `/health`)
- Operator CLI: `governance/cli/` (replay events, sample audit queries)

## Conventions

- Python with type hints, `from __future__ import annotations`, pytest for tests.
- `pyproject.toml` at this package root is SEALED — do not edit casually.
- Every gate is fail-closed: missing config, unreachable backend, or malformed input must deny + emit an audit event.
- Audit records are chain-hashed (JSONL); the chain is part of the canonical decision invariant.
