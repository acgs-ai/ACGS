# AGENTS.md - acgs_governance_eval_mvp/governance

## Purpose

Governance pipeline core. Each subdirectory is one stage of the
request -> decision flow. Public callers reach the pipeline through
`adapters/tools.py::GovernedToolAdapter` (Python) or `service/api.py` (HTTP);
everything else under this package is an internal stage.

## Pipeline Stages

- `adapters/` - vendor adapters that normalize calls into the internal event shape (`anthropic_claude.py`, `langgraph.py`, `openai_agents.py`, `tools.py`)
- `gates/` - admission control (`authority_gate.py`, `policy_recall_gate.py`, `governance_recall_gate.py`); deterministic, fail-closed
- `hooks/` - post-gate verification seams (`formal.py` — OPA/Z3 extension points)
- `audit/` - append-only audit log backends (`in_memory.py`, `jsonl_chain.py`); chain-hashed for tamper evidence
- `metrics/` - OpenTelemetry export (`otel.py`); optional, behind the `[otel]` extra
- `cli/` - operator commands (`replay_event.py`, `sample_audit_query.py`)
- `service/` - public FastAPI surface (`api.py`); the stable import target

## Module Files

- `models.py` - `ActionRequest`, `DecisionRecord`, `GateResult`, `Principal`, `GovernanceDeniedError`, `sha256_json`
- `policy_loader.py` - load roles JSON + policy YAML bundles
- `replay.py` - replay a stored decision against current policy/role bundles
- `roles.json` - bundled example roles bundle
- `policies/` - bundled example policy bundle (`2026-05/`)
- `schema/` - JSON schema for decision records and policy bundles
- `utils.py` - `canonical_input_hash` and small helpers
- `testing.py` - in-memory harness for tests / integrators

## Request Flow

`adapter.validate(payload)` -> `AuthorityGate` -> `PolicyRecallGate`
-> `FormalPolicyHooks` (optional) -> `GovernanceRecallGate`
-> append to `audit_store` -> emit `GovernanceMetrics` -> return `DecisionRecord`.
First gate to deny short-circuits but still produces an explainable record.

## Conventions

- Each subdir is a Python package; imports use dotted `governance.<subdir>.<module>` paths.
- `from __future__ import annotations` is the default in every module.
- New gates MUST be deterministic and fail-closed.
- New metadata keys consumed by gates MUST be documented in the package-root `METADATA.md`.
