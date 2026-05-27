# AGENTS.md - acgs_governance_eval_mvp/tests

## Purpose

Pytest suite covering the governance pipeline end-to-end: adapter
normalization, gate decisions (authority + policy recall + governance recall),
formal-hook contracts, audit chain hashing, HTTP service auth, replay, and
canonical-hash stability. No network access — vendor SDKs are mocked.

## Layout

- `conftest.py` - shared fixtures: `roles_bundle` loads `governance/roles.json`, `policy_bundle` loads `governance/policies/2026-05/`.
- `regression_seed.json` (~17k) + `regression_registry.json` - seed data consumed by `scripts/bench-coverage.sh`.
- `test_adapter_and_replay.py` - `GovernedToolAdapter.validate` + `governance/replay.py` round-trip.
- `test_api_auth.py` - FastAPI `verify_caller` bearer auth, tenant-prefix enforcement, `cross_tenant_delegation` bypass.
- `test_audit_chain.py` - chain-hash append, tamper detection, `verify_chain` integrity.
- `test_authority_gate.py` - tenant mismatch, resource validity, role + action + scope + limits.
- `test_canonical_hash.py` - `canonical_input_hash` stability across key reordering.
- `test_decision_state.py` - `DecisionRecord` invariants and explanation aggregation.
- `test_error_ux.py` - reason-code surfaces and remediation strings.
- `test_in_memory_audit.py` - `InMemoryAuditStore` parity with `ChainHashAuditStore`.
- `test_policy_recall_gate.py` - critical-actions enforcement and `policy_citations` matching.
- `test_reference_adapters.py` - anthropic / langgraph / openai_agents wrappers raise on deny and call through on allow.

## How to Run

From repo root (or this package's root):

```bash
pytest acgs_governance_eval_mvp/tests/                    # full suite
pytest acgs_governance_eval_mvp/tests/ -k authority       # one stage
bash acgs_governance_eval_mvp/scripts/bench-coverage.sh   # severity-weighted coverage JSON
```

## Conventions

- Each `test_*.py` file mirrors the `governance/<subdir>/` module it covers.
- Fixtures live in `conftest.py` at this level; do NOT add a sibling conftest in subdirs.
- Tests are hermetic: vendor SDKs are faked, audit files use pytest `tmp_path`, no live HTTP.
- New tests for a new gate or adapter MUST appear in the same PR as the gate/adapter; otherwise `scripts/bench-coverage.sh` regression-coverage score will not move.
