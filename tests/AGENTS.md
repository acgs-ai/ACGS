<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# tests

## Purpose
Pytest suite covering governance gates, adapters, audit integrity, replay drift, API auth, hashing, decision state, and error UX.

## Key Files
| File | Description |
|------|-------------|
| `conftest.py` | Shared role and policy bundle fixtures. |
| `test_adapter_and_replay.py` | Adapter denial, replay, and audit-store guard tests. |
| `test_api_auth.py` | FastAPI token and tenant authorization tests. |
| `test_audit_chain.py` | JSONL audit chain validity, tamper detection, concurrency, and append cost tests. |
| `test_authority_gate.py` | Role/action/scope/tenant/resource authority tests. |
| `test_canonical_hash.py` | Deterministic canonical input hashing tests. |
| `test_decision_state.py` | Decision state, bundle hash, effective input, guard, and replay tests. |
| `test_error_ux.py` | Denial exception and remediation hint tests. |
| `test_in_memory_audit.py` | In-memory audit store and harness tests. |
| `test_policy_recall_gate.py` | Policy citation and deny-policy tests. |
| `test_reference_adapters.py` | OpenAI/LangGraph/Anthropic adapter behavior and input hash consistency. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Add or update tests with every behavior change. Prefer precise assertions on reason codes, rule IDs, hashes, and effective inputs.

### Testing Requirements
Run `cd .. && python -m pytest tests`.

### Common Patterns
Tests use small in-repo role/policy bundles and validate fail-closed behavior rather than only happy paths.

## Dependencies

### Internal
- `../governance/`.

### External
- pytest, plus optional API/test dependencies available in the environment.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
