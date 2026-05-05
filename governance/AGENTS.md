<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# governance

## Purpose
Core runtime governance package for validating action requests, loading policy/role bundles, recording audit evidence, replaying decisions, and exposing adapters/services.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package marker. |
| `models.py` | Principal, ActionRequest, GateResult, DecisionRecord, hashing, and denial error models. |
| `policy_loader.py` | YAML/JSON role and policy bundle loading. |
| `replay.py` | Re-evaluates historical decisions against supplied bundles to detect drift. |
| `roles.json` | Example role bundle for LegalOps, MarketingOps, and Observer. |
| `testing.py` | Test harness helpers for requests and adapters. |
| `utils.py` | Canonical tool input hashing helper. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `adapters/` | Reference adapters for tool execution and agent frameworks (see `adapters/AGENTS.md`). |
| `audit/` | In-memory and JSONL chain-hash audit stores (see `audit/AGENTS.md`). |
| `cli/` | Small CLI/demo utilities (see `cli/AGENTS.md`). |
| `gates/` | Authority, policy recall, and governance recall gates (see `gates/AGENTS.md`). |
| `hooks/` | Formal hook helpers (see `hooks/AGENTS.md`). |
| `metrics/` | Optional OpenTelemetry metrics facade (see `metrics/AGENTS.md`). |
| `policies/` | Versioned YAML policy bundles (see `policies/AGENTS.md`). |
| `schema/` | JSON schemas for audit and decision/explain payloads (see `schema/AGENTS.md`). |
| `service/` | Optional FastAPI service (see `service/AGENTS.md`). |

## For AI Agents

### Working In This Directory
Keep all decisions deterministic, explainable, and fail-closed. Preserve hash stability for replay/audit compatibility.

### Testing Requirements
Run `cd .. && python -m pytest tests`.

### Common Patterns
Use dataclasses for model records, stable JSON hashing for bundles/inputs, and explicit `GateResult` objects for every gate.

## Dependencies

### Internal
- All governance subpackages plus `../tests/`.

### External
- PyYAML; optional FastAPI/Uvicorn/OpenTelemetry.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
