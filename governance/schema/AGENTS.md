<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# schema

## Purpose
JSON schemas for governance audit events and decision/explanation payloads.

## Key Files
| File | Description |
|------|-------------|
| `audit_event.schema.json` | Schema for persisted audit event records. |
| `decision_explain.schema.json` | Schema for decision explanation payloads. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Keep schemas compatible with `DecisionRecord.to_dict()` and audit store output. Update tests when schema-relevant fields change.

### Testing Requirements
Run `cd ../.. && python -m pytest tests/test_decision_state.py tests/test_audit_chain.py`.

### Common Patterns
Schemas should reflect explicit decision state, gate checks, hashes, policy/role versions, and explanation evidence.

## Dependencies

### Internal
- `../models.py`, `../audit/jsonl_chain.py`, and `../service/api.py`.

### External
- JSON Schema consumers.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
