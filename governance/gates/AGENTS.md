<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# gates

## Purpose
Deterministic pre-execution governance gates for authority, policy citation/denial, and final governance recall explanation.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Gate package exports. |
| `authority_gate.py` | Role/action/scope/tenant/MACI/limit validation. |
| `policy_recall_gate.py` | Applicable policy lookup, deny policy enforcement, and required citation checks. |
| `governance_recall_gate.py` | Final explanation gate requiring authority and policy recall results. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Gates must return `GateResult`; do not raise for normal denials. Deny on missing authority, missing policy, invalid resource, or incomplete recall.

### Testing Requirements
Run `cd ../.. && python -m pytest tests/test_authority_gate.py tests/test_policy_recall_gate.py tests/test_decision_state.py`.

### Common Patterns
Each gate has a stable `name`, measures latency, emits reason codes, evidence, and remediation where useful.

## Dependencies

### Internal
- `../models.py`, `../roles.json`, and `../policies/`.

### External
- Python matching and timing utilities.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
