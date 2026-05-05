<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# policies

## Purpose
Container for versioned runtime governance policy bundles.

## Key Files
None directly.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `2026-05/` | Current sample policy bundle for contracting and marketing actions (see `2026-05/AGENTS.md`). |

## For AI Agents

### Working In This Directory
Add new policy versions as separate subdirectories rather than mutating historical versions unless intentionally updating the current sample bundle.

### Testing Requirements
Run `cd ../.. && python -m pytest tests/test_policy_recall_gate.py tests/test_decision_state.py`.

### Common Patterns
The policy loader combines YAML files in a version directory into one bundle.

## Dependencies

### Internal
- `../policy_loader.py` and `../gates/policy_recall_gate.py`.

### External
- YAML via PyYAML.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
