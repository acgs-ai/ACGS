<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# 2026-05

## Purpose
Current sample governance policy bundle for contract and marketing action validation.

## Key Files
| File | Description |
|------|-------------|
| `contracting.yaml` | Contract redline/approval policies requiring citations and human review evidence for high-value approvals. |
| `marketing.yaml` | Marketing publication policies, including Ontario inducement denial and traceable approval citation requirements. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Keep policy IDs stable when tests or audit replay rely on them. Use `effect: deny` for hard prohibitions and `require_citation` for recall obligations.

### Testing Requirements
Run `cd ../../.. && python -m pytest tests/test_policy_recall_gate.py tests/test_decision_state.py`.

### Common Patterns
Each file defines `version` and `policies`; policies contain `id`, `title`, `effect`, `applies_when`, optional `conditions`, `require_citation`, and `obligations`.

## Dependencies

### Internal
- `../../policy_loader.py`, `../../gates/policy_recall_gate.py`, and `../../../tests/`.

### External
- YAML via PyYAML.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
