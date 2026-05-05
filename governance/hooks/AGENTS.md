<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# hooks

## Purpose
Formal hook helpers for integrating governance checks into external procedures or runtimes.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Hook package marker/exports. |
| `formal.py` | Formalized hook utilities. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Keep hooks declarative and aligned with `GovernedToolAdapter`; do not introduce a parallel validation path.

### Testing Requirements
Run `cd ../.. && python -m pytest tests`.

### Common Patterns
Hooks should prepare requests or wrap execution points while delegating decisions to gates/adapters.

## Dependencies

### Internal
- `../adapters/`, `../models.py`, and `../gates/`.

### External
- Python standard library unless explicitly extended.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
