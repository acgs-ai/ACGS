<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# cli

## Purpose
Small command-line utilities for replaying governance events and querying sample audit data.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | CLI package marker. |
| `replay_event.py` | Utility for replaying an event against current policy/role bundles. |
| `sample_audit_query.py` | Example audit query utility. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Keep CLIs thin wrappers around core governance modules. Avoid duplicating gate logic here.

### Testing Requirements
Run `cd ../.. && python -m pytest tests`.

### Common Patterns
CLI utilities should load bundles/stores, call core functions, and print inspectable results.

## Dependencies

### Internal
- `../replay.py`, `../policy_loader.py`, and `../audit/`.

### External
- Python standard library CLI modules.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
