<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# metrics

## Purpose
Optional metrics facade for recording governance gate and decision telemetry.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Metrics package marker/exports. |
| `otel.py` | OpenTelemetry-backed or disabled metrics implementation. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Metrics must be optional and must not change governance decisions or fail-closed paths.

### Testing Requirements
Run `cd ../.. && python -m pytest tests`.

### Common Patterns
Use disabled/no-op behavior when OpenTelemetry is absent or metrics are not configured.

## Dependencies

### Internal
- `../models.py` and `../adapters/tools.py`.

### External
- Optional OpenTelemetry API.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
