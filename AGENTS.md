<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# acgs_governance_eval_mvp

## Purpose
Python MVP for runtime governance of AI agent and tool actions using authority, policy recall, governance recall, audit, replay, adapters, and optional API/metrics surfaces.

## Key Files
| File | Description |
|------|-------------|
| `README.md` | Install, API example, and core invariant. |
| `INTEGRATING.md` | Integration guidance for consumers. |
| `METADATA.md` | Project metadata notes. |
| `pyproject.toml` | Package metadata, extras, dependencies, and pytest configuration. |
| `ACGS Business Panel.html` | Static demo/business panel artifact. |
| `ACGS Governance Eval Console.html` | Static governance console demo artifact. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `docs/` | MVP handoff and overview documentation (see `docs/AGENTS.md`). |
| `governance/` | Runtime governance package (see `governance/AGENTS.md`). |
| `tests/` | Pytest acceptance and regression suite (see `tests/AGENTS.md`). |

## For AI Agents

### Working In This Directory
Preserve the invariant: `AuthorityGate.allow AND PolicyRecallGate.allow AND GovernanceRecallGate.allow`. Fail closed when validation cannot evaluate.

### Testing Requirements
Run `python -m pytest tests` from this directory.

### Common Patterns
Dataclass models, deterministic hashes, YAML policy/role bundles, chain-hashed audit JSONL, and adapter wrappers around external side effects.

## Dependencies

### Internal
- `governance/`, `tests/`, and `docs/`.

### External
- Python 3.10+, PyYAML, optional FastAPI/Uvicorn/OpenTelemetry, pytest.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
