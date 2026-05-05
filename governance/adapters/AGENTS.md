<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# adapters

## Purpose
Reference adapters that bind governance validation to tool execution and common agent framework call patterns.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Adapter package exports. |
| `tools.py` | `GovernedToolAdapter` validating requests, writing audit events, and guarding side effects. |
| `openai_agents.py` | OpenAI Agents-style adapter wrapper. |
| `langgraph.py` | LangGraph-style adapter wrapper. |
| `anthropic_claude.py` | Anthropic Claude-style adapter wrapper. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Never bypass `GovernedToolAdapter.validate()` before external side effects. `guard()` must execute only with `decision.effective_tool_input`.

### Testing Requirements
Run `cd ../.. && python -m pytest tests/test_reference_adapters.py tests/test_adapter_and_replay.py`.

### Common Patterns
Framework-specific adapters normalize calls into `ActionRequest` dictionaries and rely on shared gate/audit behavior.

## Dependencies

### Internal
- `../models.py`, `../gates/`, `../audit/jsonl_chain.py`, and `../metrics/otel.py`.

### External
- Framework integrations are reference-level and should avoid hard runtime coupling unless intentionally added.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
