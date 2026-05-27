# packages/agent-bus-analyzer — Claude Code Guide

Observer-only analysis layer over the Enhanced Agent Bus + gove-zone audit chain. New workspace member (not a submodule). Built per `specs/001-enhanced-agent-bus-analysis/`.

## Local gate (run before every push)

```bash
cd packages/agent-bus-analyzer
pytest -q
ruff check .
mypy src/
```

Or the Makefile shortcut: `make lint typecheck test`.

## Hard constraints

1. **Read-only on the bus and on the gove-zone audit chain.** No mutation of `BusEvent`, no rewrite of audit JSONL, no `O_RDWR` on the audit file (FR-003, FR-010).
2. **Fail-closed on integrity store loss.** Observer exits with `IntegrityStoreUnavailable` if the audit JSONL is missing/unreadable; never records hash-less events (FR-008).
3. **Hash-chained traces.** Every event carries `event_hash = sha256(canonical_json(event_minus_event_hash))` and `prev_hash` linking to the predecessor in the same trace. `ingest-gap` events are intentionally not part of the chain (data-model §EventStatus).
4. **Per-event constitutional hash.** Recorded on every event so mid-run rotation is detectable (FR-002, edge case "hash rotates mid-run").
5. **Not on the authorization path.** The analyzer is an observer; FR-010 forbids it from being part of any allow/deny decision flow.

## Where to look first

| Need | File |
|---|---|
| Models (Pydantic v2 source of truth) | `src/agent_bus_analyzer/models.py` |
| Hash chain primitive | `src/agent_bus_analyzer/hashing.py` |
| FastAPI app skeleton | `src/agent_bus_analyzer/api.py` |
| Config + constitutional-hash resolution | `src/agent_bus_analyzer/config.py` |
| Schemas (contracts) | `contracts/trace-event.schema.json`, `contracts/trace-query.schema.json` |
| Spec / plan / tasks | `../../specs/001-enhanced-agent-bus-analysis/` |

## Implementation discipline

- Tests in `tests/` mirror the structure of `src/agent_bus_analyzer/`.
- Dispatcher-level tests (T016, T035) MUST exercise a real `EnhancedAgentBus` instance via `publish()` — never call observer functions directly. This is the load-bearing rule from Constitution Principle III.
- No edits inside `ACGS/packages/enhanced_agent_bus/` or `packages/gove-zone/` — we consume their public surfaces only (subproject boundary, Constitution Principle II).
