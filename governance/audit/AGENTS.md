<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# audit

## Purpose
Audit storage implementations for governance decisions, including durable chain-hashed JSONL and in-memory test storage.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Audit package exports. |
| `jsonl_chain.py` | Append-only JSONL audit store with previous/event hash verification and query helpers. |
| `in_memory.py` | In-memory audit store for tests and harness use. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Preserve append-only semantics, canonical event hashing, chain verification, and concurrent append safety.

### Testing Requirements
Run `cd ../.. && python -m pytest tests/test_audit_chain.py tests/test_in_memory_audit.py`.

### Common Patterns
Events carry `previous_hash` and `event_hash`; disk writes use file locking and fsync.

## Dependencies

### Internal
- `../models.py`.

### External
- Python filesystem, JSON, hashing, and file-locking utilities.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
