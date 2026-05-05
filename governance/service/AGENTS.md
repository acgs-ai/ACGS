<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-05 | Updated: 2026-05-05 -->

# service

## Purpose
Optional FastAPI HTTP surface for governance validation, explanation, audit querying, and audit-chain verification.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Service package marker. |
| `api.py` | FastAPI app with health, validation, explanation, audit query, and audit-chain verification endpoints. |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
Keep auth fail-closed. `ACGS_API_TOKEN` must be a tenant-prefixed bearer token, and actor tenant must match caller tenant unless cross-tenant delegation is explicit.

### Testing Requirements
Run `cd ../.. && python -m pytest tests/test_api_auth.py`.

### Common Patterns
Environment variables configure roles path, policy directory, audit path, and API token. The service delegates validation to `GovernedToolAdapter`.

## Dependencies

### Internal
- `../adapters/tools.py`, `../audit/jsonl_chain.py`, and `../policy_loader.py`.

### External
- Optional FastAPI and Uvicorn.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
