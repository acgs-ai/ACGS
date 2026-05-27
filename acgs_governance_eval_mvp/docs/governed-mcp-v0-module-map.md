# `governed_mcp_v0` — module map

Closes the 10-step `mcp_server.py` extract (refactor branch
`refactor/eval-mvp-mcp-server-extract-v2`). Documents the post-refactor
layout so future readers don't have to reconstruct it from commit history.

## Before / after

| Metric | Before (master) | After (HEAD) |
| --- | --- | --- |
| `mcp_server.py` line count | 726 | 81 |
| Public modules in `governed_mcp_v0/` | 3 (`mcp_server`, `eval_gate`, `graph`) | 11 (8 new + 3 existing) |
| Largest module | `mcp_server.py` (726 lines) | `server.py` (252 lines) |
| Test count | 175 | 179 (4 import-surface smoke tests added) |
| Public import contract | `from governed_mcp_v0.mcp_server import X` | unchanged — `mcp_server` re-exports |

## Module catalog

Listed bottom-up by dependency layer. Every arrow points to a strictly lower
layer; no cycles.

### Layer 0 — leaves (no internal deps)

- **`constants.py`** (28 lines) — `SAFE_TOOLS`, `GUARDED_TOOLS`, `GENESIS_HASH`.
  Pure constants imported by policy + verify + server.
- **`errors.py`** (10 lines) — `GovernanceDenied`, `GovernanceStorageError`.
  Typed exceptions, no behavior.
- **`models.py`** (93 lines) — `AdmissionDecision`, `ReplayResult`,
  `RuntimeTargets`, `PolicyEngine` Protocol. Frozen dataclasses; co-locates
  the Protocol because its method signature forward-refs `RuntimeTargets` and
  `AdmissionDecision` (avoids a circular import).

### Layer 1 — primitives

- **`_io.py`** (105 lines, private) — `canonical_json`, `sha256_json`,
  `_read_json`, `_write_json`, `_append_jsonl`, `_resolve_fixture_path`,
  `_load_constitution`, `_last_audit_hash`, `_constitution_hash_or_missing`,
  `_next_receipt_index`. Underscore prefix marks these as internal — callers
  should not import them across module boundaries except for the modules
  defined here.

### Layer 2 — domain logic (pure, no orchestration)

- **`policy.py`** (102 lines) — `DeterministicPolicyEngine`. Pure decision
  logic; returns `(decision, reason, policy_ids)` without IO. Implements the
  `PolicyEngine` Protocol from `models`.
- **`verify.py`** (197 lines) — `verify_replay_bundle`, `_verify_allowed_effect`,
  `_iter_jsonl`. Audit-chain replay verification. Read-only; never mutates the
  audit chain or fixture tree.
- **`fixtures.py`** (51 lines) — `create_fixture_environment`. Builds the
  on-disk evidence tree for fresh `GovernedMCPServer` instances. Only IO is
  fixture-tree creation.

### Layer 3 — orchestration

- **`server.py`** (252 lines) — `GovernedMCPServer`. The deterministic,
  audit-chained MCP facade. Wraps every side-effect operation (filesystem
  write, sql mutation, email send, deploy, github mutate, shell exec) behind
  `admit(...)` → policy decision → fail-closed enforcement → audit chain
  append.

### Layer 4 — public surface + entrypoint

- **`mcp_server.py`** (81 lines) — intentionally thin. Three jobs:
  1. **Back-compat shim:** re-exports every name previously importable from
     `mcp_server` (`AdmissionDecision`, `GovernanceDenied`, etc.) so the
     `from governed_mcp_v0.mcp_server import X` contract that `eval_gate.py`,
     the package `__init__`, and external tests rely on keeps working.
  2. **`build_fastmcp_server(targets)`** — the FastMCP binding (tool
     registration on a `FastMCP("governed-mcp-v0")` instance).
  3. `__main__` — manual MCP stdio launch path.

### Pre-existing modules

- `eval_gate.py`, `graph.py`, `__init__.py` — unchanged by this refactor.
  They still import via the `mcp_server` re-export shim, which is the
  documented stable surface.

## How the 10 steps got there

| Step | Commit | What moved |
| --- | --- | --- |
| 1/10 | `4abfaaf` | `constants.py` |
| 2/10 | `86c7f30` | `errors.py` |
| 3/10 | `e1d38d4` | `models.py` |
| 4/10 | `addda42` | `_io.py` |
| 5/10 | `6f8edde` | `policy.py` |
| 6/10 | `11e127b` | `verify.py` |
| 7/10 | `07e22e4` | `fixtures.py` + IO helpers |
| 8/10 | `e2fc648` | `server.py` + shrink `mcp_server.py` to shim |
| 9/10 | `b8ae8cf` | `test_import_surface.py` — pins shim contracts |
| 10/10 | this commit | this doc |

Each extraction was a separate commit so the diff is reviewable and any
behavioral regression bisects cleanly to a single move. No logic was
rewritten — code moved verbatim with only import adjustments.

## Verification (HEAD = `b8ae8cf` + this doc)

```
cd acgs_governance_eval_mvp && uv run python -m pytest --import-mode=importlib -q
179 passed, 3 skipped in 0.93s

uv run ruff check governed_mcp_v0/
All checks passed!
```

The smoke tests in `tests/test_import_surface.py` enforce three invariants
on the shim layer:

1. **Back-compat:** every previously-importable name still resolves from
   `mcp_server`.
2. **New-style:** every name resolves from its dedicated module.
3. **Identity:** shim re-exports are *the same object* as the dedicated
   module's binding — not a shadow class. (Catches the most likely failure
   mode of a re-export shim: silent drift between shim and source.)

## Remaining technical debt

- **`__init__.py` still funnels through the shim** (`from governed_mcp_v0.mcp_server import …`).
  New code should import from dedicated modules; the package init could
  switch direction too, but doing so changes the resolved binding's
  declaration site for tools that introspect `inspect.getmodule(...)`.
  Out of scope here.
- **`eval_gate.py` and `graph.py` still import via the shim.** Same
  rationale — backward-compatible by design. Migrate when next touching
  those files.
- **`ruff line-length = 120`** (overridden from the workspace `100` in
  `pyproject.toml`) — pre-existing, called out in the comment, separate
  cleanup PR.
- **`B008` / `RUF012` / `UP028` ignored in ruff** — pre-existing, none
  introduced by this refactor.
- **`build_fastmcp_server` falls back through two FastMCP import paths**
  (`mcp.server.fastmcp` then `fastmcp`). Tolerable for an optional runtime
  integration; would be cleaner as a single declared dependency once the
  upstream packaging settles.

## Risks remaining

- **Re-export shim coupling.** As long as `eval_gate.py`, `__init__.py`,
  and external tests import via `mcp_server`, that module cannot drop its
  re-exports without coordinated downstream changes. The shim is small and
  the smoke test pins drift — low risk.
- **`uv run pytest` from the workspace root** picks up CWD-relative paths
  inside `governance/roles.json` and fails. Run from
  `acgs_governance_eval_mvp/` (per `pyproject.toml`'s `pytest.ini_options
  pythonpath = ["."]`). Not introduced by this refactor — call out so the
  next developer doesn't waste an hour on it.
