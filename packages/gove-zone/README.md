# gove-zone

A minimal governed agent runtime — fail-closed governance, replayable
receipts, and a tamper-evident audit chain for AI agent tool calls.

> Status: Phase 1 (audit + decision primitives). Not yet shipped to PyPI.
> See `docs/PLAN-GOVE-ZONE-KERNEL.md` in the parent monorepo for the full
> roadmap and acceptance criteria.

## Why this exists

Most agent frameworks let an agent call `write_file`, `http_post`, `db_exec`,
or `shell` and only audit *after* the side effect runs. `gove-zone` wraps
every external action in one explicit decision before any side effect:

```text
Goal → Proposed Action → Governance Decision → Tool Execution or Denial
     → Receipt → Audit Log → Replay / Debug
```

If policy evaluation, receipt generation, or audit append fails, the action
is **denied**. No exception path silently allows.

## Install (when Phase 1 is published)

```bash
pip install gove-zone
```

For local development inside this monorepo, `gove-zone` is registered as a
`uv` workspace member; `uv sync` from the repo root resolves it.

## What ships in Phase 1

| Module | Surface | LOC |
|---|---|---|
| `gove_zone.decision` | `Decision` enum, `DecisionRecord` dataclass, `canonical_json`, `sha256_json` | ~80 |
| `gove_zone.audit` | `ChainHashAuditStore` — append-only JSONL with `fcntl.flock` and SHA-256 chain | ~210 |

The tool-interception kernel, policy primitives, receipt/replay, and trace
emission land in subsequent phases — see the plan doc.

## Hello, audit chain

```python
from gove_zone import ChainHashAuditStore, Decision, DecisionRecord, sha256_json

store = ChainHashAuditStore("audit.jsonl")

record = DecisionRecord(
    decision=Decision.ALLOW,
    tool="write_file",
    argument_hash=sha256_json({"path": "/tmp/safe", "content": "hi"}),
    policy_version="v0",
    event_id="ev_001",
    reason="path outside blocked roots",
)
store.append(record)

result = store.verify_chain()
assert result["valid"]
```

Two events tampered with after the fact:

```python
# After someone edits audit.jsonl by hand:
store.verify_chain()
# → {"valid": False, "checked": N, "failures": [...]}
```

## Platform support

Unix only (Linux, macOS). The store uses `fcntl.flock` to serialize
process-level appends. Windows support is deferred.

## License

Apache-2.0.
