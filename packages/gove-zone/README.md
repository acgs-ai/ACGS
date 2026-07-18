# gove-zone

A minimal governed agent runtime — fail-closed governance, replayable
receipts, and a tamper-evident audit chain for AI agent tool calls.

Zero runtime dependencies. ~1,700 LOC. `mypy --strict` clean. POSIX.

## Why this exists

Most agent frameworks let an agent call `write_file`, `http_post`, `db_exec`,
or `shell` and only audit *after* the side effect runs. `gove-zone` wraps
every external action in one explicit decision before any side effect:

```text
Goal → Proposed Action → Governance Decision → Tool Execution or Denial
     → Receipt → Audit Log → Replay / Debug
```

If policy evaluation or audit append fails, the action is **denied**. No
exception path silently allows.

## Install

```bash
pip install gove-zone
```

For local development inside this monorepo, `gove-zone` is a `uv` workspace
member; `uv sync` from the repo root resolves it.

## Quickstart — governed file writes

```python
from gove_zone import BoundaryPolicy, ChainHashAuditStore, DeniedError, Kernel

kernel = Kernel(
    policy=BoundaryPolicy(
        forbidden_keywords=["~/.ssh", "/etc/shadow", "id_rsa"],
        rule_id="FS-GUARD",
    ),
    audit=ChainHashAuditStore("audit.jsonl"),
    actor="demo-runner",
)

@kernel.tool("write_file")
def write_file(path: str, content: str) -> int:
    with open(path, "w") as f:
        return f.write(content)

# ALLOW — executes, returns (result, receipt)
n, receipt = kernel.dispatch(
    "write_file",
    {"path": "/tmp/hello.txt", "content": "hello\n"},
    goal="seed demo file",
)
print(receipt.record.decision.value, receipt.audit_hash[:16])

# DENY — blocked BEFORE the side effect; the attempt is still audit-anchored
try:
    kernel.dispatch(
        "write_file",
        {"path": "/tmp/fake/id_rsa", "content": "stolen"},
        goal="exfiltrate ssh key",
    )
except DeniedError as exc:
    print("denied:", exc.record.reason)

# Tamper-evident chain
assert kernel.audit.verify_chain()["valid"]
```

The full runnable version lives at `examples/write_file_guard.py`.

## Guarantees

| Invariant | Enforced by |
|---|---|
| No tool executes before its audit append commits | `kernel.py` dispatch order, `tests/test_kernel_dispatch.py`, `tests/test_fail_closed.py`, `tests/test_audit_chain_corruption.py` |
| Any policy/audit failure → deny, never silent allow | `tests/test_fail_closed.py`, `tests/test_fail_closed_gaps.py` |
| Every decision is a replayable record (goal, tool, argument hash, policy version, matched rules, reason, timestamp, audit hash) | `decision.py`, `receipt.py`, `tests/test_replay.py` |
| Audit chain is append-only + tamper-evident (SHA-256 chain, `fcntl` locked) | `audit.py`, `tests/test_audit_chain*.py` |
| `TRANSFORM` executes only with policy-supplied `transformed_args`; a malformed TRANSFORM (missing args) fails closed | `kernel.py`, `tests/test_fail_closed.py` |

## Public API (31 names)

| Area | Names |
|---|---|
| Kernel | `Kernel`, `ToolCall`, `ToolRegistry` |
| Meta | `__version__` |
| Decisions | `Decision`, `DecisionRecord`, `canonical_json`, `sha256_json` |
| Policies | `Policy`, `BoundaryPolicy`, `CompositePolicy`, `AllowAllPolicy`, `DenyAllPolicy`, `new_event_id` |
| Audit | `ChainHashAuditStore`, `AuditChainError`, `GENESIS_HASH` |
| Receipts / replay | `Receipt`, `safe_result_hash`, `ReplayResult`, `replay_event`, `replay_call`, `find_event` |
| Console contract | `record_to_governed_action`, `receipt_to_governed_action` |
| Errors | `GoveZoneError`, `DeniedError`, `EscalateError`, `PolicyError`, `AuditError`, `UnknownToolError` |

## CLI

```bash
# Verify a governed action against an audit chain; JSON evidence on stdout.
gove-zone replay --event <event_id> --audit audit.jsonl --audit-hash <hash>
# exit 0 = verified, exit 1 = failed verification.
# Omitting --audit returns hash-only evidence (verified=false, exit 0).

# Read-only demo console API (stdlib HTTP server, /api/v1/*)
gove-zone-api
```

## Scope — what the kernel is not

The kernel governs individual tool calls. It deliberately does **not** ship:
constitutional YAML rule loading, MACI role separation, circuit breakers,
EU-AI-Act compliance frameworks, LLM-framework integrations, or swarm
coordination. Those live in the wider ACGS ecosystem as *consumers* of this
kernel (`acgs-lite` on PyPI, `constitutional-swarm`, domain packs). See
`docs/PLAN-GOVE-ZONE-KERNEL.md` in the parent monorepo.

## Platform

POSIX (Linux/macOS) — audit locking uses `fcntl.flock`. Windows is deferred.
Python ≥ 3.11. The `schema` extra installs pydantic; it is reserved for
future schema-validation helpers — the 0.1.x kernel itself uses no runtime
dependencies.

## License

Apache-2.0
