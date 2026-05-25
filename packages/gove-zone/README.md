# gove-zone

A minimal governed agent runtime — fail-closed governance, replayable
receipts, and a tamper-evident audit chain for AI agent tool calls.

> Status: MVP runtime kernel (`0.1.0.dev0`) with audit chain, typed decisions,
> policy dispatch, receipts, replay, CLI, and runtime-hook adapter. Not yet
> shipped to PyPI. See `docs/PLAN-GOVE-ZONE-KERNEL.md` in the parent monorepo
> for roadmap context and acceptance criteria.

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

## Install

`gove-zone` is currently developed as a local workspace package, not a PyPI
release:

```bash
uv sync --all-extras
uv run --package gove-zone gove-zone doctor
```

When published, the install target will be:

```bash
pip install gove-zone
```

## What ships now

| Module | Surface | LOC |
|---|---|---|
| `gove_zone.decision` | `Decision` enum, `DecisionRecord`, canonical hashing | ~80 |
| `gove_zone.audit` | `ChainHashAuditStore` append-only JSONL with `fcntl.flock` and SHA-256 chain | ~210 |
| `gove_zone.tool` / `kernel` / `policy` | typed tool registry, path/state policy evaluation, fail-closed dispatcher | ~905 |
| `gove_zone.receipt` / `replay` / `frontend_contract` | replayable receipts and console projection helpers | ~275 |
| `gove_zone.evaluation` / `benchmark_adapters` | generic plus AgentDojo/InjecAgent/ToolEmu-style fixture replay for policy bundles | ~650 |
| `gove_zone.integration` / `setup` / `cli` | runtime-hook adapter, setup/doctor/gate/replay/enable/policy/eval commands | ~840 |

The source package is ~3,350 LOC after the path/state rule-bundle and fixture
adapter work. The
original 2,500 LOC MVP target should be treated as a trim/simplification
target before packaging, not as a current-state claim.

## Policies on paths

The kernel now carries path-aware decision context into every dispatch:

```python
from gove_zone import ChainHashAuditStore, Kernel, PathBoundaryPolicy

kernel = Kernel(
    policy=PathBoundaryPolicy(
        blocked_prefixes=["tenant-7/matter-9821/private-notes"],
        allowed_actors=["review-lead"],
    ),
    audit=ChainHashAuditStore("audit.jsonl"),
    actor="analyst-12",
)

kernel.dispatch(
    "matter.fetch",
    {"matter_id": "Matter-9821"},
    goal="Review matter private notes",
    path=("tenant-7", "matter-9821", "private-notes"),
    state={"matter_status": "privileged"},
)
```

The decision is evaluated before the tool runs. Audit events include the actor,
canonical path segments, a state hash, and a full `decision_request_hash`
binding actor + path + tool + argument hash + state hash without storing raw
state inline. Runtime hook receipts derive path context from `file_path` /
`path` fields when available.

### Declarative path/state rule bundles

For platform policy bundles, use `RuleSetPolicy` to express deterministic
rules over the proposed tool, canonical path, organization state, and actor
trust tier:

```python
from gove_zone import RuleSetPolicy

policy = RuleSetPolicy.from_dict(
    {
        "id": "legal-privilege/v1",
        "rules": [
            {
                "id": "PRIVILEGED_NOTES_REVIEW",
                "effect": "deny",
                "tools": ["matter.fetch"],
                "path_prefix": "tenant-7/matter-9821/private-notes",
                "state_equals": {"matter_status": "privileged"},
                "state_contains": {
                    "org_controls": "human_review_required_for_privileged_notes"
                },
                "allow": {
                    "actors": ["review-lead"],
                    "trust_tiers": ["reviewer", "admin"],
                },
            }
        ],
    }
)
```

Rule-set policy versions are content-addressed. Rules can `deny` or
`escalate`; positive authorization is represented as explicit actor/trust-tier
exemptions so an allow rule cannot accidentally mask a later denial.

Policy bundles can be normalized into a reviewable JSON artifact and inspected
without executing any tool:

```bash
gove-zone policy export --bundle policy.raw.json --output policy.bundle.json
gove-zone policy inspect --bundle policy.bundle.json
```

### Fixture evaluation

`gove-zone eval` replays a policy bundle against AgentDojo/InjecAgent/ToolEmu-style
fixture scenarios and returns pass/fail plus attack/utility metrics:

```bash
gove-zone eval --bundle policy.bundle.json --scenarios scenarios.json
```

For local benchmark-shaped fixtures, add an explicit adapter:

```bash
gove-zone eval \
  --bundle policy.bundle.json \
  --scenarios agentdojo-workspace-mini.json \
  --benchmark-format agentdojo

gove-zone eval \
  --bundle policy.bundle.json \
  --scenarios injecagent-workspace-mini.json \
  --benchmark-format injecagent

gove-zone eval \
  --bundle policy.bundle.json \
  --scenarios toolemu-high-stakes-mini.json \
  --benchmark-format toolemu
```

These adapters normalize reviewable local JSON (`tasks[].tool_calls` for
AgentDojo-style fixtures; `attacks[]` / `benign[]` for InjecAgent-style
fixtures; `test_cases[].tool_invocations` for ToolEmu-style high-stakes tool
fixtures). They are not a claim that the full upstream benchmark suites have
been run.

The fixture file is local JSON:

```json
{
  "dataset": "agentdojo-mini",
  "scenarios": [
    {
      "id": "attack-secret-read",
      "category": "attack",
      "actor": "worker-7",
      "tool": "file.read",
      "path": "repo/secrets/api-key.txt",
      "state": {
        "org_controls": ["block_secret_exfiltration"],
        "trust_tier": "analyst"
      },
      "expected_decision": "deny"
    }
  ]
}
```

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

## Runtime-hook integration

`gove_zone.integration` is the canonical adapter between any agent runtime
(Claude Code, Codex, MCP-style tool hosts) and the kernel. Hooks call
exactly one function:

```python
from gove_zone.integration import emit_receipt_for_hook

receipt = emit_receipt_for_hook(
    payload,                # the raw runtime hook event: {tool_name, tool_input, ...}
    action_kind="edit",     # "edit" | "autopilot" | "ralph" | "team" | ...
    actor="my-runtime",
    run_id=None,
)
```

The adapter:

- Hashes a fingerprint of `tool_input` (length + SHA-256 per string field) —
  full file contents never enter the chain.
- Normalizes multiple dependency-free tool-call shapes before hashing:
  Claude/Codex-style `{tool_name, tool_input}`, MCP-style
  `{method: "tools/call", params: {name, arguments}}`, function-call-style
  `{type: "function_call", name, arguments}`, OpenAI Responses-style
  `{output: [{type: "function_call", name, arguments}]}`, OpenAI Chat-style
  `{tool_calls: [{function: {name, arguments}}]}`, LangChain-style
  `{tool_calls: [{name, args}]}`, multi-call batches for those shapes, and
  generic `{name, arguments|args|input}` bridges. Recognized multi-call
  containers with unparseable child calls fail closed as
  `runtime.malformed_batch` instead of being treated as unknown tools.
- Appends a `DecisionRecord` to the audit JSONL chain at the resolved path.
- Returns a `Receipt` carrying the audit anchor hash.

Framework bridges that need to inspect the canonical request before emitting a
receipt can call:

```python
from gove_zone import tool_call_from_hook_payload

call = tool_call_from_hook_payload(
    {"method": "tools/call", "params": {"name": "file.write", "arguments": {"path": "README.md"}}},
    action_kind="mcp",
    actor="my-framework",
)
```

For runtime events that contain multiple proposed tool calls, use
`tool_calls_from_hook_payload(...)` to expand the batch into one
`ToolCall` per side effect before policy evaluation.

**Decisions.** The adapter is observer-by-default: it emits an
`Decision.ALLOW` receipt because the host runtime (Claude Code, Codex)
already owns allow/deny via its own permission system. To surface
`DENY`, `TRANSFORM`, or `ESCALATE` through the same chain, pass a custom
`Policy`:

```python
emit_receipt_for_hook(payload, action_kind="edit", actor="me", policy=MyPolicy())
```

**Gate mode resolution (in order):**

1. `$GOVE_ZONE_GATE_MODE`
2. `$CLAUDE_PROJECT_DIR/.gove-zone/gate.mode` (single line: `observe` or `enforce`)
3. default `observe`

Set with one command: `gove-zone enable --enforce` (or `--observe`).

| Mode | Behavior on emission failure |
|---|---|
| `observe` (default) | Returns `None`; existing fail-open contract preserved. |
| `enforce` | Raises `GateModeError`; hooks MUST exit non-zero. |

**Audit path resolution (in order):**

1. `$GOVE_ZONE_AUDIT_PATH`
2. `$CLAUDE_PROJECT_DIR/.gove-zone/audit.jsonl`
3. `$PWD/.gove-zone/audit.jsonl`

## Auto-setup

```bash
gove-zone setup            # markdown instructions for the detected host
gove-zone setup --enforce  # render the fail-closed variant
gove-zone doctor           # validate install + audit writability; exit 1 on issues
gove-zone gate < event.json   # run one hook payload through the adapter
gove-zone gate --policy-bundle policy.bundle.json < event.json
```

`gove-zone gate --policy-bundle ...` loads a `RuleSetPolicy`, writes receipts,
and exits non-zero for any `deny` / `escalate` decision so hook hosts can block
the proposed side effect before it runs. The gate accepts the same normalized
hook payloads as the adapter, including batched OpenAI Responses-style
`output[]` function-call items, OpenAI Chat `tool_calls` with JSON-string
`function.arguments`, and LangChain-style `tool_calls` with `args`. Batched
events are expanded into one governed receipt per child tool call; a single
denied child blocks the whole event and is surfaced as the primary `receipt`
alongside `receipts[]` and `receipt_count`. Malformed recognized batches emit
a `runtime.malformed_batch` deny receipt and exit non-zero before any child is
allowed. Invalid policy bundles also exit non-zero; this is a hook
configuration failure, not an allow.

## End-to-end demo

```bash
uv run --package gove-zone python packages/gove-zone/examples/runtime_hook_demo.py
```

Synthesises a Claude Code `PreToolUse` Edit event, appends a receipt,
verifies the chain, then proves fail-closed enforcement under
`GOVE_ZONE_GATE_MODE=enforce`.

## Platform support

Unix only (Linux, macOS). The store uses `fcntl.flock` to serialize
process-level appends. Windows support is deferred.

## License

Apache-2.0.
