# gove-zone

A minimal governed agent runtime — fail-closed governance, replayable
receipts, and a tamper-evident audit chain for AI agent tool calls.

> Status: Alpha foundation for receipt-first governed execution. Not yet
> shipped to PyPI; not production-ready or compliance-certified. See
> `../../docs/decision-receipts.md` and `../../docs/governed-execution.md`
> in the parent monorepo for the current trust contract.

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

## Install (when published)

```bash
pip install gove-zone
```

For local development inside this monorepo, `gove-zone` is registered as a
`uv` workspace member; `uv sync` from the repo root resolves it.

## What ships now

| Module | Surface |
|---|---|
| `gove_zone.foundation` | `GovernanceRequest`, tenant-bound `PolicyBundleBinding`, canonical `DecisionReceipt`, verifier, `GovernanceEngine`, `GovernedExecutor`, in-memory metrics hooks |
| `gove_zone.kernel` | Existing fail-closed policy-before-tool dispatch loop |
| `gove_zone.audit` | `ChainHashAuditStore` append-only JSONL with `fcntl.flock` and SHA-256 chain verification |
| `gove_zone.policy` | Deterministic stdlib policies and policy adapter interface |

The receipt-first path is intentionally local and deterministic. OPA, MCP, A2A,
and OpenTelemetry remain adapter surfaces unless explicitly wired by a consumer.


## CLI surface

The alpha CLI intentionally exposes only tested local proof commands:

```bash
gove-zone doctor
gove-zone smoke
gove-zone gate
gove-zone proofpack
gove-zone replay
```

`doctor` reports the local alpha contract. `smoke` proves allowed, denied,
missing-receipt, tampered-receipt, and audit verification behavior. `gate`
normalizes one JSON tool-call envelope and emits a Decision Receipt before any
side effect. `proofpack` writes a local conformance evidence bundle. `replay`
verifies an audit event against a JSONL chain.

The monorepo is named `govern-zone`; the installable runtime package is
currently named `gove-zone`. Keep that boundary explicit until a package rename
or publication decision is made.

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

## Command-line interface

`gove-zone` installs a CLI script `gove-zone` (or runnable via `python3 -m gove_zone.cli`).

```bash
# General health / alpha contract status
gove-zone doctor

# End-to-end smoke check of allowed, denied, and missing receipt execution
gove-zone smoke

# Evaluate a request against policy and write to audit chain
gove-zone gate --audit audit.jsonl --input-json '{"tool":"message.send","args":{"body":"secret"},"tenant_id":"tenant-alpha","policy_bundle_id":"local-boundary","request_id":"req-1","declared_goal":"demo"}'

# Verify a governed action against audit chain
gove-zone replay --event ev_1 --audit audit.jsonl --audit-hash <hash>

# Generate a conformance proof pack bundle
gove-zone proofpack --output conformance-pack/
```

## Platform support

Unix only (Linux, macOS). The store uses `fcntl.flock` to serialize
process-level appends. Windows support is deferred.

## License

Apache-2.0.
