# API Documentation — ACGS / gove-zone

> **Core invariant: No valid Decision Receipt, no side effect.**

Four integrator surfaces: the Python library API, the `gove-zone` CLI, the
Decision Receipt wire format, and the governed-MCP gateway (alpha). The
normative contracts are [`docs/DECISION_RECEIPT_SPEC.md`](../DECISION_RECEIPT_SPEC.md)
and the code + tests in `packages/gove-zone/`; this page is the integrator-facing
summary. There is **no hosted REST API today** — the HTTP shape in §5 is an
illustrative self-hosted pattern.

## 1. Python library API (`gove_zone`)

### Core types

| Symbol | Purpose |
|---|---|
| `Decision` | Enum: `ALLOW`, `DENY`, `TRANSFORM`, `ESCALATE`. Only `ALLOW` and approved `TRANSFORM` can execute. |
| `DecisionRecord` | The policy engine's output for one proposed call (decision, tool, `argument_hash`, policy version, event id, actor, reason). |
| `DecisionReceipt` | The evidence artifact; minted via `DecisionReceipt.from_record(...)`, which refuses self-validated receipts. |
| `Validator` | Validator principal; must differ from the acting principal. |
| `ReceiptValidationError` | Raised by the gate on any verification failure — the fail-closed signal. |
| `sha256_json(obj)` | Canonical-JSON SHA-256; how `argument_hash` is computed. |

### Minting a receipt

```python
from gove_zone import Decision, DecisionReceipt, DecisionRecord, Validator, sha256_json

record = DecisionRecord(
    decision=Decision.ALLOW,
    tool="runtime.file.write",
    argument_hash=sha256_json({"path": "safe.txt", "content": "ok"}),
    policy_version="example-policy/v1",
    event_id="ev_1",
    actor="agent-1",
    reason="example allow",
)
receipt = DecisionReceipt.from_record(
    record=record,
    audit_hash="...",                 # audit event anchoring this decision
    previous_audit_hash="0" * 64,
    tenant_id="tenant-A",
    execution_boundary="local-sandbox",
    policy_bundle_id="example-policy",
    policy_hash="example-policy/v1",
    request_id="req-1",
    validator=Validator("constitutional-council"),
    authority="tenant-A/write-grant",
)
```

### Gated execution

```python
from gove_zone import execute_with_receipt

result = execute_with_receipt(
    tool_fn=write_file,               # the raw side effect, kept private behind the gate
    args={"path": "safe.txt", "content": "ok"},
    receipt=receipt,
    expected_tenant_id="tenant-A",
    expected_execution_boundary="local-sandbox",
    expected_action="runtime.file.write",
    expected_actor="agent-1",         # from trusted runtime context, never from the request body
    # require_signature defaults to True (secure profile); pass a trusted
    # verifier, or opt in to dev mode explicitly with require_signature=False.
)
```

Any failure — missing/malformed/tampered receipt, DENY/ESCALATE, actor/action/
argument/tenant/boundary/policy/audit mismatch, expiry, unsigned-when-required —
raises `ReceiptValidationError` **before** `tool_fn` runs. The verifier's full
20-step rejection order is in the
[receipt spec](../DECISION_RECEIPT_SPEC.md#validation-algorithm).

`GovernedExecutor` is the reusable object form of the same gate; `ReceiptVerifier`
exposes verification without execution.

### Policies

- `RuleSetPolicy` — declarative deny/escalate rule bundles with exemptions;
  canonical export binds bundle id + hash + version. **Note: allow-by-default** —
  a bundle expresses what to deny/escalate; write deny rules accordingly.
- `BoundaryPolicy` / `PathBoundaryPolicy` — execution-boundary and path guards.
- `TenantPolicyStore` — per-tenant policy isolation.
- Custom: subclass `Policy` and implement `version()` and
  `evaluate(call) -> DecisionRecord`. Exceptions and configured timeouts
  synthesize DENY (fail closed).

### Hardening opt-ins

```python
from gove_zone.consumption import ReceiptConsumptionLedger   # single-use receipts
ledger = ReceiptConsumptionLedger("consumed.jsonl", checkpoint=True)
# pass to the gate: burns the receipt's audit anchor before the side effect;
# a replay raises ReceiptAlreadyUsedError
```

- Signing (`gove_zone.signing`): Ed25519 signer/verifier over `receipt_hash`;
  algorithm and key id are hash-bound (anti-downgrade). Requires the `crypto`
  extra.
- Audit (`gove_zone.audit`): append-only hash-chained JSONL; `verify_chain()`
  re-walks it and fails closed on edits, reorders, truncation, malformed tail.
- Replay (`gove_zone.replay`, `replay_store`): re-derive decisions from audit
  events; strong replay of arguments needs the opt-in raw-argument side-store.

### Adapters (`gove_zone.integration`)

`emit_receipt_for_hook` and the payload normalizer accept Claude/Codex hook
payloads, MCP `tools/call`, OpenAI-style function calls, and generic tool
events, producing governance-shaped calls. Runtime coverage is tiered — see
[`docs/INTEGRATION_MATRIX.md`](../INTEGRATION_MATRIX.md).

## 2. CLI (`gove-zone`)

| Command | Purpose |
|---|---|
| `setup` / `doctor` | Guided setup; environment and wiring health checks |
| `smoke --audit <path>` | End-to-end allowed/denied proof run |
| `gate` / `enable` | Gate an invocation; enable governed integrations |
| `policy inspect` / `policy export` | Inspect and canonically export policy bundles (id + hash binding) |
| `eval` | Evaluate a proposed call against a policy bundle |
| `approve-escalation` | Human-approval resume path for `ESCALATE` decisions |
| `replay` | Re-derive decisions from audit evidence |
| `proofpack` / `verify-proofpack` | Produce and offline-verify an evidence bundle (receipts, audit chain, verification results, limitations) |
| `verify-ledger [--audit <chain>]` | Verify the consumption ledger's hash chain; reconcile burns against the audit chain |
| `prune-ledger` | Prune expired entries; the persisted watermark blocks clock-rollback replay |

## 3. Decision Receipt wire format

Full schema (28 fields), validation order, and JSON examples:
[`docs/DECISION_RECEIPT_SPEC.md`](../DECISION_RECEIPT_SPEC.md). The essentials:

- vendor-neutral JSON; no framework- or model-specific shape;
- `receipt_hash = sha256(canonical_json(receipt minus receipt_hash and signature))`;
- every binding field (actor, action, `argument_hash`, tenant, boundary, policy
  id/version/hash, audit anchors, expiry, signature algorithm, key id) is inside
  the hash — edits are detected, downgrade attacks included;
- `signature` is `unsigned_local` (dev) or Ed25519 over `receipt_hash`;
- cross-host portability validators are roadmap, not a current guarantee.

## 4. Governed-MCP gateway (alpha)

`packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py` — a transparent
stdio proxy fronting one downstream MCP server:

- `tools/list` passes through; `tools/call` is gated through the sealed kernel;
- the actor is the session principal from `initialize` `clientInfo` + config
  map — **never** from the request body;
- every ALLOW is single-use via a shared consumption ledger;
- `sampling/createMessage` is denied in alpha; unregistered methods answer
  method-not-found — never a silent forward;
- trust limitation: the host→gateway stdio hop is assumed trusted (local
  transport); remote/multi-tenant deployment requires authenticating that hop.

## 5. Self-hosted HTTP pattern (illustrative — no shipped server)

A side-effect API should demand a receipt with the request:

```text
POST /deploy
{ "action": "ci.deploy", "args": {...}, "decision_receipt": {...} }
```

Server order: authenticate caller → map to `expected_actor` → verify receipt
against expected tenant/boundary/action/args/policy → execute only on success →
return the denial without executing otherwise. A demo HTTP handler exists in
`gove_zone/api.py` for the console demo; it is not a production service.

## 6. `acgs-lite` (PyPI)

The pip-installable library (`pip install acgs-lite`) exposes the
constitution-based API: `Constitution`, `GovernanceEngine`, `GovernedAgent`,
`MACIEnforcer`/`MACIRole`, `AuditLog`, Ed25519 receipt signing, plus shipped
integrations (`acgs_lite.integrations.openai`, `.anthropic`, `.langchain`,
`.mcp_server`). Its public API is stability-bound (published package); see
`packages/acgs-lite/README.md` for the full reference.

## Integrator contract (summary)

1. Keep raw tool implementations private behind the gate.
2. Verify at the executor boundary — never only in a planner or prompt.
3. Supply `expected_*` values from trusted runtime context.
4. Treat `DENY`/`ESCALATE` as non-executable, always.
5. Prove wiring with a dispatcher-level test including the negative path.
6. Don't promote unsigned local mode as production security.
