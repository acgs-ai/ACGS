# Audit Evidence

> Status: foundational / Alpha. gove-zone is **not** production-, compliance-,
> or regulator-certified.

Every governance decision — `ALLOW`, `DENY`, `TRANSFORM`, or `ESCALATE` —
creates an audit event. Evidence is produced *before* execution, so a decision
is recorded even when the side effect is refused.

## The audit chain

`gove_zone.audit.ChainHashAuditStore` is an append-only JSONL store with
cryptographic hash chaining (`audit.py`, ported from
`acgs_governance_eval_mvp/governance/audit/jsonl_chain.py`):

- `previous_hash` of event N links to `event_hash` of event N−1.
- The first event links to `GENESIS_HASH` (64 zeros).
- `event_hash = sha256(canonical_json(event_without_event_hash))`.
- Concurrent appends serialize through an exclusive `fcntl.flock` on a sidecar
  `.lock` file, so two writers never produce siblings sharing a `previous_hash`.
- Writes are `fsync`'d before the lock releases.

> Platform note: append requires a working `fcntl` lock primitive. Importing the
> package does not require `fcntl`; on hosts without it, append support is
> deferred (it raises rather than appending unsafely — fail-closed).

## Verification & replay

- `verify_chain()` re-walks the chain and returns
  `{valid, checked, failures, last_hash}`. `valid` is `True` only if every
  `event_hash` recomputes and every `previous_hash` matches the prior event.
- `iter_events()` / `query(where=, limit=)` read events back in chain order;
  malformed lines raise `AuditChainError` rather than being silently skipped.
- Replay (`gove_zone.replay`) reconstructs and re-checks decisions from the log.

Integrity is tested directly:

| Property | Test |
|---|---|
| Tampered event fails verification | `test_audit_chain*` |
| Corrupt / malformed tail raises | `test_audit_chain_corruption.py` |
| Chain holds under mixed outcomes | `test_fail_closed.py::test_audit_chain_holds_under_mixed_outcomes` |
| Concurrent appends keep the chain linear | `test_audit_chain.py` |
| Round-trip portability | `test_audit_portability.py` |

## AuditEvent — the typed evidence view

The chain persists bare JSON dicts built from the decision record. The
governance *linkage* (tenant, request, receipt, bundle) lives on the
`DecisionReceipt`. `gove_zone.contracts.AuditEvent` joins the two into one
typed view via `AuditEvent.from_receipt_and_event(receipt, chain_event)`:

| Field | Source |
|---|---|
| `event_id`, `previous_hash`, `event_hash`, `timestamp` | chain event |
| `request_id`, `receipt_id`, `tenant_id`, `actor`, `action_summary`, `decision`, `policy_bundle_id` | receipt |

`AuditEvent` is a **read-side projection**. It does not change what is written
to disk.

## What is and is not guaranteed

**Implemented:** local append-only chain, tamper-evident hashing, fail-closed
append, chain verification, replay, a typed evidence projection.

**Roadmap / not implemented:** external/append-only durable sinks (e.g. WORM
storage, SIEM shipping), signed events, multi-node consensus, retention
policies. The persisted chain record does not itself carry `tenant_id` /
`request_id` today — that linkage is reconstructed via the receipt. Persisting
those fields directly in the chain is roadmap.

## See also

- `decision-receipts.md`, `governed-execution.md`
- `examples/runtime_hook_demo.py` — audit chain from a runtime hook payload.
