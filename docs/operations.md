---
title: Operations notes
description: Local quality gates, metrics fields, and operational limitations for the first foundation.
---

# Operations notes

## How to run locally

```bash
uv run --package gove-zone gove-zone doctor
uv run --package gove-zone gove-zone smoke
uv run --package gove-zone gove-zone proofpack
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
PYTHONPATH=packages/gove-zone/src python3 packages/gove-zone/examples/receipt_first_demo.py
```

In this execution surface, `uv`, `pytest`, `ruff`, and `mypy` may need to be
installed before the package gate can run.

## Metrics fields

`InMemoryGovernanceMetrics` records the fields that a future OpenTelemetry
exporter should preserve:

- `decisions_total` by decision type;
- `denied_total`;
- `receipt_verification_failed_total`;
- `audit_write_failed_total`;
- `policy_bundle_id`;
- `tenant_id`;
- `request_id`.

Keep high-cardinality runtime payloads out of metric labels. Use receipts and
audit events for full evidence.

## Audit operations

`ChainHashAuditStore.verify_chain()` recomputes event hashes and previous-hash
links. Any edited, reordered, or malformed JSONL event should make verification
return `valid: false` or raise an audit-chain error.

## Current SLO posture

No production SLO is claimed. For local development, the expected hot path is a
single in-memory policy evaluation plus one local JSONL append before execution.
Remote policy engines, remote signing, and distributed audit storage are future
operational work.
