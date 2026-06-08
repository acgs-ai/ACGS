# API reference

This page points to the current local API surfaces. Source code and package-local docs remain authoritative.

## Runtime kernel

Package path: `packages/gove-zone/src/gove_zone/`

Key modules:

- `gove_zone.receipt`: decision receipt types and verification;
- `gove_zone.executor`: receipt-gated execution helpers;
- `gove_zone.integration`: hook and tool-call payload normalization;
- `gove_zone.audit`: audit-chain writing and verification;
- `gove_zone.contracts`: public contract helpers for callers.

## Package-local docs

- `packages/gove-zone/README.md`
- `packages/gove-zone/ARCHITECTURE.md`
- `packages/gove-zone/docs/decision-receipts.md`
- `packages/gove-zone/docs/audit-evidence.md`
- `packages/gove-zone/docs/governed-execution.md`

## Import example

```python
from gove_zone import DecisionReceipt
```

Use package-local tests as executable examples for exact constructor arguments and verification behavior.
