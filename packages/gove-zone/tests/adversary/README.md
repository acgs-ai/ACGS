# gove-zone adversary coverage manifest (Pack II · B2)

An explicit, machine-checked map of the 8 adversary classes to the tests that
prove gove-zone defends each. Reconciled against **master** — where all 8 are
already **DEFENDED** (including standalone-receipt replay, closed by the opt-in
`ReceiptConsumptionLedger`). This directory therefore adds **no new exploit
tests** (that would duplicate the existing suite); it adds one authoritative
taxonomy that fails if a covering test is renamed or removed.

Run:

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests/adversary --import-mode=importlib -q
```

## Coverage (8 classes, all DEFENDED on master)

| Adversary class | Proven by |
|---|---|
| forged-authorization | `test_receipt_signing.py`, `test_maci_role_separation.py`, `test_executor_guard.py` |
| replayed-authorization | `test_receipt_consumption.py` (single-use ledger), `test_replay*.py` |
| ledger-tampering | `test_audit_chain.py`, `test_audit_chain_corruption.py` |
| policy-downgrade | `test_tenant_safety.py`, `test_receipt_signing.py`, `test_executor_guard.py` |
| tenant-crossover | `test_tenant_safety.py`, `test_executor_guard.py` |
| signature-stripping | `test_receipt_signing.py`, `test_executor_guard.py` |
| validator-bypass | `test_maci_role_separation.py`, `test_kernel_dispatch.py`, `test_executor_guard.py` |
| evidence-omission | `test_kernel_dispatch.py`, `test_executor_guard.py` |

`test_coverage_manifest.py` enforces this map: every referenced `file::test`
must resolve to a real function, and all 8 classes must carry ≥1 covering test.

## Note on provenance

An earlier draft of this suite (on the stale `feat/governed-vulnclaw-pentest`
fork, 196 commits behind master) reported standalone-receipt replay and unpinned
policy-downgrade as open gaps. Those "gaps" were artifacts of the stale branch —
master closed both (consumption ledger; `policy_hash` made load-bearing at the
gate). This manifest reflects master's real, hardened state.
