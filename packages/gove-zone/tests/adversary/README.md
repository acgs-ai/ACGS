# gove-zone adversary coverage manifest (Pack II · B2)

An explicit, machine-checked map of the 8 adversary classes to the existing
tests that cover them. Reconciled against **master**, whose static taxonomy marks
all 8 **DEFENDED** (including standalone-receipt replay when its opt-in
`ReceiptConsumptionLedger` is configured). The companion adaptive dimension
makes those conditions explicit: it exercises bounded families against the real
gate and distinguishes an invariant that holds across its family from a defense
that depends on an opt-in binding or a caller-supplied expectation.

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

## Bounded adaptive dimension

`adaptive.py` adds a deterministic, real-surface variant family for each static
class. `adaptive_attack(class_name)` runs each family member through the actual
receipt/executor, kernel, or audit API and returns the first admitted variant,
if any. `test_adaptive_stability.py` pins the resulting current-master posture:
**3 STABLE / 5 BYPASSABLE / 0 UNTESTED**.

The result is intentionally narrower than a security proof. **No model, no
AgentDojo, no GCG:** this is deterministic config/input-space coverage, not an
optimizing model-in-the-loop evaluation. “Adaptively stable” means only “no
variant in this bounded, hand-enumerated family bypassed this surface”; it does
not mean secure. A BYPASSABLE result names a concrete precondition that needs
binding (for example a consumption ledger or expected policy value), rather
than silently converting static test coverage into an unconditional claim.

The stable families check distinct variants (not a repeated single case):
signature verification, tenant/boundary binding, and receipt/audit anchoring.
The family-size test fails before the fixed budget could truncate a stable
family.

## Note on provenance

An earlier draft of this suite (on the stale `feat/governed-vulnclaw-pentest`
fork, 196 commits behind master) reported standalone-receipt replay and unpinned
policy-downgrade as open gaps. Those "gaps" were artifacts of the stale branch —
master closed both (consumption ledger; `policy_hash` made load-bearing at the
gate). This manifest reflects master's real, hardened state.
