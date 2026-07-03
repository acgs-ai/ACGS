# gove-zone adversary suite (Pack II · B2)

Honest, non-redundant adversary coverage over the **real** gove-zone gate
(`execute_with_receipt`). This suite does **not** re-prove defenses that existing
package tests already cover with real exploits — it makes the taxonomy explicit
and machine-checked, and adds live reproducing tests for the two open gaps.

Run:

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests/adversary --import-mode=importlib -q
```

## Coverage at a glance (8 classes)

| Adversary class | Status | Where it's proven |
|---|---|---|
| forged-authorization | **DEFENDED** | `test_receipt_signing.py`, `test_maci_role_separation.py`, `test_executor_guard.py` |
| ledger-tampering | **DEFENDED** | `test_audit_chain.py`, `test_audit_chain_corruption.py` |
| tenant-crossover | **DEFENDED** | `test_tenant_safety.py`, `test_executor_guard.py` |
| signature-stripping | **DEFENDED** | `test_receipt_signing.py`, `test_executor_guard.py` |
| validator-bypass | **DEFENDED** | `test_maci_role_separation.py`, `test_kernel_dispatch.py` |
| evidence-omission | **DEFENDED** | `test_kernel_dispatch.py`, `test_executor_guard.py` |
| replayed-authorization | **PARTIAL** | intra-workflow replay blocked; standalone reuse **NOT-DEFENDED** → `test_standalone_receipt_replay.py` |
| policy-downgrade | **PARTIAL** | pinned path blocked; unpinned default is a gap → `test_policy_version_downgrade.py` |

The map itself is enforced by `test_coverage_manifest.py`: if a "covering" test
is renamed/deleted, or a gap loses its tripwire, the manifest test fails.

## NOT-DEFENDED (open gaps, tracked as live tests)

1. **Standalone-receipt replay.** `execute_with_receipt` is stateless (verify →
   run, nothing consumes the receipt), so one ALLOW receipt authorizes unbounded
   re-execution across separate gate calls. No `ReceiptConsumptionLedger` is
   wired on this branch. Roadmap: single-use / nonce enforcement at the gate.
   The xfail `test_standalone_receipt_replay_should_be_rejected` flips to xpass
   when that lands.
2. **Unpinned policy-version downgrade.** `expected_policy_hash` defaults to
   `None`; a caller that doesn't pin it accepts a receipt minted under an older,
   more permissive policy. Mitigation exists (pin `expected_policy_hash`) and is
   proven; the gap is that binding is opt-in, not default.

Overclaiming a defense is a BLOCKER: a class is "DEFENDED" here only because a
real exploit test proves it, and the two gaps are stated plainly rather than
hidden.
