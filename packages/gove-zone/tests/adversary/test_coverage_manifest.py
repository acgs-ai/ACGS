"""The gove-zone adversary taxonomy, made explicit and machine-checked.

This is Pack II artifact B2, reconciled against **master** (not the stale
feat/governed-vulnclaw-pentest fork). On master all 8 adversary classes are
DEFENDED by existing, dedicated tests — including standalone-receipt replay,
which is now closed by the ``ReceiptConsumptionLedger`` (opt-in single-use gate).
There are therefore no net-new exploit tests to add; the value of this file is a
single, authoritative map of "which test proves gove-zone defends class X",
enforced so a covering test cannot be silently renamed or deleted without this
manifest failing.

Each entry names real ``file::test`` nodes in ``packages/gove-zone/tests``. The
tests below assert every one of them exists (the file defines that function), so
the taxonomy stays honest as the suite evolves.
"""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]  # packages/gove-zone/tests

# class -> covering "file::test_name" nodes proving master defends it.
MANIFEST: dict[str, list[str]] = {
    "forged-authorization": [
        "test_receipt_signing.py::test_forged_recomputed_receipt_rejected_without_private_key",
        "test_maci_role_separation.py::test_gate_refuses_forged_self_validated_receipt",
        "test_executor_guard.py::test_executor_refuses_tampered_receipt",
    ],
    "replayed-authorization": [
        # closed on master by the opt-in single-use consumption ledger
        "test_receipt_consumption.py::test_resume_replay_blocked_with_ledger",
        "test_receipt_consumption.py::test_reminted_receipt_same_anchor_blocked",
        "test_receipt_consumption.py::test_replay_without_ledger_pins_stateless_gate",
    ],
    "ledger-tampering": [
        "test_audit_chain.py::test_chain_detects_tampered_event_hash",
        "test_audit_chain.py::test_chain_detects_tampered_previous_hash",
        "test_audit_chain_corruption.py::test_append_rejects_corrupt_final_jsonl_line_without_writing",
    ],
    "policy-downgrade": [
        "test_tenant_safety.py::test_policy_hash_mismatch_fails_closed",
        "test_receipt_signing.py::test_algorithm_downgrade_rejected",
        "test_executor_guard.py::test_gate_policy_binding_accepts_matching_policy",
    ],
    "tenant-crossover": [
        "test_tenant_safety.py::test_tenant_a_receipt_cannot_authorize_tenant_b_action",
        "test_executor_guard.py::test_executor_refuses_wrong_tenant",
    ],
    "signature-stripping": [
        "test_receipt_signing.py::test_unsigned_rejected_when_required",
        "test_receipt_signing.py::test_signed_receipt_without_verifier_rejected",
        "test_executor_guard.py::test_executor_production_default_rejects_unsigned_no_verifier",
    ],
    "validator-bypass": [
        "test_maci_role_separation.py::test_issuance_refuses_self_validation",
        "test_maci_role_separation.py::test_gate_refuses_validator_equals_caller",
        "test_executor_guard.py::test_executor_refuses_denied_receipt",
    ],
    "evidence-omission": [
        "test_kernel_dispatch.py::test_every_dispatch_anchors_in_audit_chain",
        "test_executor_guard.py::test_executor_refuses_no_receipt",
    ],
}

EXPECTED_CLASSES = frozenset(
    {
        "forged-authorization",
        "replayed-authorization",
        "ledger-tampering",
        "policy-downgrade",
        "tenant-crossover",
        "signature-stripping",
        "validator-bypass",
        "evidence-omission",
    }
)


def _node_exists(node: str) -> bool:
    """'<file>::<test_name>' exists iff the file exists and defines it."""
    filename, _, test_name = node.partition("::")
    path = TESTS_DIR / filename
    if not path.is_file():
        return False
    return f"def {test_name}(" in path.read_text(encoding="utf-8")


def test_all_eight_adversary_classes_are_enumerated() -> None:
    assert frozenset(MANIFEST) == EXPECTED_CLASSES
    assert len(MANIFEST) == 8


def test_every_class_has_at_least_one_covering_test() -> None:
    empty = [cls for cls, nodes in MANIFEST.items() if not nodes]
    assert not empty, f"classes with no covering test (undefended): {empty}"


def test_every_covering_test_actually_exists() -> None:
    """Each named test must resolve to a real function. If master renames or
    removes a covering test, this fails — the taxonomy cannot silently overclaim.
    """
    missing: list[str] = []
    for cls, nodes in MANIFEST.items():
        for node in nodes:
            if not _node_exists(node):
                missing.append(f"{cls}: {node}")
    assert not missing, "covering tests referenced but not found:\n" + "\n".join(missing)
