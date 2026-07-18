"""The gove-zone adversary taxonomy, made explicit and machine-checked.

This is Pack II artifact B2, reconciled against current ``master``. The static
``status`` records whether a class has dedicated existing coverage; the separate
``adaptive`` value records the result of the bounded variant family in
``adaptive.py``. A static DEFENDED label is therefore not a claim that every
configuration has the same posture: the adaptive layer makes default/opt-in
preconditions visible and machine-checked.

Each entry names real ``file::test`` nodes in ``packages/gove-zone/tests``. The
tests below assert every one exists, so the taxonomy cannot silently rot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, TypedDict


class ManifestEntry(TypedDict):
    status: Literal["DEFENDED"]
    adaptive: Literal["STABLE", "BYPASSABLE", "UNTESTED"]
    covering: list[str]


TESTS_DIR = Path(__file__).resolve().parents[1]  # packages/gove-zone/tests

# ``status`` is the current master static taxonomy. ``adaptive`` is an observed
# result from the deterministic real-surface harness, not a security proof.
MANIFEST: dict[str, ManifestEntry] = {
    "forged-authorization": {
        "status": "DEFENDED",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_receipt_signing.py::test_forged_recomputed_receipt_rejected_without_private_key",
            "test_maci_role_separation.py::test_gate_refuses_forged_self_validated_receipt",
            "test_executor_guard.py::test_executor_refuses_tampered_receipt",
        ],
    },
    "replayed-authorization": {
        "status": "DEFENDED",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_receipt_consumption.py::test_resume_replay_blocked_with_ledger",
            "test_receipt_consumption.py::test_reminted_receipt_same_anchor_blocked",
            "test_receipt_consumption.py::test_replay_without_ledger_pins_stateless_gate",
        ],
    },
    "ledger-tampering": {
        "status": "DEFENDED",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_audit_chain.py::test_chain_detects_tampered_event_hash",
            "test_audit_chain.py::test_chain_detects_tampered_previous_hash",
            "test_audit_chain_corruption.py::test_append_rejects_corrupt_final_jsonl_line_without_writing",
        ],
    },
    "policy-downgrade": {
        "status": "DEFENDED",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_tenant_safety.py::test_policy_hash_mismatch_fails_closed",
            "test_receipt_signing.py::test_algorithm_downgrade_rejected",
            "test_executor_guard.py::test_gate_policy_binding_accepts_matching_policy",
        ],
    },
    "tenant-crossover": {
        "status": "DEFENDED",
        "adaptive": "STABLE",
        "covering": [
            "test_tenant_safety.py::test_tenant_a_receipt_cannot_authorize_tenant_b_action",
            "test_executor_guard.py::test_executor_refuses_wrong_tenant",
        ],
    },
    "signature-stripping": {
        "status": "DEFENDED",
        "adaptive": "STABLE",
        "covering": [
            "test_receipt_signing.py::test_unsigned_rejected_when_required",
            "test_receipt_signing.py::test_signed_receipt_without_verifier_rejected",
            "test_executor_guard.py::test_executor_production_default_rejects_unsigned_no_verifier",
        ],
    },
    "validator-bypass": {
        "status": "DEFENDED",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_maci_role_separation.py::test_issuance_refuses_self_validation",
            "test_maci_role_separation.py::test_gate_refuses_validator_equals_caller",
            "test_executor_guard.py::test_executor_refuses_denied_receipt",
        ],
    },
    "evidence-omission": {
        "status": "DEFENDED",
        "adaptive": "STABLE",
        "covering": [
            "test_kernel_dispatch.py::test_every_dispatch_anchors_in_audit_chain",
            "test_executor_guard.py::test_executor_refuses_no_receipt",
        ],
    },
}

EXPECTED_CLASSES = frozenset(MANIFEST)
_VALID_STATIC = frozenset({"DEFENDED"})
_VALID_ADAPTIVE = frozenset({"STABLE", "BYPASSABLE", "UNTESTED"})


def _node_exists(node: str) -> bool:
    """``<file>::<test_name>`` exists iff the file defines that test function."""
    filename, _, test_name = node.partition("::")
    path = TESTS_DIR / filename
    return path.is_file() and f"def {test_name}(" in path.read_text(encoding="utf-8")


def test_all_eight_adversary_classes_are_enumerated() -> None:
    assert len(MANIFEST) == 8
    assert {
        "forged-authorization",
        "replayed-authorization",
        "ledger-tampering",
        "policy-downgrade",
        "tenant-crossover",
        "signature-stripping",
        "validator-bypass",
        "evidence-omission",
    } == EXPECTED_CLASSES
    assert all(entry["status"] in _VALID_STATIC for entry in MANIFEST.values())
    assert all(entry["adaptive"] in _VALID_ADAPTIVE for entry in MANIFEST.values())


def test_every_class_has_at_least_one_covering_test() -> None:
    empty = [cls for cls, entry in MANIFEST.items() if not entry["covering"]]
    assert not empty, f"classes with no covering test: {empty}"


def test_every_covering_test_actually_exists() -> None:
    missing: list[str] = []
    for cls, entry in MANIFEST.items():
        for node in entry["covering"]:
            if not _node_exists(node):
                missing.append(f"{cls}: {node}")
    assert not missing, "covering tests referenced but not found:\n" + "\n".join(missing)
