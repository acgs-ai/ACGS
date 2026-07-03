"""The adversary taxonomy, made honest and machine-checked.

A1's rule: "the report is only as honest as the taxonomy." This file is the
taxonomy. Each of the 8 adversary classes maps to either (a) real, existing
covering tests in ``packages/gove-zone/tests`` (DEFENDED), or (b) an explicit
NOT-DEFENDED / PARTIAL entry backed by a live gap test in THIS directory.

The tests below fail if a "covering" test is renamed or deleted (so a defense
claim can't silently rot), or if a NOT-DEFENDED gap loses its reproducing test.
This is the mechanical form of "no overclaiming."
"""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]  # packages/gove-zone/tests
ADV_DIR = Path(__file__).resolve().parent

# status: DEFENDED (fully covered) | PARTIAL (covered + a named residual gap)
# covering: existing "file::test_name" nodes that prove the defended part.
# gap_tests: reproducing tests IN THIS DIR for the residual/undefended part.
MANIFEST: dict[str, dict[str, object]] = {
    "forged-authorization": {
        "status": "DEFENDED",
        "covering": [
            "test_receipt_signing.py::test_forged_recomputed_receipt_rejected_without_private_key",
            "test_maci_role_separation.py::test_gate_refuses_forged_self_validated_receipt",
            "test_executor_guard.py::test_executor_refuses_tampered_receipt",
        ],
        "gap_tests": [],
    },
    "replayed-authorization": {
        "status": "PARTIAL",
        "covering": [
            "test_workflow_receipt_chain.py::test_replayed_step_rejected_tool_not_called",
        ],
        "gap_tests": [
            "test_standalone_receipt_replay.py::test_standalone_receipt_is_replayable_KNOWN_LIMITATION",
        ],
    },
    "ledger-tampering": {
        "status": "DEFENDED",
        "covering": [
            "test_audit_chain.py::test_chain_detects_tampered_event_hash",
            "test_audit_chain.py::test_chain_detects_tampered_previous_hash",
        ],
        "gap_tests": [],
    },
    "policy-downgrade": {
        "status": "PARTIAL",
        "covering": [
            "test_tenant_safety.py::test_policy_hash_mismatch_fails_closed",
            "test_receipt_signing.py::test_algorithm_downgrade_rejected",
        ],
        "gap_tests": [
            "test_policy_version_downgrade.py::test_unpinned_gate_accepts_downgraded_policy_receipt_KNOWN_GAP",
        ],
    },
    "tenant-crossover": {
        "status": "DEFENDED",
        "covering": [
            "test_tenant_safety.py::test_tenant_a_receipt_cannot_authorize_tenant_b_action",
            "test_executor_guard.py::test_executor_refuses_wrong_tenant",
        ],
        "gap_tests": [],
    },
    "signature-stripping": {
        "status": "DEFENDED",
        "covering": [
            "test_receipt_signing.py::test_unsigned_rejected_when_required",
            "test_receipt_signing.py::test_signed_receipt_without_verifier_rejected",
        ],
        "gap_tests": [],
    },
    "validator-bypass": {
        "status": "DEFENDED",
        "covering": [
            "test_maci_role_separation.py::test_issuance_refuses_self_validation",
            "test_executor_guard.py::test_executor_refuses_denied_receipt",
        ],
        "gap_tests": [],
    },
    "evidence-omission": {
        "status": "DEFENDED",
        "covering": [
            "test_kernel_dispatch.py::test_every_dispatch_anchors_in_audit_chain",
            "test_executor_guard.py::test_executor_refuses_no_receipt",
        ],
        "gap_tests": [],
    },
}

EXPECTED_CLASSES = frozenset(MANIFEST)


def _node_exists(node: str, base: Path) -> bool:
    """A '<file>::<test_name>' node exists iff the file exists and defines it."""
    filename, _, test_name = node.partition("::")
    path = base / filename
    if not path.is_file():
        return False
    return f"def {test_name}(" in path.read_text(encoding="utf-8")


def test_all_eight_adversary_classes_are_enumerated() -> None:
    expected = {
        "forged-authorization",
        "replayed-authorization",
        "ledger-tampering",
        "policy-downgrade",
        "tenant-crossover",
        "signature-stripping",
        "validator-bypass",
        "evidence-omission",
    }
    assert expected == EXPECTED_CLASSES
    assert len(MANIFEST) == 8


def test_every_covering_test_actually_exists() -> None:
    """A defended/partial claim must name real, collectable tests. If one is
    renamed or deleted, this fails — the taxonomy can't silently overclaim."""
    missing: list[str] = []
    for cls, entry in MANIFEST.items():
        for node in entry["covering"]:  # type: ignore[union-attr]
            if not _node_exists(node, TESTS_DIR):
                missing.append(f"{cls}: {node}")
    assert not missing, "covering tests referenced but not found:\n" + "\n".join(missing)


def test_every_gap_has_a_live_reproducing_test() -> None:
    """Every PARTIAL/NOT-DEFENDED class must point at a real gap test in this
    directory, so no gap is asserted without a tripwire proving it."""
    missing: list[str] = []
    for cls, entry in MANIFEST.items():
        if entry["status"] == "DEFENDED":
            assert not entry["gap_tests"], f"{cls}: DEFENDED must have no gap_tests"
            continue
        gap_tests = entry["gap_tests"]  # type: ignore[assignment]
        assert gap_tests, f"{cls}: {entry['status']} must name a gap test"
        for node in gap_tests:  # type: ignore[union-attr]
            if not _node_exists(node, ADV_DIR):
                missing.append(f"{cls}: {node}")
    assert not missing, "gap tests referenced but not found:\n" + "\n".join(missing)


def test_defended_classes_are_the_expected_six() -> None:
    """Pin the honest headline: 6 defended, 2 partial. Changing the posture must
    be a deliberate edit here, not an accident."""
    defended = {c for c, e in MANIFEST.items() if e["status"] == "DEFENDED"}
    partial = {c for c, e in MANIFEST.items() if e["status"] == "PARTIAL"}
    assert len(defended) == 6, defended
    assert partial == {"replayed-authorization", "policy-downgrade"}, partial
