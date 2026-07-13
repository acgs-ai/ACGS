"""The adversary taxonomy, made honest and machine-checked.

A1's rule: "the report is only as honest as the taxonomy." This file is the
taxonomy. Each adversary class maps to either (a) real, existing covering tests
in ``packages/gove-zone/tests`` (DEFENDED), or (b) an explicit
PARTIAL / NOT_DEFENDED entry backed by a live gap test in THIS directory.

Threat-model-v2 (docs/security/threat-model-v2.md) expanded the taxonomy from the
original 8 classes to 10 by adding the two surfaces the original map folded or
omitted — ``adapter-bypass`` and ``policy-default-allow`` — and by honestly
downgrading three classes that had an untested residual (``forged-authorization``
unsigned recompute, ``ledger-tampering`` full-chain rewrite, ``validator-bypass``
authority-scope-at-gate) from DEFENDED to PARTIAL with a live gap test each.

The tests below fail if a "covering" test is renamed or deleted (so a defense
claim can't silently rot), or if a PARTIAL/NOT_DEFENDED gap loses its reproducing
test. This is the mechanical form of "no overclaiming."
"""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]  # packages/gove-zone/tests
ADV_DIR = Path(__file__).resolve().parent

# status: DEFENDED (fully covered) | PARTIAL (covered + a named residual gap)
#         | NOT_DEFENDED (no defended part on this branch; gap only)
# covering: existing "file::test_name" nodes (under tests/) that prove the defended part.
# gap_tests: reproducing tests IN THIS DIR for the residual/undefended part.
MANIFEST: dict[str, dict[str, object]] = {
    "forged-authorization": {
        "status": "PARTIAL",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_receipt_signing.py::test_forged_recomputed_receipt_rejected_without_private_key",
            "test_maci_role_separation.py::test_gate_refuses_forged_self_validated_receipt",
            "test_executor_guard.py::test_executor_refuses_tampered_receipt",
        ],
        "gap_tests": [
            "test_unsigned_forgery.py::test_unsigned_recomputed_forgery_executes_KNOWN_LIMITATION",
        ],
    },
    "replayed-authorization": {
        "status": "PARTIAL",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_workflow_receipt_chain.py::test_replayed_step_rejected_tool_not_called",
        ],
        "gap_tests": [
            "test_standalone_receipt_replay.py::test_standalone_receipt_is_replayable_KNOWN_LIMITATION",
        ],
    },
    "ledger-tampering": {
        "status": "PARTIAL",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_audit_chain.py::test_chain_detects_tampered_event_hash",
            "test_audit_chain.py::test_chain_detects_tampered_previous_hash",
        ],
        "gap_tests": [
            "test_audit_full_chain_rewrite.py::test_verify_chain_accepts_self_consistent_full_rewrite_KNOWN_GAP",
        ],
    },
    "policy-downgrade": {
        "status": "PARTIAL",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_tenant_safety.py::test_policy_hash_mismatch_fails_closed",
            "test_receipt_signing.py::test_algorithm_downgrade_rejected",
        ],
        "gap_tests": [
            "test_policy_version_downgrade.py::test_unpinned_gate_accepts_downgraded_policy_receipt_KNOWN_GAP",
            "test_policy_bundle_id_downgrade.py::test_unpinned_gate_accepts_swapped_bundle_id_KNOWN_GAP",
        ],
    },
    "policy-default-allow": {
        "status": "NOT_DEFENDED",
        "adaptive": "BYPASSABLE",
        "covering": [],
        "gap_tests": [
            "test_ruleset_default_allow.py::test_unmatched_action_falls_through_to_allow_KNOWN_GAP",
            "test_pql_silent_fail_open.py::test_empty_vendor_feed_compiles_to_allow_all_KNOWN_GAP",
        ],
    },
    "tenant-crossover": {
        "status": "DEFENDED",
        "adaptive": "STABLE",
        "covering": [
            "test_tenant_safety.py::test_tenant_a_receipt_cannot_authorize_tenant_b_action",
            "test_executor_guard.py::test_executor_refuses_wrong_tenant",
        ],
        "gap_tests": [],
    },
    "signature-stripping": {
        "status": "DEFENDED",
        "adaptive": "STABLE",
        "covering": [
            "test_receipt_signing.py::test_unsigned_rejected_when_required",
            "test_receipt_signing.py::test_signed_receipt_without_verifier_rejected",
        ],
        "gap_tests": [],
    },
    "validator-bypass": {
        "status": "PARTIAL",
        "adaptive": "BYPASSABLE",
        "covering": [
            "test_maci_role_separation.py::test_issuance_refuses_self_validation",
            "test_executor_guard.py::test_executor_refuses_denied_receipt",
        ],
        "gap_tests": [
            "test_authority_scope_unenforced.py::test_gate_ignores_authority_grant_KNOWN_GAP",
        ],
    },
    "evidence-omission": {
        "status": "DEFENDED",
        "adaptive": "STABLE",
        "covering": [
            "test_kernel_dispatch.py::test_every_dispatch_anchors_in_audit_chain",
            "test_executor_guard.py::test_executor_refuses_no_receipt",
        ],
        "gap_tests": [],
    },
    "adapter-bypass": {
        "status": "NOT_DEFENDED",
        "adaptive": "BYPASSABLE",
        "covering": [],
        "gap_tests": [
            "test_adapter_bypass.py::test_managed_agent_default_policy_executes_untrusted_tool_KNOWN_LIMITATION",
        ],
    },
}
_VALID_ADAPTIVE_STATUSES = frozenset({"STABLE", "BYPASSABLE", "UNTESTED"})

EXPECTED_CLASSES = frozenset(MANIFEST)
_VALID_STATUSES = frozenset({"DEFENDED", "PARTIAL", "NOT_DEFENDED"})


def _node_exists(node: str, base: Path) -> bool:
    """A '<file>::<test_name>' node exists iff the file exists and defines it."""
    filename, _, test_name = node.partition("::")
    path = base / filename
    if not path.is_file():
        return False
    return f"def {test_name}(" in path.read_text(encoding="utf-8")


def test_all_adversary_classes_are_enumerated() -> None:
    expected = {
        "forged-authorization",
        "replayed-authorization",
        "ledger-tampering",
        "policy-downgrade",
        "policy-default-allow",
        "tenant-crossover",
        "signature-stripping",
        "validator-bypass",
        "evidence-omission",
        "adapter-bypass",
    }
    assert expected == EXPECTED_CLASSES
    assert len(MANIFEST) == 10
    assert all(entry["status"] in _VALID_STATUSES for entry in MANIFEST.values())
    assert all(entry["adaptive"] in _VALID_ADAPTIVE_STATUSES for entry in MANIFEST.values())


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
    """Every PARTIAL/NOT_DEFENDED class must point at a real gap test in this
    directory, so no gap is asserted without a tripwire proving it. DEFENDED
    classes must carry NO gap test (a defended claim with a live 'attack succeeds'
    test would be a contradiction)."""
    missing: list[str] = []
    for cls, entry in MANIFEST.items():
        if entry["status"] == "DEFENDED":
            assert not entry["gap_tests"], f"{cls}: DEFENDED must have no gap_tests"
            continue
        gap_tests = entry["gap_tests"]  # type: ignore[assignment]
        assert gap_tests, f"{cls}: {entry['status']} must name at least one gap test"
        for node in gap_tests:  # type: ignore[union-attr]
            if not _node_exists(node, ADV_DIR):
                missing.append(f"{cls}: {node}")
    assert not missing, "gap tests referenced but not found:\n" + "\n".join(missing)


def test_taxonomy_posture_is_pinned() -> None:
    """Pin the honest headline: 3 defended, 5 partial, 2 not-defended. Changing the
    posture must be a deliberate edit here, not an accident. Threat-model-v2 §10 is the
    prose companion to this pin."""
    defended = {c for c, e in MANIFEST.items() if e["status"] == "DEFENDED"}
    partial = {c for c, e in MANIFEST.items() if e["status"] == "PARTIAL"}
    not_defended = {c for c, e in MANIFEST.items() if e["status"] == "NOT_DEFENDED"}

    assert defended == {
        "tenant-crossover",
        "signature-stripping",
        "evidence-omission",
    }, defended
    assert partial == {
        "forged-authorization",
        "replayed-authorization",
        "ledger-tampering",
        "policy-downgrade",
        "validator-bypass",
    }, partial
    assert not_defended == {"policy-default-allow", "adapter-bypass"}, not_defended
