"""The gove-zone adversary taxonomy, made explicit and machine-checked.

This is Pack II artifact B2, reconciled against current ``master``. The static
``status`` records this repository's posture against a class; the separate
``adaptive`` value records the result of the bounded variant family in
``adaptive.py``. The two are independent axes: a class can have dedicated
coverage (``status`` DEFENDED) while the adaptive layer still finds a bypassing
variant (``adaptive`` BYPASSABLE). Read both.

``status`` vocabulary:

- ``DEFENDED``   — dedicated coverage exists and asserts the boundary holds.
- ``PARTIAL``    — a real control exists but does not cover the whole class.
- ``BYPASSABLE`` — the class defeats the current controls; the covering test
  documents *how*, rather than asserting a boundary.
- ``UNKNOWN``    — no evidence either way. Carries no covering tests by
  construction.

``status`` was formerly ``Literal["DEFENDED"]``, so every class read DEFENDED by
construction and the schema could not express a gap — which is also why a class
with no coverage could not be added to the taxonomy at all. The vocabulary is
widened so that absence is representable. This is deliberately a schema change,
not an evidence change: the eight original classes keep the posture their
existing tests actually support.

Two invariants keep the wider vocabulary honest in both directions. A class may
not claim ``DEFENDED``/``PARTIAL``/``BYPASSABLE`` without citing at least one
real test, so a posture cannot be asserted without evidence; and a class may not
claim ``UNKNOWN`` while citing tests, so a gap cannot be recorded while evidence
exists that would settle it.

Each entry names real ``file::test`` nodes in ``packages/gove-zone/tests``. The
tests below assert every one exists, so the taxonomy cannot silently rot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, TypedDict


class ManifestEntry(TypedDict):
    status: Literal["DEFENDED", "PARTIAL", "BYPASSABLE", "UNKNOWN"]
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
    # The three classes below concern where the gate *sits* rather than what it
    # checks. None can reach DEFENDED from library code alone: each is closed by
    # a deployment topology that puts the enforcement point outside the
    # proposer's trust domain. They are enumerated here so the taxonomy states
    # that plainly instead of omitting it.
    "negligent-integrator": {
        # Wiring omissions, framework-native tool-calling paths that skip the
        # gate, and signature checks disabled in a test config that reaches
        # production. PARTIAL: shipped examples are proven to route through the
        # gate and an in-process direct call is blocked and audited, but nothing
        # detects a newly added ungoverned effect path — no static scan and no
        # CI job anywhere in the repository performs that check.
        "status": "PARTIAL",
        "adaptive": "UNTESTED",
        "covering": [
            "test_gate_wiring_matrix.py::test_shipped_example_routes_through_gate",
            "test_universal_gateway.py::test_direct_sealed_call_is_blocked_and_audited",
        ],
    },
    "compromised-host": {
        # Attacker controls process memory, filesystem, and clock. BYPASSABLE:
        # the covering test documents the bypass rather than asserting a
        # boundary — a keyless ``verify_chain()`` returns valid on a truncated
        # chain, and only a caller-supplied external anchor detects it. No
        # shipped src/ call site supplies one, so the default posture is
        # keyless. Signing keys are readable by definition under this adversary.
        "status": "BYPASSABLE",
        "adaptive": "UNTESTED",
        "covering": [
            "test_audit_chain_corruption.py::test_verify_chain_detects_whole_event_truncation",
        ],
    },
    "exec-capable-agent": {
        # A proposer holding shell or interpreter tools, able to author its own
        # side-effect code without ever calling a registered tool. UNKNOWN, not
        # BYPASSABLE: no test models it in either direction. The nearest control
        # is the sandbox, and when bwrap is absent it degrades to an
        # unrestricted subprocess behind a UserWarning -- a path test_sandbox.py
        # does not exercise. Closing this requires the reference enforcement
        # topology (WS-C), not a library change.
        "status": "UNKNOWN",
        "adaptive": "UNTESTED",
        "covering": [],
    },
}

EXPECTED_CLASSES = frozenset(MANIFEST)

# The taxonomy may grow, but these eight may never silently disappear.
BASELINE_CLASSES = frozenset(
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

_VALID_STATIC = frozenset({"DEFENDED", "PARTIAL", "BYPASSABLE", "UNKNOWN"})
_VALID_ADAPTIVE = frozenset({"STABLE", "BYPASSABLE", "UNTESTED"})
# A posture other than UNKNOWN is an evidence-bearing claim: it must cite a test.
_EVIDENCE_BEARING = frozenset({"DEFENDED", "PARTIAL", "BYPASSABLE"})


def _node_exists(node: str) -> bool:
    """``<file>::<test_name>`` exists iff the file defines that test function."""
    filename, _, test_name = node.partition("::")
    path = TESTS_DIR / filename
    return path.is_file() and f"def {test_name}(" in path.read_text(encoding="utf-8")


def test_baseline_classes_are_never_dropped() -> None:
    """The taxonomy may grow; it may not silently shrink."""
    dropped = BASELINE_CLASSES - EXPECTED_CLASSES
    assert not dropped, f"baseline adversary classes removed from the taxonomy: {sorted(dropped)}"


def test_every_class_uses_the_declared_vocabulary() -> None:
    bad_status = {
        cls: entry["status"]
        for cls, entry in MANIFEST.items()
        if entry["status"] not in _VALID_STATIC
    }
    assert not bad_status, f"unknown status values: {bad_status}"
    bad_adaptive = {
        cls: entry["adaptive"]
        for cls, entry in MANIFEST.items()
        if entry["adaptive"] not in _VALID_ADAPTIVE
    }
    assert not bad_adaptive, f"unknown adaptive values: {bad_adaptive}"


def test_a_posture_claim_must_cite_evidence() -> None:
    """DEFENDED / PARTIAL / BYPASSABLE all assert something about reality."""
    unevidenced = [
        cls
        for cls, entry in MANIFEST.items()
        if entry["status"] in _EVIDENCE_BEARING and not entry["covering"]
    ]
    assert not unevidenced, "classes claiming a posture with no covering test: " + ", ".join(
        sorted(unevidenced)
    )


def test_unknown_may_not_cite_evidence() -> None:
    """The converse: a gap cannot be recorded while tests exist that would settle it."""
    contradictory = {
        cls: entry["covering"]
        for cls, entry in MANIFEST.items()
        if entry["status"] == "UNKNOWN" and entry["covering"]
    }
    assert not contradictory, "classes marked UNKNOWN while citing covering tests: " + repr(
        contradictory
    )


def test_every_covering_test_actually_exists() -> None:
    missing: list[str] = []
    for cls, entry in MANIFEST.items():
        for node in entry["covering"]:
            if not _node_exists(node):
                missing.append(f"{cls}: {node}")
    assert not missing, "covering tests referenced but not found:\n" + "\n".join(missing)
