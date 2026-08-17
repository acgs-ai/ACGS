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
widened so that absence is representable.

Three layers, kept deliberately separate
----------------------------------------

- **Claim** — ``status`` / ``adaptive``. What this repository *declares* about a
  class. Hand-maintained.
- **Evidence** — ``covering``, plus the ``GAP``/``BOUNDARY`` kind that
  :func:`_evidence_kind` derives *from the cited test itself* (an ``xfail``
  marker or the repo's ``_KNOWN_GAP`` name suffix), not from a label repeated
  here. Evidence a maintainer can relabel by hand is not independent evidence.
- **Verifier** — the tests below, which check the claim against the evidence.

What the verifier does and does not establish
---------------------------------------------

It checks *consistency*, not truth. Passing means the declared posture does not
contradict the kind of evidence cited for it. It cannot show that a control is
correct, that coverage is sufficient, or that a class is genuinely defended —
no manifest can. Specifically:

- ``DEFENDED`` requires at least one boundary-asserting test and **no** test
  that documents a residual gap. This is what makes posture inflation cost
  something: flipping a class to ``DEFENDED`` while it still cites a gap-marked
  test fails, so the evidence must change too.
- ``BYPASSABLE`` requires at least one gap-documenting test.
- ``PARTIAL`` requires at least one boundary-asserting test. The "does not cover
  the whole class" half is prose and is **not** machine-checked.
- ``UNKNOWN`` must cite nothing, so a gap cannot be recorded while evidence
  exists that would settle it.

Each entry names real ``file::test`` nodes under ``packages/gove-zone/tests``.
The tests below assert every one resolves inside that tree, so the taxonomy
cannot silently rot.
"""

from __future__ import annotations

import ast
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
        # production. PARTIAL: a static AST check does run in CI
        # (test_gate_wiring_matrix.py, via saas-beta-required.yml), and an
        # in-process direct call is blocked and audited. But that check asserts
        # only that a gate symbol is imported *and* called somewhere in the
        # module, over the examples INTEGRATION_MATRIX.md claims as shipped —
        # not that the side effect is mediated, and not over integrator code.
        # Nothing detects an ungoverned effect path added outside that set.
        "status": "PARTIAL",
        "adaptive": "UNTESTED",
        "covering": [
            "test_gate_wiring_matrix.py::test_shipped_example_routes_through_gate",
            "test_universal_gateway.py::test_direct_sealed_call_is_blocked_and_audited",
        ],
    },
    "compromised-host": {
        # Attacker controls process memory, filesystem, and clock. BYPASSABLE
        # rests on the xfail residual: keyless ``verify_chain()`` accepts a
        # self-consistent full rewrite, and only a caller-supplied external
        # anchor detects it. Signing keys are readable by definition under this
        # adversary. The truncation test is cited alongside it because it
        # asserts the *anchored* boundary affirmatively (length_mismatch and
        # last_hash_mismatch), so the pair records both halves: what the anchor
        # catches, and what its absence does not.
        "status": "BYPASSABLE",
        "adaptive": "UNTESTED",
        "covering": [
            "test_mutation_suite.py::test_keyless_full_rewrite_residual_KNOWN_GAP",
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


def _resolve_node(node: str) -> tuple[Path, str] | None:
    """Resolve ``<file>::<test_name>`` to a real test function, or ``None``.

    Rejects anything that is not a ``test_``-prefixed function in a ``.py`` file
    *inside* ``TESTS_DIR``. Without the containment check a covering entry could
    cite ``../src/gove_zone/audit.py::...`` and satisfy the existence invariant
    with a source file rather than a test.
    """
    filename, sep, test_name = node.partition("::")
    if not sep or not test_name.startswith("test_"):
        return None
    path = (TESTS_DIR / filename).resolve()
    if path.suffix != ".py" or not path.is_relative_to(TESTS_DIR) or not path.is_file():
        return None
    return (path, test_name) if f"def {test_name}(" in path.read_text(encoding="utf-8") else None


def _node_exists(node: str) -> bool:
    return _resolve_node(node) is not None


def _evidence_kind(node: str) -> str:
    """``GAP`` or ``BOUNDARY``, derived from the cited test, not from a label.

    A test counts as gap-documenting when it is marked ``xfail`` or carries the
    repository's ``_KNOWN_GAP`` name suffix — both of which say "this reproduces
    a residual we have not closed". Everything else is read as asserting a
    boundary. Deriving this from the test source is the point: a maintainer
    cannot inflate a posture by editing a label next to the claim.
    """
    resolved = _resolve_node(node)
    if resolved is None:
        return "BOUNDARY"
    path, test_name = resolved
    if test_name.endswith("_KNOWN_GAP"):
        return "GAP"
    for item in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if (
            isinstance(item, ast.FunctionDef)
            and item.name == test_name
            and any("xfail" in ast.dump(dec) for dec in item.decorator_list)
        ):
            return "GAP"
    return "BOUNDARY"


def _posture_evidence_violations(manifest: dict[str, ManifestEntry]) -> list[str]:
    """Check each declared posture against the *kind* of evidence it cites.

    Consistency only — see the module docstring for what this does not prove.
    """
    violations: list[str] = []
    for cls, entry in sorted(manifest.items()):
        kinds = {_evidence_kind(node) for node in entry["covering"]}
        status = entry["status"]
        if status == "DEFENDED" and "GAP" in kinds:
            violations.append(f"{cls}: DEFENDED while citing a gap-documenting test")
        if status in {"DEFENDED", "PARTIAL"} and "BOUNDARY" not in kinds:
            violations.append(f"{cls}: {status} without any boundary-asserting test")
        if status == "BYPASSABLE" and "GAP" not in kinds:
            violations.append(f"{cls}: BYPASSABLE without any gap-documenting test")
    return violations


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


def test_covering_nodes_must_resolve_inside_the_test_tree() -> None:
    """A source file, a private helper, or a path escaping ``tests/`` is not evidence."""
    for forged in (
        "../src/gove_zone/audit.py::test_verify_chain_detects_whole_event_truncation",
        "test_audit_chain_corruption.py::_record",
        "test_audit_chain_corruption.py",
    ):
        assert not _node_exists(forged), f"accepted a non-test covering node: {forged}"


def test_declared_posture_is_consistent_with_its_evidence() -> None:
    violations = _posture_evidence_violations(MANIFEST)
    assert not violations, "posture contradicts the evidence cited for it:\n" + "\n".join(
        violations
    )


def test_posture_inflation_without_new_evidence_is_rejected() -> None:
    """The negative case that gives the consistency check teeth.

    Before this rule, flipping ``compromised-host`` from BYPASSABLE to DEFENDED
    with its ``covering`` list completely unchanged passed every invariant —
    posture inflation was free. It must now cost a change in evidence, because
    the class still cites an xfail-marked residual.
    """
    inflated: dict[str, ManifestEntry] = dict(MANIFEST)
    inflated["compromised-host"] = {
        **MANIFEST["compromised-host"],
        "status": "DEFENDED",
    }

    violations = _posture_evidence_violations(inflated)
    assert any("compromised-host" in v and "DEFENDED" in v for v in violations), (
        f"claiming DEFENDED while still citing a gap-documenting test must fail; got: {violations}"
    )
