"""CI enforcement for the ACGS Physical Execution Profile RFC.

The RFC (``docs/design/acgs-physical-execution-profile.md``) declares five
decisions frozen before P0 implementation. Until this file existed, that freeze
was enforced by human review only — a reviewer had to notice that an edit
quietly relaxed one. These tests make the freeze mechanical.

Design note on brittleness: these assertions deliberately match **structure and
distinctive tokens**, never long prose sentences. A gate that asserts a full
paragraph turns every editorial commit red and trains people to edit the gate
instead of restoring the invariant — which is exactly backwards. Prose may be
rewritten freely here; the invariants may not.

Scope is limited to the physical execution profile. Other ``docs/design/*.md``
files belong to different work streams and are not governed by this file.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RFC = "docs/design/acgs-physical-execution-profile.md"

# Responses that must never be reachable from a fault or a geometric violation.
PATH_FOLLOWING_RESPONSE = "ramp_stop"

# A violation of any of these means the commanded path itself is untrustworthy,
# so continuing along it is never an acceptable response.
NO_PATH_FOLLOWING_TRIGGERS = (
    "TorqueSensorMismatch",
    "ActuatorIntegrityFailure",
    "SDF / forbidden zone",
    "Non-finite setpoint",
    "Calibration epoch change",
    "Lease revoked",
)

# Every field the execution binding must commit to. Dropping any one of these
# re-opens a replay path: the same trajectory bytes becoming valid in a
# different physical context.
EXECUTION_ROOT_BINDINGS = (
    "merkle_root",
    "receipt_id",
    "robot_id",
    "calibration_digest",
    "contract_digest",
    "lease_id",
    "calibration_epoch",
    "boot_id",
)

# The loader verifies and refuses. It never decides.
LOADER_PROHIBITIONS = (
    "modify or re-derive constraints",
    "resolve conflicts",
    "upgrade, widen",
    "substitute a default",
    "recompute a digest",
)

# Claim boundaries. These must stay absent regardless of how the RFC evolves.
#
# Each entry must be a phrase that can ONLY appear as a claim. Loose terms are
# actively harmful here: "certified safe" also matches the disclaimer "requires
# a certified safety function", so banning it would flag the RFC for correctly
# disclaiming certification. A gate that fires on its own disclaimers teaches
# people to delete disclaimers.
FORBIDDEN_CLAIMS = (
    "production-certified",
    "compliance-certified",
    "safety-certified",
    "regulator-approved",
    "formal verification complete",
    "guaranteed safe",
    "production-ready",
)


def _rfc() -> str:
    path = ROOT / RFC
    assert path.is_file(), f"missing design RFC: {RFC}"
    return path.read_text(encoding="utf-8")


def _table_rows(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.lstrip().startswith("|")]


def _prose(text: str) -> str:
    """Lowercase text with markdown emphasis and line breaks flattened.

    Claim-boundary sentences carry bold/italic markers that move around during
    ordinary editing (``is **not** a functional-safety system``). Matching the
    normalized form keeps the gate anchored to the claim rather than to its
    current formatting.
    """
    return re.sub(r"\s+", " ", text.replace("*", "").replace("`", "")).lower()


def test_rfc_declares_its_frozen_decisions() -> None:
    """The freeze section must exist and still carry five numbered decisions."""
    text = _rfc()
    assert "Frozen before P0" in text, "RFC lost its frozen-decision section"

    _, _, tail = text.partition("### Frozen before P0")
    section, _, _ = tail.partition("### Open questions")
    numbered = re.findall(r"^\d+\.\s+\*\*", section, flags=re.MULTILINE)
    assert len(numbered) == 5, (
        f"expected 5 frozen decisions, found {len(numbered)}. "
        "Adding or removing one is an RFC amendment, not an edit."
    )


def test_fault_and_geometric_violations_never_follow_the_path() -> None:
    """A fault or geometric violation must not resolve to ``ramp_stop``.

    ``ramp_stop`` decelerates *along the authorized path*. Applying it to an SDF
    or forbidden-zone violation drives the robot into the obstacle that
    triggered the stop; applying it to a fault keeps following a trajectory
    planned against dynamics that no longer describe the machine.
    """
    rows = _table_rows(_rfc())
    for trigger in NO_PATH_FOLLOWING_TRIGGERS:
        matching = [r for r in rows if trigger in r]
        assert matching, f"violation class disappeared from the RFC: {trigger}"
        for row in matching:
            assert PATH_FOLLOWING_RESPONSE not in row, (
                f"{trigger!r} maps to {PATH_FOLLOWING_RESPONSE!r}; a fault or "
                "geometric violation must never continue along the path"
            )


def test_torque_taxonomy_separates_envelope_breach_from_fault() -> None:
    """A limit breach and a fault must remain distinct classes."""
    text = _rfc()
    for token in (
        "TorqueEnvelopeViolation",
        "TorqueSensorMismatch",
        "ActuatorIntegrityFailure",
    ):
        assert token in text, f"torque taxonomy lost its {token} class"

    envelope_rows = [r for r in _table_rows(text) if "TorqueEnvelopeViolation" in r]
    assert envelope_rows, "TorqueEnvelopeViolation left the response table"
    assert any(PATH_FOLLOWING_RESPONSE in r for r in envelope_rows), (
        "TorqueEnvelopeViolation no longer maps to ramp_stop — an envelope "
        "breach leaves the model intact and the path valid"
    )


def test_execution_root_binds_the_full_physical_context() -> None:
    """The enforced root must commit to context, not just trajectory bytes."""
    text = _rfc()
    assert "execution_root" in text, "execution_root binding removed"
    _, _, tail = text.partition("execution_root = H(")
    formula, _, _ = tail.partition(")")
    assert formula, "execution_root derivation formula removed"
    for field in EXECUTION_ROOT_BINDINGS:
        assert field in formula, (
            f"execution_root no longer binds {field!r}; dropping it re-opens "
            "replay of the same trajectory in a different physical context"
        )


def test_loader_cannot_become_a_second_authority() -> None:
    """The compiler decides; the loader only verifies and refuses."""
    text = _rfc()
    assert "Compiler / Loader authority boundary" in text
    for prohibition in LOADER_PROHIBITIONS:
        assert prohibition in text, (
            f"loader prohibition removed: {prohibition!r}. A loader that can "
            "decide is a second authority with no receipt recording which won."
        )


def test_constraint_compilation_is_monotonic() -> None:
    """Narrowing is allowed; relaxation must fail compilation."""
    text = _rfc()
    assert "operator_override  ⊆  cell_policy  ⊆  robot_capability" in text, (
        "constraint monotonicity lattice removed or reordered"
    )
    assert "CompilationRejected" in text or "FAILS COMPILATION" in text, (
        "relaxation no longer produces a compile-time failure"
    )


def test_calibration_drift_is_checked_live() -> None:
    """T-13 must stay a per-tick check, not an activation-time snapshot."""
    text = _rfc()
    assert "T-13" in text, "calibration drift threat removed"
    assert "calibration_epoch" in text, "calibration epoch guard removed"


def test_threat_ids_are_contiguous() -> None:
    """No threat may be silently dropped from the middle of the table."""
    found = sorted({int(m) for m in re.findall(r"\|\s*T-(\d{2})\s*\|", _rfc())})
    assert found, "threat table has no entries"
    assert found == list(range(1, len(found) + 1)), f"threat ids are not contiguous: {found}"


def test_rfc_makes_no_certification_or_safety_claim() -> None:
    """Authority is not safety, and this RFC must never imply otherwise."""
    prose = _prose(_rfc())
    for phrase in FORBIDDEN_CLAIMS:
        assert phrase not in prose, f"RFC makes a forbidden claim: {phrase!r}"

    for required in (
        "not a functional-safety system",
        "signature is not a safety case",
        "design budgets, not measurements",
    ):
        assert required in prose, f"RFC lost its claim boundary: {required!r}"
