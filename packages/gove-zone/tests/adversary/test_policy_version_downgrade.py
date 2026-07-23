"""Adversary class: POLICY-DOWNGRADE (older/weaker policy receipt).

Status on this branch: PARTIAL — policy binding exists but is OPT-IN.

``execute_with_receipt``'s ``expected_policy_hash`` defaults to ``None`` (verified
in executor.py). When the integrator does not pin it, a receipt minted under any
older / more permissive policy is accepted — the gate never compares the
receipt's ``policy_hash`` to the policy actually in force. The MITIGATION already
exists (pin ``expected_policy_hash``), so this is a genuine paired adversary
test: the attack succeeds undefended and fails defended. It is NOT redundant with
test_tenant_safety.py::test_policy_hash_mismatch_fails_closed (which only tests the
pinned path) — the net-new assertion is that the DEFAULT (unpinned) path is a gap.
"""

from __future__ import annotations

from gove_zone import ReceiptValidationError
from tests.adversary.conftest import _SIGNER


def test_unpinned_gate_accepts_downgraded_policy_receipt_KNOWN_GAP(
    side_effect, issue, run_gate
) -> None:
    """Undefended: no pin -> a stale/permissive-policy receipt is accepted."""
    stale = issue(_SIGNER, policy_hash="policy/v1-permissive", policy_version="v1-permissive")

    result = run_gate(stale, side_effect, expected_policy_hash=None)

    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.ran is True, (
        "with expected_policy_hash unpinned, a downgraded-policy receipt is "
        "expected to be accepted on this branch (policy binding is opt-in)"
    )


def test_pinned_gate_rejects_downgraded_policy_receipt(side_effect, issue, run_gate) -> None:
    """Defended: pinning expected_policy_hash to the in-force policy rejects a
    receipt carrying a different (downgraded) policy_hash, and the side effect
    never runs."""
    stale = issue(_SIGNER, policy_hash="policy/v1-permissive", policy_version="v1-permissive")

    try:
        run_gate(stale, side_effect, expected_policy_hash="policy/v2-current")
        raised = False
    except ReceiptValidationError:
        raised = True

    assert raised, "pinned expected_policy_hash must reject a downgraded receipt"
    assert side_effect.ran is False


def test_pinned_gate_accepts_matching_policy_receipt(side_effect, issue, run_gate) -> None:
    """Control: the same pin ACCEPTS a receipt whose policy_hash matches, proving
    the rejection above is about the downgrade, not about pinning per se."""
    current = issue(_SIGNER, policy_hash="policy/v2-current", policy_version="v2-current")

    result = run_gate(current, side_effect, expected_policy_hash="policy/v2-current")

    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.ran is True
