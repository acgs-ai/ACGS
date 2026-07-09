"""Adversary class: PRIVILEGE ESCALATION via unenforced authority scope.

``authority`` and ``validator_role`` are bound into ``receipt_hash`` (so tampering is
caught) and CAN be checked by ``DecisionReceipt.verify(expected_authority=...,
expected_validator_role=...)``. But NO gate surface plumbs them: ``execute_with_receipt``,
``GovernedExecutor.execute``, and ``resume_with_receipt`` neither accept nor forward
``expected_authority``/``expected_validator_role``. So a deployment that treats
``authority`` as a privilege boundary cannot enforce it at the gate — a correctly
tenant/boundary/actor/action-bound receipt for the WRONG authority scope executes.

See threat-model-v2.md §4(d). Action/args/actor escalation and self-validation ARE
gate-enforced and tested (test_maci_role_separation.py); this file covers the one
privilege residual that is untested at the gate.
"""

from __future__ import annotations

import inspect

import pytest

from gove_zone import ReceiptValidationError, execute_with_receipt

# Must match tests/adversary/conftest.py.
TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS = {"path": "safe.txt"}


def test_gate_ignores_authority_grant_KNOWN_GAP(side_effect, issue, run_gate) -> None:
    """No gate surface can pin the authority grant, so a receipt executes regardless of
    what authority scope the caller intended to require — the attack succeeds today."""
    # The gate exposes no expected_authority parameter at all:
    params = inspect.signature(execute_with_receipt).parameters
    assert "expected_authority" not in params, (
        "if execute_with_receipt gained expected_authority, the gap is closing — update "
        "the manifest and add the enforcement assertion."
    )
    assert "expected_validator_role" not in params

    receipt = issue(actor="agent-1")  # authority defaults to 'tenant-A/write-grant'
    result = run_gate(receipt, side_effect)

    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.run_count == 1


def test_raw_verify_can_pin_authority_HELD(issue) -> None:
    """The enforcement mechanism EXISTS — but only on direct verify(), not at any gate.
    A mismatched expected_authority is rejected here, proving the residual is 'not wired
    to the gate', not 'no mechanism'."""
    receipt = issue(actor="agent-1")  # authority = 'tenant-A/write-grant'
    with pytest.raises(ReceiptValidationError):
        receipt.verify(
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_actor="agent-1",
            expected_action=ACTION,
            expected_args=ARGS,
            expected_authority="tenant-A/ADMIN-grant",
        )
