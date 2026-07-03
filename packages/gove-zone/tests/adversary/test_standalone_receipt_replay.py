"""Adversary class: REPLAYED-AUTHORIZATION (standalone receipt reuse).

Status on this branch: NOT-DEFENDED (open gap).

Intra-workflow step replay IS blocked (test_workflow_receipt_chain.py's per-run
step ledger). But ``execute_with_receipt`` is stateless: its body is
``receipt.verify(...)`` then ``tool_fn(**args)`` with nothing that consumes or
records the receipt. So a single ALLOW receipt authorizes unbounded
re-execution across separate gate invocations. There is no ReceiptConsumptionLedger
wired into the standalone gate on this branch (verified: grep of executor.py /
receipt.py finds none), and test_escalation_resume.py pins this as a KNOWN
LIMITATION.

This file makes the gap a live, visible tripwire instead of a buried caveat.
"""

from __future__ import annotations

import pytest

from gove_zone import ReceiptValidationError


def test_standalone_receipt_is_replayable_KNOWN_LIMITATION(side_effect, issue, run_gate) -> None:
    """The SAME receipt authorizes N executions — the attack succeeds today.

    This asserts the current (weaker) reality so the limitation cannot be
    silently claimed as defended. If it starts failing, either the gap closed
    (good — update the manifest and the xfail below) or a regression changed
    gate behavior (investigate).
    """
    receipt = issue()

    first = run_gate(receipt, side_effect)
    second = run_gate(receipt, side_effect)  # replay: identical receipt, new call

    assert first == "SIDE EFFECT EXECUTED"
    assert second == "SIDE EFFECT EXECUTED"
    assert side_effect.run_count == 2, (
        "standalone-receipt replay is expected to succeed on this branch; "
        "if run_count != 2 the gap may have been closed or a regression occurred"
    )


@pytest.mark.xfail(
    reason="single-use / nonce enforcement is not wired into execute_with_receipt "
    "on this branch; this flips to xpass when a ReceiptConsumptionLedger rejects "
    "the second use.",
    strict=False,
)
def test_standalone_receipt_replay_should_be_rejected(side_effect, issue, run_gate) -> None:
    """The DEFENDED expectation: a single-use gate rejects the second use.

    Kept as an xfail so the day the defense lands it turns xpass — a built-in
    'defense arrived' signal — without failing CI in the meantime.
    """
    receipt = issue()
    run_gate(receipt, side_effect)
    with pytest.raises(ReceiptValidationError):
        run_gate(receipt, side_effect)
