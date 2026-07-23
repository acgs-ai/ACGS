"""Positive control for the adversary fixtures.

If these fail, every "attack succeeds when undefended" assertion in this suite
is suspect (it might pass because the harness is broken, not because the gap is
real). This guards against the A1 anti-pattern: a test that passes for the
wrong reason.
"""

from __future__ import annotations

import pytest

from gove_zone import ReceiptValidationError
from tests.adversary.conftest import _SIGNER


def test_valid_receipt_executes_exactly_once(side_effect, issue, run_gate) -> None:
    """A well-formed ALLOW receipt runs the guarded side effect once."""
    result = run_gate(issue(_SIGNER), side_effect)
    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.ran is True
    assert side_effect.run_count == 1


def test_missing_receipt_fails_closed(side_effect, run_gate) -> None:
    """No receipt -> no side effect (sanity that the gate is really gating)."""
    with pytest.raises(ReceiptValidationError):
        run_gate(None, side_effect)
    assert side_effect.ran is False
