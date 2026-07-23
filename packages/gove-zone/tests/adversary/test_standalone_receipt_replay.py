"""Adversary class: REPLAYED-AUTHORIZATION (standalone receipt reuse).

The standalone gate must durably consume an authorization before invoking the
side effect and reject every later use of the receipt, nonce, or request id.
"""

from __future__ import annotations

import pytest

from gove_zone import ReceiptValidationError


def test_standalone_receipt_replay_is_rejected(side_effect, issue, run_gate) -> None:
    from tests.adversary.conftest import _SIGNER

    receipt = issue(_SIGNER)

    first = run_gate(receipt, side_effect)
    assert first == "SIDE EFFECT EXECUTED"
    with pytest.raises(ReceiptValidationError, match="receipt.execution.replay"):
        run_gate(receipt, side_effect)
    assert side_effect.run_count == 1
