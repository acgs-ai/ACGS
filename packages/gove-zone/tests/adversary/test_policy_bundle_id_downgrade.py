"""Adversary class: POLICY BYPASS via unpinned policy-bundle-id substitution.

Sibling of ``test_policy_version_downgrade.py``. ``expected_policy_bundle_id`` binds into
``receipt_hash`` and IS checked when pinned (receipt.py check 12), but defaults to ``None``
at every gate — so a caller who doesn't pin it accepts a receipt minted under a different
(e.g. stale/permissive) policy bundle. Unlike the policy-hash gap, the bundle-id path had
no adversarial test until now.

See threat-model-v2.md §2c.
"""

from __future__ import annotations

import pytest

from gove_zone import ReceiptValidationError, execute_with_receipt

# Must match tests/adversary/conftest.py.
TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS = {"path": "safe.txt"}


def test_unpinned_gate_accepts_swapped_bundle_id_KNOWN_GAP(side_effect, issue) -> None:
    """Caller does NOT pin expected_policy_bundle_id -> a receipt under any bundle id
    passes. The substitution succeeds today."""
    receipt = issue()  # policy_bundle_id = 'policy-bundle'

    result = execute_with_receipt(
        tool_fn=side_effect.run,
        args=ARGS,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor="agent-1",
        require_signature=False,
    )  # no expected_policy_bundle_id

    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.run_count == 1


def test_pinned_bundle_id_rejects_swap_HELD(side_effect, issue) -> None:
    """The mitigation works when engaged: pinning a different bundle id is rejected."""
    receipt = issue()  # policy_bundle_id = 'policy-bundle'

    with pytest.raises(ReceiptValidationError):
        execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-1",
            expected_policy_bundle_id="a-different-bundle",
            require_signature=False,
        )
    assert side_effect.run_count == 0
