"""Adversary class: TENANT ISOLATION — HELD tripwire in the adversary suite.

Both ``tenant_id`` and ``execution_boundary`` are hash-bound and checked by default at the
real gate (they are non-optional kwargs of ``execute_with_receipt``). This test keeps a
live adversarial tripwire in the adversary suite itself so a regression that dropped either
check is caught here, not only in the package suite (test_tenant_safety.py).

See threat-model-v2.md §5.
"""

from __future__ import annotations

import pytest

from gove_zone import ReceiptValidationError, execute_with_receipt

# Must match tests/adversary/conftest.py.
TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS = {"path": "safe.txt"}


def test_cross_tenant_and_cross_boundary_both_blocked_HELD(side_effect, issue) -> None:
    """A tenant-A/local-sandbox receipt authorizes neither tenant-B nor a different
    execution boundary — both are rejected and the side effect never runs."""
    receipt = issue()  # tenant-A / local-sandbox

    with pytest.raises(ReceiptValidationError):
        execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id="tenant-B",  # cross-tenant
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-1",
            require_signature=False,
        )

    with pytest.raises(ReceiptValidationError):
        execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary="prod-cluster",  # cross-boundary
            expected_action=ACTION,
            expected_actor="agent-1",
            require_signature=False,
        )

    assert side_effect.run_count == 0
