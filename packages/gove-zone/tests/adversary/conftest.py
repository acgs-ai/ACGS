"""Shared fixtures for the adversary suite (Pack II artifact B2).

These mirror the canonical governed-run idiom from
``packages/gove-zone/tests/test_receipt_signing.py`` (``_issue`` / ``_run_gate``)
so every adversary test exercises the REAL gate — ``execute_with_receipt`` —
rather than a re-implemented or mocked kernel. A test that passes for the wrong
reason (import error, mocked gate, vacuous assertion) is a BLOCKER, so a
positive control (``test_fixtures_baseline.py``) proves the fixtures produce a
genuinely valid governed run before any "attack succeeds" assertion is trusted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

# The adversary gaps here concern the receipt gate; the signing machinery needs
# `cryptography`. Skip cleanly where the optional extra is absent (same pattern
# as the rest of the security suite) so this dir never hard-fails collection.
pytest.importorskip("cryptography")

from gove_zone import (  # noqa: E402  (after importorskip by design)
    Decision,
    DecisionReceipt,
    DecisionRecord,
    Validator,
    execute_with_receipt,
)
from gove_zone.decision import sha256_json  # noqa: E402

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS: dict[str, Any] = {"path": "safe.txt"}


class SideEffect:
    """A guarded side effect that records whether — and how often — it ran."""

    def __init__(self) -> None:
        self.ran = False
        self.run_count = 0
        self.args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.run_count += 1
        self.args = kwargs
        return "SIDE EFFECT EXECUTED"


def _issue_allow_receipt(
    signer: Any | None = None,
    *,
    actor: str = "agent-1",
    validator_id: str = "constitutional-council",
    policy_version: str = "v2-current",
    policy_hash: str = "policy/v2-current",
    args: dict[str, Any] | None = None,
) -> DecisionReceipt:
    """Mint an ALLOW receipt, optionally signed, via the real receipt schema."""
    effective_args = args if args is not None else ARGS
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(effective_args),
        policy_version=policy_version,
        event_id="ev_adversary",
        actor=actor,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash=policy_hash,
        request_id="req-123",
        validator=Validator(validator_id),
        authority="tenant-A/write-grant",
        signer=signer,
    )


def _run_gate(
    receipt: DecisionReceipt | None,
    side_effect: SideEffect,
    *,
    verifier: Any = None,
    require_signature: bool = False,
    args: dict[str, Any] | None = None,
    expected_actor: str = "agent-1",
    expected_policy_hash: str | None = None,
) -> Any:
    """Run a receipt through the real gate. Dev posture by default
    (unsigned + require_signature=False), matching the security suite."""
    return execute_with_receipt(
        tool_fn=side_effect.run,
        args=args if args is not None else ARGS,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=expected_actor,
        expected_policy_hash=expected_policy_hash,
        verifier=verifier,
        require_signature=require_signature,
    )


@pytest.fixture
def side_effect() -> SideEffect:
    return SideEffect()


@pytest.fixture
def issue() -> Callable[..., DecisionReceipt]:
    """Factory that mints an ALLOW receipt (see ``_issue_allow_receipt``)."""
    return _issue_allow_receipt


@pytest.fixture
def run_gate() -> Callable[..., Any]:
    """The real governed gate (see ``_run_gate``)."""
    return _run_gate
