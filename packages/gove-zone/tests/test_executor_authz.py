"""Principal-authorization tests for the executor gate (B13 slice 2).

Slice 1 wired ``PrincipalRegistry`` authorization into the kernel dispatch path.
The executor (``execute_with_receipt`` / ``GovernedExecutor``) is a separate
governed-execution boundary the kernel does not own — and the path that
``workflow.py`` and ``escalation.py`` run through. These tests prove the same
fail-closed, off-by-default principal check now guards that boundary too:

- unauthorized principal -> ``AuthzDeniedError`` BEFORE receipt verify / ledger /
  tool, with the tool never executed;
- it is a strictly additional AND-gate: an otherwise-VALID receipt is still
  denied, so the denial is unambiguously the authz check;
- off by default -> behavior byte-for-byte unchanged;
- enforcing with no registry fails closed at construction.
"""

from __future__ import annotations

from typing import Any

import pytest

from gove_zone import (
    AuthzDeniedError,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    PrincipalEntry,
    PrincipalRegistry,
    Validator,
    execute_with_receipt,
)
from gove_zone.authz import AuthzReason
from gove_zone.decision import sha256_json

_ACTION = "runtime.file.write"
_ARGS: dict[str, Any] = {"path": "safe.txt"}


class _Spy:
    def __init__(self) -> None:
        self.called = False

    def run(self, **kwargs: Any) -> str:
        self.called = True
        return "success"


def _valid_allow_receipt() -> DecisionReceipt:
    """An otherwise-valid unsigned ALLOW receipt for ``anonymous`` / ``_ACTION``.

    Valid on every axis the gate checks, so a denial in these tests can only be
    the authz gate, not a receipt defect."""
    record = DecisionRecord(
        decision=Decision("allow"),
        tool=_ACTION,
        argument_hash=sha256_json(_ARGS),
        policy_version="v1",
        event_id="ev_authz",
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-authz",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )


def _registry(*entries: PrincipalEntry) -> PrincipalRegistry:
    reg = PrincipalRegistry()
    for entry in entries:
        reg.add(entry)
    return reg


def _run(spy: _Spy, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = dict(
        tool_fn=spy.run,
        args=_ARGS,
        receipt=_valid_allow_receipt(),
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action=_ACTION,
        expected_actor="anonymous",
        require_signature=False,  # dev mode: isolate the authz gate, not signing
    )
    kwargs.update(overrides)
    return execute_with_receipt(**kwargs)


def test_executor_authz_denies_unregistered_principal() -> None:
    """Enforce on + actor not in the registry -> AuthzDeniedError, tool never runs.
    The receipt is otherwise valid, so the denial is purely the authz gate."""
    spy = _Spy()
    with pytest.raises(AuthzDeniedError) as exc:
        _run(spy, authz_enforce=True, principal_registry=_registry(PrincipalEntry("other", None)))
    assert exc.value.reason is AuthzReason.UNREGISTERED_PRINCIPAL
    assert spy.called is False


def test_executor_authz_allows_registered_principal() -> None:
    """Positive control: actor registered + tool permitted -> the tool runs."""
    spy = _Spy()
    res = _run(
        spy,
        authz_enforce=True,
        principal_registry=_registry(PrincipalEntry("anonymous", frozenset({_ACTION}))),
    )
    assert res == "success"
    assert spy.called is True


def test_executor_authz_denies_tool_not_permitted() -> None:
    """Registered principal acting outside its allowed_tools -> denied, specific reason."""
    spy = _Spy()
    with pytest.raises(AuthzDeniedError) as exc:
        _run(
            spy,
            authz_enforce=True,
            principal_registry=_registry(PrincipalEntry("anonymous", frozenset({"other.action"}))),
        )
    assert exc.value.reason is AuthzReason.TOOL_NOT_PERMITTED
    assert spy.called is False


def test_executor_authz_off_by_default_runs() -> None:
    """Default OFF: an unregistered actor executes exactly as before."""
    spy = _Spy()
    res = _run(spy)  # no authz_enforce / principal_registry
    assert res == "success"
    assert spy.called is True


def test_executor_authz_enforce_without_registry_fails_closed() -> None:
    spy = _Spy()
    with pytest.raises(ValueError, match="requires a principal_registry"):
        _run(spy, authz_enforce=True)
    assert spy.called is False


def test_governed_executor_authz_denies_through_execute() -> None:
    """Wiring proof through the real GovernedExecutor.execute path (the one
    workflow.py and escalation.py use): unauthorized actor -> AuthzDeniedError,
    tool never runs."""
    spy = _Spy()
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=False,
        authz_enforce=True,
        principal_registry=_registry(PrincipalEntry("other", None)),
    )
    executor.register(_ACTION, spy.run)

    with pytest.raises(AuthzDeniedError):
        executor.execute(_ACTION, _ARGS, _valid_allow_receipt())
    assert spy.called is False


def test_governed_executor_authz_construction_fails_closed() -> None:
    with pytest.raises(ValueError, match="requires a principal_registry"):
        GovernedExecutor(
            tenant_id="tenant-A",
            execution_boundary="local-sandbox",
            expected_actor="anonymous",
            authz_enforce=True,
        )
