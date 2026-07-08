"""Design test #22: canonicalizer_failure_is_deny_not_crash.

The gate (``governance/admission/gate.py``) hashes the request, decision
body, and policy bundle via ``sha256_json`` while building the decision
receipt. ``sha256_json`` uses ``json.dumps(..., default=str)``, which still
raises for real inputs — circular references (``ValueError``) and objects
whose ``__str__`` raises — and any future strict canonicalizer may raise
more.

Fail-closed contract implemented in ``decide()``/``_build_decision``:

- A canonicalization/hash failure during receipt construction converts the
  decision (including a computed ``allow``) into a ``deny`` with
  ``reason_code == "canonicalization_failure"``.
- The fallback deny grants nothing: ``effective_permissions == []`` and all
  requested capabilities are blocked.
- The degraded receipt sets any unproducible hash field to
  ``HASH_UNAVAILABLE``, which no replay verifier can reproduce, so the
  receipt also fails closed at verification time.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

from governance.admission.gate import HASH_UNAVAILABLE, decide
from governance.admission.policy import PolicyBundle
from governance.admission.replay import ReplayError, verify_decision

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _minimal_bundle() -> PolicyBundle:
    return PolicyBundle(
        bundle_id="test-bundle",
        version="v1",
        rules=[
            {
                "id": "allow-all",
                "action": "allow",
                "reason_code": "test_allow",
                "when": {},
            }
        ],
        raw={"bundle_id": "test-bundle", "version": "v1", "rules": []},
    )


def _minimal_request() -> dict:
    return {
        "schema_version": "admission_gate/0.1",
        "request_id": "req-canonical-failure-test",
        "workflow_id": "workflow-canonical-test",
        "run_id": "run-canonical-test",
        "phase": "workflow_admission",
        "actor": {"id": "test-agent", "role": "agent", "tenant": "default"},
        "declared_goal": "test canonicalizer failure handling",
        "proposed_method": "test",
        "risk_class": "low",
        "requested_capabilities": ["net.fetch"],
        "execution_boundary": {"environment": "local", "allowed_outputs": []},
        "policy_context": {
            "policy_bundle_id": "test-bundle",
            "evaluation_mode": "strict",
        },
        "inputs_manifest": {},
    }


def _assert_fail_closed_deny(result: dict) -> None:
    assert result["decision"] == "deny"
    assert result["reason_code"] == "canonicalization_failure"
    assert "canonicali" in str(result.get("reason", "")).lower()
    assert result["execution_boundary"]["effective_permissions"] == []
    assert result["execution_boundary"]["blocked_capabilities"] == ["net.fetch"]
    assert result["receipt"]["receipt_id"].startswith("rcpt_")


def test_canonicalizer_failure_is_deny_not_crash() -> None:
    """When sha256_json raises, decide() returns a fail-closed deny."""
    bundle = _minimal_bundle()
    request = _minimal_request()

    with patch(
        "governance.admission.gate.sha256_json",
        side_effect=ValueError("simulated canonicalization failure"),
    ):
        result = decide(request, policy_bundle=bundle)

    _assert_fail_closed_deny(result)
    receipt = result["receipt"]
    assert receipt["request_hash"] == HASH_UNAVAILABLE
    assert receipt["decision_hash"] == HASH_UNAVAILABLE
    # policy_bundle_hash goes through governance.admission.policy, which was
    # not patched — the bundle itself is still hashable.
    assert _HEX64.match(receipt["policy_bundle_hash"])


def test_degraded_receipt_fails_replay_verification() -> None:
    """A degraded receipt must never verify — fail-closed at replay too."""
    bundle = _minimal_bundle()
    request = _minimal_request()

    with patch(
        "governance.admission.gate.sha256_json",
        side_effect=ValueError("simulated canonicalization failure"),
    ):
        result = decide(request, policy_bundle=bundle)

    with pytest.raises(ReplayError):
        verify_decision(request=request, decision=result, policy_bundle=bundle)


def test_circular_reference_request_is_denied() -> None:
    """Real raise path: json.dumps detects circular refs even with default=str."""
    bundle = _minimal_bundle()
    request = _minimal_request()
    circular: dict = {}
    circular["self"] = circular
    request["inputs_manifest"] = circular

    result = decide(request, policy_bundle=bundle)

    _assert_fail_closed_deny(result)
    receipt = result["receipt"]
    assert receipt["request_hash"] == HASH_UNAVAILABLE
    # The fallback deny body itself is built from safe coercions, so its
    # hash (and the bundle hash) are still real and tamper-evident.
    assert _HEX64.match(receipt["decision_hash"])
    assert _HEX64.match(receipt["policy_bundle_hash"])


def test_unstringable_object_in_request_is_denied() -> None:
    """Real raise path: default=str calls str(), which itself can raise."""

    class Unstringable:
        def __str__(self) -> str:
            raise RuntimeError("cannot stringify")

    bundle = _minimal_bundle()
    request = _minimal_request()
    request["inputs_manifest"] = {"artifact": Unstringable()}

    result = decide(request, policy_bundle=bundle)

    _assert_fail_closed_deny(result)
    assert result["receipt"]["request_hash"] == HASH_UNAVAILABLE


def test_hashable_request_still_produces_real_receipt() -> None:
    """The fail-closed path must not disturb currently-hashable payloads."""
    bundle = _minimal_bundle()
    request = _minimal_request()

    result = decide(request, policy_bundle=bundle)

    assert result["decision"] == "allow"
    assert result["reason_code"] == "test_allow"
    for field in ("request_hash", "decision_hash", "policy_bundle_hash"):
        assert _HEX64.match(result["receipt"][field]), field
