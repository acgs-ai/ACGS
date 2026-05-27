"""Design test #22: canonicalizer_failure_is_deny_not_crash.

Investigation findings
----------------------
The gate (``governance/admission/gate.py``) uses ``sha256_json`` from
``governance.models``, which is::

    def stable_json(value):
        return json.dumps(value, sort_keys=True, ..., default=str)

``default=str`` means ``sha256_json`` **cannot raise** — every Python value
is coercible to a string via ``str()``, so the gate never encounters a
canonicalization error on the request or decision hash paths.

The Phase 2 strict canonicalizer (``governance.crypto.canonical.canonical_bytes``
/ ``CanonicalizationError``) is used only in the crypto signing path
(``hop_signature.sign_hop``), not in the gate decision path.

There is therefore **no deny-on-canonicalizer-failure path** in the gate today;
the design requirement that a canonicalizer failure must produce ``allow=False``
instead of propagating the exception is unimplemented.

This test documents the current (deficient) behavior with ``xfail(strict=True)``.
When the production fix lands (wrapping ``sha256_json`` calls in ``decide()`` with
a try/except that returns a deny decision), change this test to assert
``result["decision"] == "deny"``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from governance.admission.gate import decide
from governance.admission.policy import PolicyBundle


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
        "requested_capabilities": [],
        "execution_boundary": {"environment": "local", "allowed_outputs": []},
        "policy_context": {
            "policy_bundle_id": "test-bundle",
            "evaluation_mode": "strict",
        },
        "inputs_manifest": {},
    }


@pytest.mark.xfail(
    reason=(
        "design test #22: gate should convert canonicalizer failure to deny=False, "
        "currently sha256_json uses default=str and cannot raise, so no deny path exists"
    ),
    strict=True,
)
def test_canonicalizer_failure_currently_raises() -> None:
    """When sha256_json raises (simulated via monkeypatch), decide() should
    return allow=False rather than propagating the exception.

    Current behavior: the exception propagates (no try/except in decide()).
    Expected behavior per design test #22: decide() catches the error and
    returns a deny decision with a structured reason.
    """
    bundle = _minimal_bundle()
    request = _minimal_request()

    with patch(
        "governance.admission.gate.sha256_json",
        side_effect=ValueError("simulated canonicalization failure"),
    ):
        # Design requirement: should return deny, not raise
        result = decide(request, policy_bundle=bundle)
        assert result["decision"] == "deny"
        assert "canonicali" in str(result.get("reason", "")).lower() or result.get("reason_code") is not None
