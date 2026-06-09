"""Tests for GovernanceProfile — the named secure-by-default posture selector.

The profile resolves to a coherent (require_signature, signer, verifier) bundle
and selects production-by-default from $GOVE_ZONE_PROFILE, mirroring
current_gate_mode()/$GOVE_ZONE_GATE_MODE. These tests pin the default flip
(unset env → production) and the orthogonality to GateMode.
"""

from __future__ import annotations

from typing import Any

import pytest

from gove_zone import GovernanceProfile
from gove_zone.signing import NullSigner


class _FakeVerifier:
    """A minimal ReceiptSigner-shaped stand-in (no crypto extra needed)."""

    algorithm = "ed25519"
    key_id = "k1"

    def sign(self, payload: bytes) -> str:  # pragma: no cover - not exercised here
        return "sig"

    def verify(self, payload: bytes, signature: str) -> bool:  # pragma: no cover
        return True


def test_production_constructor_requires_signature() -> None:
    profile = GovernanceProfile.production()
    assert profile.name == "production"
    assert profile.is_production is True
    assert profile.require_signature is True
    # No key supplied here — selection and key configuration are independent.
    assert profile.signer is None
    assert profile.verifier is None


def test_production_carries_signer_and_verifier() -> None:
    signer = NullSigner()
    verifier = _FakeVerifier()
    profile = GovernanceProfile.production(signer=signer, verifier=verifier)
    assert profile.signer is signer
    assert profile.verifier is verifier
    assert profile.as_gate_kwargs() == {"require_signature": True, "verifier": verifier}


def test_dev_constructor_is_unsigned() -> None:
    profile = GovernanceProfile.dev()
    assert profile.name == "dev"
    assert profile.is_production is False
    assert profile.require_signature is False
    assert profile.signer is None
    assert profile.verifier is None
    assert profile.as_gate_kwargs() == {"require_signature": False, "verifier": None}


def test_from_env_unset_defaults_to_production() -> None:
    """DEFAULT-FLIP PROOF: an unset GOVE_ZONE_PROFILE resolves to production."""
    profile = GovernanceProfile.from_env(env={})
    assert profile.is_production is True
    assert profile.require_signature is True


@pytest.mark.parametrize("value", ["production", "PRODUCTION", "  production  ", ""])
def test_from_env_production_values(value: str) -> None:
    profile = GovernanceProfile.from_env(env={"GOVE_ZONE_PROFILE": value})
    assert profile.is_production is True
    assert profile.require_signature is True


@pytest.mark.parametrize("value", ["dev", "DEV", "  dev  "])
def test_from_env_dev_values(value: str) -> None:
    profile = GovernanceProfile.from_env(env={"GOVE_ZONE_PROFILE": value})
    assert profile.name == "dev"
    assert profile.require_signature is False


def test_from_env_unknown_value_falls_back_to_production() -> None:
    """An unrecognized value fails safe to production rather than silently
    downgrading to unsigned (mirrors current_gate_mode's secure-default behavior).
    """
    profile = GovernanceProfile.from_env(env={"GOVE_ZONE_PROFILE": "banana"})
    assert profile.is_production is True
    assert profile.require_signature is True


def test_from_env_forwards_keys_to_production() -> None:
    verifier = _FakeVerifier()
    profile = GovernanceProfile.from_env(env={}, verifier=verifier)
    assert profile.is_production is True
    assert profile.verifier is verifier


def test_from_env_reads_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")
    assert GovernanceProfile.from_env().name == "dev"
    monkeypatch.delenv("GOVE_ZONE_PROFILE", raising=False)
    assert GovernanceProfile.from_env().is_production is True


def test_profile_gate_kwargs_feed_execute_with_receipt() -> None:
    """The dev-profile bundle wires straight into the side-effect gate, proving
    the escape hatch is a coherent one-call opt-out for downstream callers.
    """
    from gove_zone import Decision, DecisionReceipt, DecisionRecord, Validator
    from gove_zone.decision import sha256_json
    from gove_zone.executor import execute_with_receipt

    args: dict[str, Any] = {"path": "safe.txt"}
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool="runtime.file.write",
        argument_hash=sha256_json(args),
        policy_version="v1",
        event_id="ev_profile",
        actor="agent-1",
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-1",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
    )

    ran: list[bool] = []

    def tool(**kwargs: Any) -> str:
        ran.append(True)
        return "ok"

    result = execute_with_receipt(
        tool_fn=tool,
        args=args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="agent-1",
        **GovernanceProfile.dev().as_gate_kwargs(),
    )
    assert result == "ok"
    assert ran == [True]
