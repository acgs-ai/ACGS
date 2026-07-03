"""Tests for GovernanceProfile.production_strict — the opt-in hardened posture.

Plain ``production()`` requires only a signature; a valid receipt with no TTL,
no single-use ledger, and no policy watchdog can be replayed, live forever, and
block on a hung policy. ``production_strict`` makes all three mandatory. These
tests pin:

* construction fail-closed (no ledger / no verifier raise ProductionProfileError),
* single-use enforcement (a replay is refused) when the strict bundle is the gate,
* TTL enforcement (a no-expiry receipt is rejected) when the strict bundle is the gate,
* the policy_timeout default is set and surfaced via as_kernel_kwargs,
* the additive contract: production()/dev() bundles are byte-for-byte unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gove_zone import Decision, DecisionReceipt, DecisionRecord, GovernanceProfile, Validator
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import sha256_json
from gove_zone.errors import (
    ProductionProfileError,
    ReceiptAlreadyUsedError,
    ReceiptRejectionReason,
    ReceiptValidationError,
)
from gove_zone.executor import execute_with_receipt


class _FakeVerifier:
    """A minimal ReceiptSigner-shaped stand-in (no crypto extra needed)."""

    algorithm = "ed25519"
    key_id = "k1"

    def sign(self, payload: bytes) -> str:  # pragma: no cover - not exercised here
        return "sig"

    def verify(self, payload: bytes, signature: str) -> bool:  # pragma: no cover
        return True


def _make_receipt(*, expires_at: str = "") -> tuple[DecisionReceipt, dict[str, Any]]:
    """Build an unsigned ALLOW receipt and the args it authorizes.

    Unsigned is fine for these tests: the strict-profile behaviours under test
    (ledger burn, TTL rejection) are orthogonal to signature checking, and the
    strict bundle in these tests is fed through the gate with require_signature
    overridden off where needed.
    """
    args: dict[str, Any] = {"path": "safe.txt"}
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool="runtime.file.write",
        argument_hash=sha256_json(args),
        policy_version="v1",
        event_id="ev_strict",
        actor="agent-1",
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash_strict",
        previous_audit_hash="prev",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-1",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
        expires_at=expires_at,
    )
    return receipt, args


def _future_iso() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat()


# ---------------------------------------------------------------------------
# Construction fail-closed contracts
# ---------------------------------------------------------------------------


def test_strict_requires_verifier() -> None:
    ledger = ReceiptConsumptionLedger(Path("/tmp/_unused_ledger_a.jsonl"))
    with pytest.raises(ProductionProfileError):
        GovernanceProfile.production_strict(verifier=None, consumption_ledger=ledger)  # type: ignore[arg-type]


def test_strict_requires_consumption_ledger() -> None:
    with pytest.raises(ProductionProfileError):
        GovernanceProfile.production_strict(
            verifier=_FakeVerifier(),
            consumption_ledger=None,  # type: ignore[arg-type]
        )


def test_strict_constructor_sets_all_three_controls(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    verifier = _FakeVerifier()
    profile = GovernanceProfile.production_strict(verifier=verifier, consumption_ledger=ledger)

    assert profile.name == "production-strict"
    assert profile.is_production is True  # strict is still a production posture
    assert profile.is_strict is True
    assert profile.require_signature is True
    assert profile.verifier is verifier
    assert profile.consumption_ledger is ledger
    assert profile.require_expiry is True
    # Sane finite default — a hung policy fails closed rather than blocking.
    assert profile.policy_timeout == 5.0


def test_strict_policy_timeout_is_overridable(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    profile = GovernanceProfile.production_strict(
        verifier=_FakeVerifier(), consumption_ledger=ledger, policy_timeout=2.5
    )
    assert profile.policy_timeout == 2.5
    assert profile.as_kernel_kwargs() == {"policy_timeout": 2.5}


# ---------------------------------------------------------------------------
# as_gate_kwargs / as_kernel_kwargs emission
# ---------------------------------------------------------------------------


def test_strict_gate_kwargs_emit_ledger_and_require_expiry(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    verifier = _FakeVerifier()
    profile = GovernanceProfile.production_strict(verifier=verifier, consumption_ledger=ledger)
    gate = profile.as_gate_kwargs()
    assert gate == {
        "require_signature": True,
        "verifier": verifier,
        "consumption_ledger": ledger,
        "require_expiry": True,
    }


def test_strict_kernel_kwargs_emit_policy_timeout(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    profile = GovernanceProfile.production_strict(
        verifier=_FakeVerifier(), consumption_ledger=ledger
    )
    assert profile.as_kernel_kwargs() == {"policy_timeout": 5.0}


# ---------------------------------------------------------------------------
# Additive contract: production()/dev() bundles unchanged
# ---------------------------------------------------------------------------


def test_production_gate_kwargs_unchanged() -> None:
    """The plain production bundle stays the exact two-key dict callers splat."""
    verifier = _FakeVerifier()
    assert GovernanceProfile.production(verifier=verifier).as_gate_kwargs() == {
        "require_signature": True,
        "verifier": verifier,
    }


def test_dev_gate_kwargs_unchanged() -> None:
    assert GovernanceProfile.dev().as_gate_kwargs() == {
        "require_signature": False,
        "verifier": None,
    }


def test_production_kernel_kwargs_have_no_timeout() -> None:
    """Plain production leaves the watchdog off — today's behavior."""
    assert GovernanceProfile.production().as_kernel_kwargs() == {"policy_timeout": None}


def test_strict_gate_kwargs_splat_into_all_three_surfaces(tmp_path: Path) -> None:
    """Contract guard: ``as_gate_kwargs()`` is documented to feed all three gate
    surfaces. The strict bundle (which carries the extra ``consumption_ledger`` +
    ``require_expiry`` keys) must construct each without a TypeError, so a future
    removal of the param on any one surface is caught here rather than only at the
    execute_with_receipt path the enforcement tests exercise.
    """
    from gove_zone.contracts import ReceiptVerifier
    from gove_zone.executor import GovernedExecutor

    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    strict = GovernanceProfile.production_strict(
        verifier=_FakeVerifier(), consumption_ledger=ledger
    )
    gate = strict.as_gate_kwargs()

    # GovernedExecutor accepts consumption_ledger + require_expiry from the splat.
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="agent-1",
        **gate,
    )
    assert executor.consumption_ledger is ledger
    assert executor.require_expiry is True

    # ReceiptVerifier accepts require_expiry from the splat. It does not accept
    # consumption_ledger (it is a pure verification wrapper, no burn step), so
    # drop that one key — mirroring how a verifier-only caller would use it.
    verify_kwargs = {k: v for k, v in gate.items() if k != "consumption_ledger"}
    rv = ReceiptVerifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        **verify_kwargs,
    )
    assert rv.require_expiry is True


# ---------------------------------------------------------------------------
# Enforcement through the side-effect gate (the real wiring)
# ---------------------------------------------------------------------------


def _strict_gate_kwargs_unsigned(profile: GovernanceProfile) -> dict[str, Any]:
    """Strict bundle, but with signing overridden off so the unsigned test
    receipt verifies — isolates the ledger/TTL behaviours under test.
    """
    kwargs = profile.as_gate_kwargs()
    kwargs["require_signature"] = False
    kwargs["verifier"] = None
    return kwargs


def test_strict_blocks_replay_single_use(tmp_path: Path) -> None:
    """A second presentation of the same receipt is refused (anti-replay)."""
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    profile = GovernanceProfile.production_strict(
        verifier=_FakeVerifier(), consumption_ledger=ledger
    )
    receipt, args = _make_receipt(expires_at=_future_iso())

    ran: list[bool] = []

    def tool(**kwargs: Any) -> str:
        ran.append(True)
        return "ok"

    common = dict(
        tool_fn=tool,
        args=args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="agent-1",
        **_strict_gate_kwargs_unsigned(profile),
    )

    # First execution succeeds and burns the audit anchor.
    assert execute_with_receipt(**common) == "ok"
    # Replay is refused with no side effect.
    with pytest.raises(ReceiptAlreadyUsedError):
        execute_with_receipt(**common)
    assert ran == [True]


def test_strict_rejects_receipt_without_expiry(tmp_path: Path) -> None:
    """A receipt with empty expires_at is rejected under the strict profile."""
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    profile = GovernanceProfile.production_strict(
        verifier=_FakeVerifier(), consumption_ledger=ledger
    )
    receipt, args = _make_receipt(expires_at="")  # no TTL

    ran: list[bool] = []

    def tool(**kwargs: Any) -> str:  # pragma: no cover - must never run
        ran.append(True)
        return "ok"

    with pytest.raises(ReceiptValidationError) as exc:
        execute_with_receipt(
            tool_fn=tool,
            args=args,
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="agent-1",
            **_strict_gate_kwargs_unsigned(profile),
        )
    assert exc.value.reason_code is ReceiptRejectionReason.EXPIRY_REQUIRED
    assert ran == []
    # Rejected before the burn: the audit anchor must remain fresh.
    assert ledger.is_consumed(receipt.audit_event_hash) is False


def test_strict_allows_valid_receipt_with_future_expiry(tmp_path: Path) -> None:
    """Sanity: a receipt that satisfies all three controls executes once."""
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    profile = GovernanceProfile.production_strict(
        verifier=_FakeVerifier(), consumption_ledger=ledger
    )
    receipt, args = _make_receipt(expires_at=_future_iso())

    def tool(**kwargs: Any) -> str:
        return "ok"

    result = execute_with_receipt(
        tool_fn=tool,
        args=args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="agent-1",
        **_strict_gate_kwargs_unsigned(profile),
    )
    assert result == "ok"
    assert ledger.is_consumed(receipt.audit_event_hash) is True


def test_require_expiry_param_is_default_off_in_executor(tmp_path: Path) -> None:
    """Additive proof: execute_with_receipt without require_expiry accepts a
    no-TTL receipt (existing callers unaffected).
    """
    receipt, args = _make_receipt(expires_at="")

    def tool(**kwargs: Any) -> str:
        return "ok"

    # No require_expiry, no ledger, signing off → today's behavior: runs fine.
    result = execute_with_receipt(
        tool_fn=tool,
        args=args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="agent-1",
        require_signature=False,
        verifier=None,
    )
    assert result == "ok"
