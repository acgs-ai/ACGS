"""Tests for optional receipt expiry — fail-closed when a receipt is used past
its lifetime. Expiry is opt-in (empty ``expires_at`` = no expiry) and the clock
is injectable via ``now_iso`` so these tests are deterministic.
"""

from __future__ import annotations

import dataclasses

import pytest

from gove_zone import Decision, DecisionReceipt, DecisionRecord, ReceiptValidationError, Validator


def _receipt(expires_at: str = "") -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool="runtime.file.write",
        argument_hash="hash",
        policy_version="v1",
        event_id="ev_exp",
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="bundle-A",
        policy_hash="policy-hash",
        request_id="req-1",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
        expires_at=expires_at,
    )


def test_no_expiry_receipt_is_valid_regardless_of_clock() -> None:
    receipt = _receipt(expires_at="")
    # Far-future "now": a no-expiry receipt must still verify.
    receipt.verify(now_iso="2999-01-01T00:00:00+00:00")


def test_unexpired_receipt_passes() -> None:
    receipt = _receipt(expires_at="2026-01-01T00:00:00+00:00")
    receipt.verify(now_iso="2025-12-31T23:59:59+00:00")


def test_expired_receipt_fails_closed() -> None:
    receipt = _receipt(expires_at="2026-01-01T00:00:00+00:00")
    with pytest.raises(ReceiptValidationError) as exc:
        receipt.verify(now_iso="2026-01-01T00:00:01+00:00")
    assert "expired" in str(exc.value)


def test_expiry_is_bound_into_receipt_hash() -> None:
    # Tampering with expires_at without recomputing the hash is caught by the
    # tamper check (#2), not the expiry check — proving expiry is signed.
    receipt = _receipt(expires_at="2026-01-01T00:00:00+00:00")
    tampered = dataclasses.replace(receipt, expires_at="2999-01-01T00:00:00+00:00")
    with pytest.raises(ReceiptValidationError) as exc:
        tampered.verify(now_iso="2027-01-01T00:00:00+00:00")
    assert "receipt_hash mismatch" in str(exc.value)


def test_expiry_compares_across_timezone_offsets() -> None:
    # expires 08:00Z (written as 13:00+05:00); now is 12:00Z → genuinely expired.
    # A naive lexicographic string compare would WRONGLY accept this (fail open),
    # because "12:00:00+00:00" < "13:00:00+05:00" as text.
    receipt = _receipt(expires_at="2026-01-01T13:00:00+05:00")
    with pytest.raises(ReceiptValidationError, match="expired"):
        receipt.verify(now_iso="2026-01-01T12:00:00+00:00")


def test_unparseable_expiry_fails_closed() -> None:
    receipt = _receipt(expires_at="not-a-timestamp")
    with pytest.raises(ReceiptValidationError, match="Unparseable"):
        receipt.verify(now_iso="2026-01-01T00:00:00+00:00")


def test_expiry_survives_json_round_trip() -> None:
    receipt = _receipt(expires_at="2026-01-01T00:00:00+00:00")
    restored = DecisionReceipt.from_json(receipt.to_json())
    assert restored.expires_at == "2026-01-01T00:00:00+00:00"
    assert restored.receipt_hash == receipt.receipt_hash
    restored.verify(now_iso="2025-06-01T00:00:00+00:00")
