"""B4-V0 reason-code taxonomy — always-on, crypto-free.

Two jobs, neither of which needs the optional ``cryptography`` extra (unlike the signed
fixture corpus in ``test_fixture_corpus.py``, which ``importorskip``s it). So this module is
the integrity floor that runs in EVERY environment — addressing the risk that a no-crypto
validation env could green while skipping all verifier coverage:

1. **Completeness guard** — every ``raise ReceiptValidationError(`` inside ``verify()`` /
   ``from_record`` carries a ``reason_code`` (static, via ``inspect``). A new raise site added
   without one fails here.
2. **Runtime taxonomy** — unsigned receipts (no crypto) actually reach a representative set of
   the numbered checks and surface the correct ``ReceiptRejectionReason`` on the exception.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import re
from collections.abc import Iterator
from typing import Any

import pytest

from gove_zone import Decision, DecisionReceipt, DecisionRecord, Validator
from gove_zone.decision import sha256_json
from gove_zone.errors import GoveZoneError, ReceiptRejectionReason, ReceiptValidationError

TS = "2026-01-01T00:00:00+00:00"
PAST = "2020-01-01T00:00:00+00:00"


def _mint(
    *, decision: Decision = Decision.ALLOW, expires_at: str = "", args: dict[str, Any] | None = None
) -> DecisionReceipt:
    """Mint an UNSIGNED receipt through the real issuance path (no cryptography needed)."""
    effective = {"path": "safe.txt"} if args is None else args
    record = DecisionRecord(
        decision=decision,
        tool="runtime.file.write",
        argument_hash=sha256_json(effective),
        policy_version="v1",
        event_id="ev_taxonomy",
        actor="agent-1",
        timestamp_iso=TS,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
        expires_at=expires_at,
        signer=None,
    )


# --- 1. Completeness guard (static) -----------------------------------------
def _raise_windows(src: str) -> Iterator[str]:
    starts = [m.start() for m in re.finditer(r"raise ReceiptValidationError\(", src)]
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(src)
        yield src[start:end]


def test_every_verify_rejection_carries_reason_code() -> None:
    windows = list(_raise_windows(inspect.getsource(DecisionReceipt.verify)))
    assert windows, "no raise sites found in verify() — inspect failure"
    for w in windows:
        assert "reason_code=" in w, f"verify() raise site missing reason_code:\n{w[:200]}"


def test_from_record_self_validation_carries_reason_code() -> None:
    for w in _raise_windows(inspect.getsource(DecisionReceipt.from_record)):
        assert "reason_code=" in w, f"from_record raise site missing reason_code:\n{w[:200]}"


# --- 2. Runtime taxonomy (unsigned, crypto-free) ----------------------------
def _expired() -> DecisionReceipt:
    return _mint(expires_at=PAST)


_CASES: list[tuple[str, Any, dict[str, Any], ReceiptRejectionReason]] = [
    # name, receipt-factory, verify_kwargs, expected reason_code
    (
        "missing-field",
        lambda: dataclasses.replace(_mint(), authority=""),
        {},
        ReceiptRejectionReason.MISSING_REQUIRED_FIELD,
    ),
    (
        "hash-mismatch",
        lambda: dataclasses.replace(_mint(), actor="attacker"),
        {},
        ReceiptRejectionReason.RECEIPT_HASH_MISMATCH,
    ),
    (
        "tenant-mismatch",
        _mint,
        {"expected_tenant_id": "other-tenant"},
        ReceiptRejectionReason.TENANT_MISMATCH,
    ),
    (
        "action-mismatch",
        _mint,
        {"expected_action": "runtime.file.delete"},
        ReceiptRejectionReason.ACTION_MISMATCH,
    ),
    (
        "denied-receipt",
        lambda: _mint(decision=Decision.DENY),
        {},
        ReceiptRejectionReason.DENIED_RECEIPT,
    ),
    (
        "escalated-receipt",
        lambda: _mint(decision=Decision.ESCALATE),
        {},
        ReceiptRejectionReason.ESCALATED_RECEIPT,
    ),
    ("expired", _expired, {"now_iso": TS}, ReceiptRejectionReason.RECEIPT_EXPIRED),
]


@pytest.mark.parametrize("name,factory,kwargs,expected", _CASES, ids=[c[0] for c in _CASES])
def test_unsigned_rejection_reason_codes(
    name: str, factory: Any, kwargs: dict[str, Any], expected: ReceiptRejectionReason
) -> None:
    receipt = factory()
    with pytest.raises(GoveZoneError) as excinfo:
        receipt.verify(**kwargs)
    assert isinstance(excinfo.value, ReceiptValidationError)
    assert excinfo.value.reason_code == expected, (
        f"{name}: expected {expected!r}, got {excinfo.value.reason_code!r} ({excinfo.value})"
    )


def test_valid_unsigned_receipt_accepts() -> None:
    """Control: a correct unsigned receipt verifies (no exception, dev posture)."""
    _mint().verify(require_signature=False)


def test_reason_code_serialises_as_plain_string() -> None:
    code = ReceiptRejectionReason.RECEIPT_HASH_MISMATCH
    assert isinstance(code, str)
    assert code == "RECEIPT_HASH_MISMATCH"
    assert json.dumps({"reason_code": code}) == '{"reason_code": "RECEIPT_HASH_MISMATCH"}'


def test_hand_constructed_error_defaults_reason_code_none() -> None:
    """Backward-compat: ``reason_code`` is additive and defaults to None when not supplied."""
    assert ReceiptValidationError("boom").reason_code is None
