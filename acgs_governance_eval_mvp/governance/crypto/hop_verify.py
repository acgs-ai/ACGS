"""Hop verification: bind a signed hop payload to a KeyEntry.

This is the per-hop integration layer between the pure signature
primitive (:mod:`governance.crypto.hop_signature`) and the
metadata-rich key store (:mod:`governance.crypto.principal_keys`).

See `docs/design/phase2-trace-crypto.md` §verification path and
ADR-0007 §5, §6, §10.

Checks performed
----------------
1. Signature verifies under ``key.public_key`` over the domain-tagged
   canonical payload.
2. ``key.principal_id == hop.delegator_id``.
3. ``key.tenant == hop.tenant`` (universal; per-tenant root keys —
   no exemption).
4. ``"trace-delegation" in key.purposes``.
5. ``key.valid_from <= hop.delegated_at <= key.valid_to``.
6. ``key.revoked_at is None`` or ``hop.delegated_at < key.revoked_at``.
7. ``hop.not_after >= now() - CLOCK_SKEW_TOLERANCE``.
8. ``hop.not_after - hop.delegated_at <= MAX_TRACE_TTL``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .hop_signature import HopSignatureError, verify_hop
from .principal_keys import KeyEntry

CLOCK_SKEW_TOLERANCE: timedelta = timedelta(seconds=60)
MAX_TRACE_TTL_DEFAULT: timedelta = timedelta(hours=24)

_TRACE_DELEGATION_PURPOSE = "trace-delegation"


class HopVerificationError(ValueError):
    """Raised when a hop fails any of the identity-binding checks.

    Wraps :class:`HopSignatureError` for signature failures so callers
    have a single exception type to catch.
    """


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise HopVerificationError(f"datetime {value!r} is not timezone-aware")
    return parsed


def verify_hop_against_entry(
    hop_payload: dict[str, Any],
    signature: bytes,
    key_entry: KeyEntry,
    *,
    now: datetime | None = None,
    clock_skew_tolerance: timedelta = CLOCK_SKEW_TOLERANCE,
    max_trace_ttl: timedelta = MAX_TRACE_TTL_DEFAULT,
) -> None:
    """Verify a hop payload + signature against a resolved KeyEntry.

    Raises :class:`HopVerificationError` on any failure. Returns
    ``None`` on success.

    The ``now`` parameter is injectable for tests; production callers
    omit it and the function uses ``datetime.now(tz=timezone.utc)``.
    """
    # 1. Signature
    try:
        verify_hop(key_entry.public_key, hop_payload, signature)
    except HopSignatureError as exc:
        raise HopVerificationError("hop signature did not verify") from exc

    # 2. Delegator binding
    delegator_id = hop_payload.get("delegator_id")
    if key_entry.principal_id != delegator_id:
        raise HopVerificationError(
            f"key principal_id {key_entry.principal_id!r} does not match hop delegator_id {delegator_id!r}"
        )

    # 3. Tenant binding (universal, no root-key exemption)
    hop_tenant = hop_payload.get("tenant")
    if key_entry.tenant != hop_tenant:
        raise HopVerificationError(f"key tenant {key_entry.tenant!r} does not match hop tenant {hop_tenant!r}")

    # 4. Purpose
    if _TRACE_DELEGATION_PURPOSE not in key_entry.purposes:
        raise HopVerificationError(
            f"key purposes {sorted(key_entry.purposes)!r} do not include {_TRACE_DELEGATION_PURPOSE!r}"
        )

    # 5. Validity window vs delegated_at
    delegated_at = _parse_dt(hop_payload["delegated_at"])
    if not (key_entry.valid_from <= delegated_at <= key_entry.valid_to):
        raise HopVerificationError(
            f"hop delegated_at {delegated_at.isoformat()} outside key validity "
            f"[{key_entry.valid_from.isoformat()}, {key_entry.valid_to.isoformat()}]"
        )

    # 6. Revocation
    if key_entry.revoked_at is not None and delegated_at >= key_entry.revoked_at:
        raise HopVerificationError(
            f"key was revoked at {key_entry.revoked_at.isoformat()}, before hop delegated_at {delegated_at.isoformat()}"
        )

    # 7. Expiry (with clock-skew tolerance for backward-skewed clocks)
    not_after = _parse_dt(hop_payload["not_after"])
    current = now if now is not None else datetime.now(tz=timezone.utc)
    if not_after < current - clock_skew_tolerance:
        raise HopVerificationError(f"hop expired: not_after {not_after.isoformat()} < now - tolerance")

    # 8. TTL bound
    if not_after - delegated_at > max_trace_ttl:
        raise HopVerificationError(f"hop TTL exceeds MAX_TRACE_TTL ({(not_after - delegated_at)} > {max_trace_ttl})")


__all__ = [
    "CLOCK_SKEW_TOLERANCE",
    "HopVerificationError",
    "MAX_TRACE_TTL_DEFAULT",
    "verify_hop_against_entry",
]
