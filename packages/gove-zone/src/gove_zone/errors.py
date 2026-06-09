"""Typed errors raised by the kernel.

Every non-ALLOW dispatch raises a typed error carrying the
:class:`~gove_zone.decision.DecisionRecord` and the audit chain hash that
anchors the decision. Callers can catch the specific type or the
:class:`GoveZoneError` base.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gove_zone.decision import DecisionRecord

if TYPE_CHECKING:
    from gove_zone.escalation import PendingApproval


class GoveZoneError(Exception):
    """Base for all gove-zone errors."""


class ReceiptValidationError(GoveZoneError):
    """Raised when a DecisionReceipt validation fails."""


class SigningError(GoveZoneError):
    """Raised for signer construction / key / missing-dependency problems.

    NOTE: signature *verification failures at the gate* raise
    :class:`ReceiptValidationError`, not this — they stay on the single
    fail-closed receipt-verification path. ``SigningError`` covers issuance-side
    and configuration faults: missing ``crypto`` extra, malformed key bytes, or
    attempting to ``sign`` with a verify-only signer.
    """


class DeniedError(GoveZoneError):
    """Raised when a dispatch is denied by policy or fail-closed fallback."""

    def __init__(self, record: DecisionRecord, audit_hash: str) -> None:
        self.record = record
        self.audit_hash = audit_hash
        super().__init__(f"denied by policy {record.policy_version!r}: {record.reason}")


class EscalateError(GoveZoneError):
    """Raised when a dispatch needs external (e.g. human) approval.

    ``pending`` carries the :class:`~gove_zone.escalation.PendingApproval` needed
    to later approve and resume the escalated call. It is optional and defaults
    to ``None`` so existing ``EscalateError(record, audit_hash)`` call sites keep
    working; the kernel populates it on every ESCALATE dispatch.
    """

    def __init__(
        self,
        record: DecisionRecord,
        audit_hash: str,
        *,
        pending: PendingApproval | None = None,
    ) -> None:
        self.record = record
        self.audit_hash = audit_hash
        self.pending = pending
        super().__init__(f"escalated by policy {record.policy_version!r}: {record.reason}")


class PolicyError(GoveZoneError):
    """Raised when policy.evaluate raises AND fail-closed fallback could not
    append a denial record to the audit chain (both layers failed).
    """


class AuditError(GoveZoneError):
    """Raised when the audit append fails for a decision the kernel had
    already produced. Treated as fail-closed: the dispatch never executes.
    """


class UnknownToolError(GoveZoneError):
    """Raised when dispatch names a tool that was never registered."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"tool not registered: {name!r}")
