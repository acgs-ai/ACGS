"""Typed errors raised by the kernel.

Every non-ALLOW dispatch raises a typed error carrying the
:class:`~gove_zone.decision.DecisionRecord` and the audit chain hash that
anchors the decision. Callers can catch the specific type or the
:class:`GoveZoneError` base.
"""

from __future__ import annotations

from gove_zone.decision import DecisionRecord


class GoveZoneError(Exception):
    """Base for all gove-zone errors."""


class DeniedError(GoveZoneError):
    """Raised when a dispatch is denied by policy or fail-closed fallback."""

    def __init__(self, record: DecisionRecord, audit_hash: str) -> None:
        self.record = record
        self.audit_hash = audit_hash
        super().__init__(
            f"denied by policy {record.policy_version!r}: {record.reason}"
        )


class EscalateError(GoveZoneError):
    """Raised when a dispatch needs external (e.g. human) approval."""

    def __init__(self, record: DecisionRecord, audit_hash: str) -> None:
        self.record = record
        self.audit_hash = audit_hash
        super().__init__(
            f"escalated by policy {record.policy_version!r}: {record.reason}"
        )


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
