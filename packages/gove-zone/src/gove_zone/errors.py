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


class ReceiptValidationError(GoveZoneError):
    """Raised when a DecisionReceipt validation fails."""


class ProductionProfileError(ReceiptValidationError):
    """Raised when a gate runs under the production profile (the default) but is
    not configured to enforce a signature — i.e. ``require_signature=True`` with
    no verifier supplied.

    Subclasses :class:`ReceiptValidationError` deliberately: it must stay on the
    single fail-closed receipt-verification path so that callers catching
    ``ReceiptValidationError`` (e.g. :meth:`gove_zone.contracts.ReceiptVerifier.is_valid`)
    keep their existing contract. The message names both exits — configure a
    verifier/signer, or explicitly select the dev profile
    (``GovernanceProfile.dev()`` / ``require_signature=False``) — so the secure
    default never auto-generates an ephemeral key (which would be false security).
    """


PRODUCTION_NO_VERIFIER_MSG = (
    "production profile requires a signer/verifier: this gate runs with "
    "require_signature=True but no verifier was configured. Configure a "
    "public-key verifier (and a private-key signer at issuance), or explicitly "
    "select the dev profile (GovernanceProfile.dev() / pass require_signature=False) "
    "for unsigned operation. The gate will NOT auto-generate an ephemeral key."
)


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
    """Raised when a dispatch needs external (e.g. human) approval."""

    def __init__(self, record: DecisionRecord, audit_hash: str) -> None:
        self.record = record
        self.audit_hash = audit_hash
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
