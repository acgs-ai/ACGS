"""Typed errors raised by the kernel.

Every non-ALLOW dispatch raises a typed error carrying the
:class:`~gove_zone.decision.DecisionRecord` and the audit chain hash that
anchors the decision. Callers can catch the specific type or the
:class:`GoveZoneError` base.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from gove_zone.authz import AuthzReason
from gove_zone.decision import DecisionRecord
from gove_zone.rejection import HUMAN_APPROVAL, REVISE_AND_RETRY, rejection_dict

if TYPE_CHECKING:
    from gove_zone.escalation import PendingApproval


class GoveZoneError(Exception):
    """Base for all gove-zone errors."""


class ReceiptRejectionReason(StrEnum):
    """Stable, machine-readable reason codes for receipt verification failures.

    The *contract* a relying party (and the fixture corpus) asserts on, instead of
    the human-readable exception message — message text is explicitly NOT a contract
    (it carries hashes/field values for humans and may be reworded). Every
    :meth:`gove_zone.receipt.DecisionReceipt.verify` rejection and every
    :class:`ReceiptValidationError` subclass populates one of these. Names mirror the
    numbered checks in ``verify()``; values equal the member names (StrEnum) so the
    code serialises as a plain string in JSON / proof packs without leaking detail.

    Additive (B4-V0): ``reason_code`` defaults to ``None`` on a hand-constructed
    ``ReceiptValidationError`` for backward compatibility; the library populates it.
    """

    # verify() checks 1-13 (see receipt.py)
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    RECEIPT_HASH_MISSING = "RECEIPT_HASH_MISSING"
    RECEIPT_HASH_MISMATCH = "RECEIPT_HASH_MISMATCH"
    UNSIGNED_REJECTED = "UNSIGNED_REJECTED"
    SIGNING_KEY_UNKNOWN = "SIGNING_KEY_UNKNOWN"
    SIGNING_KEY_REVOKED = "SIGNING_KEY_REVOKED"
    SIGNED_RECEIPT_NO_VERIFIER = "SIGNED_RECEIPT_NO_VERIFIER"
    SIGNATURE_ALG_MISMATCH = "SIGNATURE_ALG_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    ACTOR_MISMATCH = "ACTOR_MISMATCH"
    SELF_VALIDATION = "SELF_VALIDATION"
    APPROVAL_CHAIN_DIVERGENCE = "APPROVAL_CHAIN_DIVERGENCE"
    UNKNOWN_DECISION = "UNKNOWN_DECISION"
    DENIED_RECEIPT = "DENIED_RECEIPT"
    ESCALATED_RECEIPT = "ESCALATED_RECEIPT"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    EXECUTION_BOUNDARY_MISMATCH = "EXECUTION_BOUNDARY_MISMATCH"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    AUDIT_HASH_MISMATCH = "AUDIT_HASH_MISMATCH"
    TRANSFORMATIONS_MALFORMED = "TRANSFORMATIONS_MALFORMED"
    TRANSFORM_MISMATCH = "TRANSFORM_MISMATCH"
    ARGUMENT_MISMATCH = "ARGUMENT_MISMATCH"
    POLICY_HASH_MISMATCH = "POLICY_HASH_MISMATCH"
    POLICY_BUNDLE_MISMATCH = "POLICY_BUNDLE_MISMATCH"
    VALIDATOR_ROLE_MISMATCH = "VALIDATOR_ROLE_MISMATCH"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    EXPIRY_UNPARSEABLE = "EXPIRY_UNPARSEABLE"
    RECEIPT_EXPIRED = "RECEIPT_EXPIRED"
    EXPIRY_REQUIRED = "EXPIRY_REQUIRED"
    # gate-level / subclass reasons
    PRODUCTION_PROFILE_NO_VERIFIER = "PRODUCTION_PROFILE_NO_VERIFIER"
    RECEIPT_ALREADY_USED = "RECEIPT_ALREADY_USED"
    CONSUMPTION_LEDGER_UNPROVABLE = "CONSUMPTION_LEDGER_UNPROVABLE"
    # multi-agent governance DAG reasons (gove_zone.dag)
    DAG_STRUCTURE_INVALID = "DAG_STRUCTURE_INVALID"
    AUTHORITY_VIOLATION = "AUTHORITY_VIOLATION"
    DAG_REPLAY_INVALID = "DAG_REPLAY_INVALID"


class ReceiptValidationError(GoveZoneError):
    """Raised when a DecisionReceipt validation fails.

    Carries an optional machine-readable :class:`ReceiptRejectionReason` in
    ``reason_code`` (B4-V0). ``None`` only on a hand-constructed instance that did not
    supply one; every library raise site populates it. ``reason_code`` is keyword-only
    and additive, so existing positional-message call sites are unaffected.
    """

    def __init__(self, *args: object, reason_code: ReceiptRejectionReason | None = None) -> None:
        super().__init__(*args)
        self.reason_code = reason_code


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

    def __init__(self, *args: object, reason_code: ReceiptRejectionReason | None = None) -> None:
        super().__init__(
            *args, reason_code=reason_code or ReceiptRejectionReason.PRODUCTION_PROFILE_NO_VERIFIER
        )


class ReceiptAlreadyUsedError(ReceiptValidationError):
    """Raised when a receipt presented at the gate was already consumed.

    A :class:`~gove_zone.consumption.ReceiptConsumptionLedger` keys consumption
    on the receipt's ``audit_event_hash`` — one audit-anchored decision
    authorizes at most one execution. Subclasses
    :class:`ReceiptValidationError` deliberately (the
    :class:`ProductionProfileError` precedent): replay refusal stays on the
    single fail-closed receipt-verification path, so every existing caller
    that treats ``ReceiptValidationError`` as "execution refused" handles
    replay correctly with no new catch site.
    """

    def __init__(self, audit_event_hash: str = "", ledger_path: str = "") -> None:
        self.audit_event_hash = audit_event_hash
        self.ledger_path = ledger_path
        super().__init__(
            "receipt already consumed: audit anchor "
            f"{self.audit_event_hash!r} is burned in the consumption ledger "
            f"({self.ledger_path}). One approval authorizes at most one "
            "execution — obtain a fresh decision/approval to run again.",
            reason_code=ReceiptRejectionReason.RECEIPT_ALREADY_USED,
        )

    def __reduce__(self) -> tuple[type[ReceiptAlreadyUsedError], tuple[str, str]]:
        # BaseException pickling replays ``args`` (the rendered message) into
        # ``__init__``; rebuild from the structured fields instead so the error
        # survives multiprocessing/ProcessPoolExecutor boundaries intact.
        return (type(self), (self.audit_event_hash, self.ledger_path))


class ConsumptionLedgerError(ReceiptValidationError):
    """Raised when the consumption ledger cannot prove a receipt is fresh —
    unreadable file, corrupt line, or a failed write of the consumption entry.

    Subclasses :class:`ReceiptValidationError` deliberately (the
    :class:`ProductionProfileError` precedent): if single-use cannot be
    *proven*, execution is refused on the same fail-closed path as any other
    receipt-validation failure rather than silently degrading to stateless
    (replayable) verification.
    """

    def __init__(self, *args: object, reason_code: ReceiptRejectionReason | None = None) -> None:
        super().__init__(
            *args, reason_code=reason_code or ReceiptRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE
        )


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


class IdentityRejectionReason(StrEnum):
    """Machine-readable reason codes for identity-layer refusals.

    The contract a relying party asserts on instead of the human-readable
    message — mirrors :class:`ReceiptRejectionReason` and
    :class:`~gove_zone.authz.AuthzReason`. Values equal member names (StrEnum)
    so they serialise as plain strings.
    """

    UNKNOWN_SUBJECT = "UNKNOWN_SUBJECT"
    UNSUPPORTED_CREDENTIAL_TYPE = "UNSUPPORTED_CREDENTIAL_TYPE"
    CREDENTIAL_KIND_NOT_ALLOWED = "CREDENTIAL_KIND_NOT_ALLOWED"
    UNKNOWN_OR_REVOKED_CREDENTIAL = "UNKNOWN_OR_REVOKED_CREDENTIAL"
    CREDENTIAL_TYPE_MISMATCH = "CREDENTIAL_TYPE_MISMATCH"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    TIMESTAMP_UNPARSEABLE = "TIMESTAMP_UNPARSEABLE"
    TIMESTAMP_NAIVE = "TIMESTAMP_NAIVE"
    NO_ROLE_MAPPED = "NO_ROLE_MAPPED"
    TOOL_NOT_PERMITTED_BY_ROLE = "TOOL_NOT_PERMITTED_BY_ROLE"


class IdentityError(GoveZoneError):
    """Raised when identity resolution or role mapping fails — fail-closed.

    Covers the Identity/Authority layers (:mod:`gove_zone.identity`): unknown or
    revoked credentials, credential-type mismatches, workload audience
    mismatches, expired tokens, and principals with no mapped role. Distinct
    from :class:`AuthzDeniedError` (a resolved principal refused at the executor
    allowlist) and :class:`ReceiptValidationError` (a receipt defect): an
    ``IdentityError`` means no principal was established at all, so no
    governance request is ever made.

    Carries a machine-readable :class:`IdentityRejectionReason` in
    ``reason_code`` (the :class:`ReceiptValidationError` precedent): relying
    parties route on the code, never on message prose. ``None`` only on a
    hand-constructed instance; every library raise site populates it.
    """

    def __init__(self, *args: object, reason_code: IdentityRejectionReason | None = None) -> None:
        super().__init__(*args)
        self.reason_code = reason_code


class AuthzDeniedError(GoveZoneError):
    """Raised at the executor gate when the acting principal is not authorized.

    Distinct from :class:`ReceiptValidationError` (a receipt defect): the receipt
    may be perfectly valid; the principal is simply not on the integrator's
    allowlist for this action. Relying parties assert on ``reason`` — the same
    :class:`~gove_zone.authz.AuthzReason` taxonomy the kernel emits as
    ``AUTHZ_DENY:<reason>``.
    """

    def __init__(self, reason: AuthzReason, actor: str, action: str) -> None:
        self.reason = reason
        self.actor = actor
        self.action = action
        super().__init__(f"principal {actor!r} not authorized for action {action!r} ({reason})")


class DeniedError(GoveZoneError):
    """Raised when a dispatch is denied by policy or fail-closed fallback."""

    def __init__(self, record: DecisionRecord, audit_hash: str) -> None:
        self.record = record
        self.audit_hash = audit_hash
        super().__init__(f"denied by policy {record.policy_version!r}: {record.reason}")

    def to_rejection_dict(
        self,
        *,
        allowed_alternatives: Iterable[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Machine-readable rejection envelope for a calling agent.

        Deny is terminal for *this* call: the resolution hint is
        ``revise_and_retry`` and ``resumable`` is ``False``. Pure projection of
        the deciding record — see :func:`gove_zone.rejection.rejection_dict`.

        ``allowed_alternatives`` (from
        :func:`gove_zone.rejection.discover_alternatives`) is passed through to
        the envelope; ``None`` keeps the key omitted ("not computed").
        """
        return rejection_dict(
            self.record,
            self.audit_hash,
            resumable=False,
            resolution=REVISE_AND_RETRY,
            allowed_alternatives=allowed_alternatives,
        )


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

    def to_rejection_dict(
        self,
        *,
        allowed_alternatives: Iterable[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Machine-readable rejection envelope for a calling agent.

        Escalation is **not** a dead-end: ``approval`` advertises the
        human-approval resume path
        (:func:`gove_zone.escalation.approve_escalation` →
        :func:`gove_zone.escalation.resume_with_receipt`). ``resumable`` tracks
        the actual affordance — it is ``True`` **iff** a
        :class:`~gove_zone.escalation.PendingApproval` is attached (the kernel
        attaches one on every ESCALATE dispatch; a hand-constructed
        ``EscalateError(record, audit_hash)`` has none, so ``resumable`` is
        ``False`` and ``approval.pending`` agrees). A consumer can therefore gate
        the resume call on either ``resumable`` or ``approval.pending`` without
        the two ever disagreeing.

        ``allowed_alternatives`` (from
        :func:`gove_zone.rejection.discover_alternatives`) is passed through to
        the envelope; ``None`` keeps the key omitted ("not computed").
        """
        has_pending = self.pending is not None
        return rejection_dict(
            self.record,
            self.audit_hash,
            resumable=has_pending,
            resolution=HUMAN_APPROVAL,
            approval={"via": "approve_escalation", "pending": has_pending},
            allowed_alternatives=allowed_alternatives,
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


class UnsafeAuditFilesystemError(AuditError):
    """Raised at :class:`~gove_zone.audit.ChainHashAuditStore` construction when
    the audit path lives on a filesystem whose cross-process locking is unsafe.

    The audit chain's append-only guarantee depends on ``fcntl.flock`` (POSIX)
    serializing concurrent writers. On an NFS mount **without a running lock
    manager (lockd/NLM)**, ``flock`` can silently no-op, so two processes could
    append sibling events sharing a ``previous_hash`` and corrupt the chain.
    Rather than proceed with a locking guarantee it cannot honor, the store
    refuses to start (fail closed). Subclasses :class:`AuditError` so callers
    catching audit faults treat an unsafe backing store as a fail-closed audit
    outcome. An operator who knows their NFS export runs lockd can opt in with
    the ``GOVE_ZONE_ALLOW_UNSAFE_FS=1`` environment variable.
    """
