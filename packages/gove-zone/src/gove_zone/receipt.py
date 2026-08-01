"""Receipt — the full proof-of-decision artifact for one dispatch.

A :class:`Receipt` is what the kernel returns alongside a successful tool
result. It packages the :class:`~gove_zone.decision.DecisionRecord`, the
audit chain hash, the actor identity, and a digest of the result. Receipts
are the unit of replay (see :mod:`gove_zone.replay`).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from gove_zone.decision import DecisionRecord, sha256_json
from gove_zone.signing import ReceiptSigner

if TYPE_CHECKING:
    from gove_zone.revocation import RevocationList
    from gove_zone.trust import ReceiptTrustRegistry


DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS = 300
MAX_RECEIPT_CLOCK_SKEW_SECONDS = DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS


def validate_receipt_clock_skew_seconds(value: int) -> int:
    """Return a bounded receipt clock-skew allowance or fail closed.

    The receipt liveness skew is a security boundary. Callers may tighten it,
    but never widen it beyond the library default.
    """
    from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError

    if type(value) is not int:
        raise ReceiptValidationError(
            "max_clock_skew_seconds must be an integer",
            reason_code=ReceiptRejectionReason.EXPIRY_UNPARSEABLE,
        )
    if value < 0 or value > MAX_RECEIPT_CLOCK_SKEW_SECONDS:
        raise ReceiptValidationError(
            "max_clock_skew_seconds must be between 0 and "
            f"{MAX_RECEIPT_CLOCK_SKEW_SECONDS} seconds",
            reason_code=ReceiptRejectionReason.EXPIRY_UNPARSEABLE,
        )
    return value


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def safe_result_hash(value: Any) -> str:
    """Hash *value* deterministically.

    Falls back to ``repr(value)[:512]`` for non-JSON-serializable values so
    the receipt always carries a hash even when a tool returns objects we
    cannot canonicalize.
    """
    try:
        json.dumps(value, sort_keys=True, default=str)
        return sha256_json(value)
    except (TypeError, ValueError):
        return sha256_json({"_repr": repr(value)[:512]})


@dataclass(frozen=True, slots=True)
class Receipt:
    """Proof-of-decision: the decision, the audit anchor, and the outcome.

    Attributes:
        record: the policy's frozen :class:`DecisionRecord`.
        audit_hash: ``event_hash`` returned by the audit store on append.
        actor: opaque identity string ("anonymous" by default).
        result_hash: SHA-256 of the canonical-JSON of the tool result, or
            ``None`` if the dispatch did not execute (DENY/ESCALATE).
        error_class: class name of the exception raised by tool execution,
            or ``None`` if execution succeeded or never ran.
    """

    record: DecisionRecord
    audit_hash: str
    actor: str = "anonymous"
    result_hash: str | None = None
    error_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.record.to_dict(),
            "audit_hash": self.audit_hash,
            "actor": self.actor,
            "result_hash": self.result_hash,
            "error_class": self.error_class,
        }


@dataclass(frozen=True, slots=True)
class Validator:
    """MACI validating principal. Distinct from the proposer (ToolCall.actor).

    A ``Validator`` issues the authority decision; the proposer never can. This
    is the type/role boundary that structurally prevents self-validation: an
    agent may *propose* an action but can never *validate* its own authority to
    execute it. Fail-closed at construction — an empty id or role is rejected.
    """

    validator_id: str
    role: str = "validator"

    def __post_init__(self) -> None:
        if not self.validator_id:
            raise ValueError("Validator.validator_id is required (fail-closed)")
        if not self.role:
            raise ValueError("Validator.role is required (fail-closed)")


@dataclass(frozen=True, slots=True)
class DecisionReceipt:
    """Canonical public Decision Receipt schema for AI-agent execution.

    Designed for deterministic serialisation, canonical hashing, and fail-closed validation.

    MACI role separation: ``actor`` is the proposer (the ToolCall actor) while
    ``validator_id`` / ``validator_role`` identify the distinct principal that
    issued the authority decision, and ``authority`` is the grant it conferred.
    These three fields are bound into ``receipt_hash`` (via ``to_dict``), enforcing
    validator≠proposer at issuance and at the gate. The gate surfaces
    (:func:`gove_zone.executor.execute_with_receipt`,
    :class:`gove_zone.executor.GovernedExecutor`,
    :class:`gove_zone.contracts.ReceiptVerifier`) now *require* ``expected_actor``,
    so the strong caller-anchored check (2b below) is the default — omission fails
    loudly rather than silently downgrading. ``verify()`` itself keeps
    ``expected_actor`` optional; the weak ``validator_id == actor`` fallback (2c)
    remains as residual defense-in-depth for direct ``verify()`` callers only.

    Ed25519 asymmetric signing closes the recomputed-receipt residual **when
    engaged**: ``signature`` is a private-key signature over ``receipt_hash``; the
    gate verifies it with the matching public key. ``signature_algorithm`` and
    ``signing_key_id`` are bound into ``receipt_hash`` (anti-downgrade: an attacker
    cannot change the algorithm or key without breaking the hash), while
    ``signature`` itself stays OUT of ``compute_hash`` (the signature signs the
    hash). An unsigned receipt keeps ``signature_algorithm="none"``,
    ``signing_key_id=""``, ``signature="unsigned_local"``.

    **Precondition for closure.** The residual is closed only when receipts are
    issued with a private-key signer AND the gate is configured with a matching
    public-key verifier plus ``require_signature=True``. Default deployments are
    unsigned. Residuals not addressed: private-key custody, key distribution /
    trust establishment, and revocation (no PKI; the verifier map is static).
    """

    receipt_id: str
    request_id: str
    tenant_id: str
    actor: str
    proposed_action: str
    declared_goal: str
    execution_boundary: str
    policy_bundle_id: str
    policy_version: str
    policy_hash: str
    decision: str
    matched_rules: list[str]
    constraints: dict[str, Any]
    transformations: list[dict[str, Any]]
    approval_chain_summary: dict[str, Any]
    timestamp: str
    previous_audit_hash: str
    audit_event_hash: str
    subject: str = ""
    expires_at: str = ""
    authority: str = ""
    validator_id: str = ""
    validator_role: str = ""
    argument_hash: str = ""
    receipt_hash: str = ""
    signature_algorithm: str = "none"
    signing_key_id: str = ""
    signature: str = "unsigned_local"
    receipt_schema_version: str = ""
    project_id: str = ""
    environment_id: str = ""
    trust_epoch: int = 0

    def to_dict(self) -> dict[str, Any]:
        transformations_list: Any = []
        if isinstance(self.transformations, list):
            for t in self.transformations:
                if isinstance(t, dict):
                    transformations_list.append(dict(t))
                else:
                    transformations_list.append(t)
        else:
            transformations_list = self.transformations

        payload: dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "subject": self.subject,
            "proposed_action": self.proposed_action,
            "declared_goal": self.declared_goal,
            "execution_boundary": self.execution_boundary,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "decision": self.decision,
            "matched_rules": list(self.matched_rules),
            "constraints": (
                dict(self.constraints) if isinstance(self.constraints, dict) else self.constraints
            ),
            "transformations": transformations_list,
            "approval_chain_summary": (
                dict(self.approval_chain_summary)
                if isinstance(self.approval_chain_summary, dict)
                else self.approval_chain_summary
            ),
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
            "authority": self.authority,
            "validator_id": self.validator_id,
            "validator_role": self.validator_role,
            "argument_hash": self.argument_hash,
            "previous_audit_hash": self.previous_audit_hash,
            "audit_event_hash": self.audit_event_hash,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
            "receipt_hash": self.receipt_hash,
            "signature": self.signature,
        }
        if self.receipt_schema_version:
            payload["receipt_schema_version"] = self.receipt_schema_version
            payload["project_id"] = self.project_id
            payload["environment_id"] = self.environment_id
            payload["trust_epoch"] = self.trust_epoch
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DecisionReceipt:
        from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError
        from gove_zone.trust import RECEIPT_V1, RECEIPT_V2

        v2_only = {"project_id", "environment_id", "trust_epoch"}
        schema_version = d.get("receipt_schema_version", "")
        if not schema_version:
            present_v2 = sorted(field for field in v2_only if field in d)
            if present_v2:
                raise ReceiptValidationError(
                    "receipt v1 cannot carry v2-only scoped trust fields: " + ", ".join(present_v2),
                    reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
                )
        elif schema_version == RECEIPT_V1:
            raise ReceiptValidationError(
                "receipt v1 is represented by an absent receipt_schema_version field",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        elif schema_version != RECEIPT_V2:
            raise ReceiptValidationError(
                f"unsupported receipt schema version: {schema_version!r}",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        elif not all(field in d for field in v2_only):
            missing = sorted(field for field in v2_only if field not in d)
            raise ReceiptValidationError(
                "receipt v2 missing scoped trust fields: " + ", ".join(missing),
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        trust_epoch_raw = d.get("trust_epoch", 0)
        if type(trust_epoch_raw) is not int:
            raise ReceiptValidationError(
                "trust_epoch must be a positive integer",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        trust_epoch = trust_epoch_raw
        if schema_version == RECEIPT_V2:
            if trust_epoch <= 0:
                raise ReceiptValidationError(
                    "trust_epoch must be positive for receipt v2",
                    reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
                )
            for field in ("project_id", "environment_id"):
                if not isinstance(d.get(field), str) or not d[field].strip():
                    raise ReceiptValidationError(
                        f"{field} is required for receipt v2",
                        reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
                    )
        return cls(
            receipt_id=d["receipt_id"],
            request_id=d["request_id"],
            tenant_id=d["tenant_id"],
            actor=d["actor"],
            subject=d.get("subject", ""),
            proposed_action=d["proposed_action"],
            declared_goal=d["declared_goal"],
            execution_boundary=d["execution_boundary"],
            policy_bundle_id=d["policy_bundle_id"],
            policy_version=d["policy_version"],
            policy_hash=d["policy_hash"],
            decision=d["decision"],
            matched_rules=list(d["matched_rules"]),
            constraints=dict(d.get("constraints", {})),
            transformations=[dict(t) for t in d.get("transformations", [])],
            approval_chain_summary=dict(d.get("approval_chain_summary", {})),
            timestamp=d["timestamp"],
            expires_at=d.get("expires_at", ""),
            authority=d.get("authority", ""),
            validator_id=d.get("validator_id", ""),
            validator_role=d.get("validator_role", ""),
            argument_hash=d.get("argument_hash", ""),
            previous_audit_hash=d["previous_audit_hash"],
            audit_event_hash=d["audit_event_hash"],
            receipt_hash=d.get("receipt_hash", ""),
            signature_algorithm=d.get("signature_algorithm", "none"),
            signing_key_id=d.get("signing_key_id", ""),
            signature=d.get("signature", "unsigned_local"),
            receipt_schema_version=schema_version,
            project_id=d.get("project_id", ""),
            environment_id=d.get("environment_id", ""),
            trust_epoch=trust_epoch,
        )

    @classmethod
    def from_json(cls, text: str) -> DecisionReceipt:
        return cls.from_dict(json.loads(text))

    def _hash_payload(self) -> dict[str, Any]:
        """Payload fed to :meth:`compute_hash`, without the defensive copies
        :meth:`to_dict` makes for external callers and without the two
        hash-excluded fields. Byte-identical to ``to_dict()`` with
        ``receipt_hash``/``signature`` popped: the frozen receipt's fields
        cannot mutate, and ``sha256_json`` serializes a tuple and a list
        identically, so referencing the fields directly yields the same
        canonical bytes.
        """
        payload: dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "subject": self.subject,
            "proposed_action": self.proposed_action,
            "declared_goal": self.declared_goal,
            "execution_boundary": self.execution_boundary,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "decision": self.decision,
            "matched_rules": self.matched_rules,
            "constraints": self.constraints,
            "transformations": self.transformations,
            "approval_chain_summary": self.approval_chain_summary,
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
            "authority": self.authority,
            "validator_id": self.validator_id,
            "validator_role": self.validator_role,
            "argument_hash": self.argument_hash,
            "previous_audit_hash": self.previous_audit_hash,
            "audit_event_hash": self.audit_event_hash,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
        }
        if self.receipt_schema_version:
            payload["receipt_schema_version"] = self.receipt_schema_version
            payload["project_id"] = self.project_id
            payload["environment_id"] = self.environment_id
            payload["trust_epoch"] = self.trust_epoch
        return payload

    def compute_hash(self) -> str:
        return sha256_json(self._hash_payload())

    @classmethod
    def from_record(
        cls,
        record: DecisionRecord,
        audit_hash: str,
        previous_audit_hash: str,
        tenant_id: str,
        execution_boundary: str,
        policy_bundle_id: str,
        policy_hash: str,
        request_id: str,
        *,
        validator: Validator,
        authority: str,
        subject: str = "",
        constraints: dict[str, Any] | None = None,
        approval_chain_summary: dict[str, Any] | None = None,
        expires_at: str = "",
        signer: ReceiptSigner | None = None,
    ) -> DecisionReceipt:
        """Mint a receipt for *record*, binding a distinct MACI *validator*.

        Fail-closed: the validator must differ from the proposer
        (``record.actor``). A self-validated receipt — where the proposer would
        also be its own authority — can never be minted. The proposer/validator
        linkage is recorded in ``approval_chain_summary``.

        If *signer* is provided, its ``algorithm`` and ``key_id`` are bound into
        ``receipt_hash`` (anti-downgrade) and ``signature`` is the signer's
        signature over the hash. With ``signer=None`` (default) the receipt is
        unsigned (``signature_algorithm="none"``, ``signature="unsigned_local"``),
        fully backward-compatible.
        """
        from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError

        proposer = record.actor or "anonymous"
        if validator.validator_id == proposer:
            raise ReceiptValidationError(
                "self-validation forbidden: validator must differ from proposer "
                f"(both are {proposer!r})",
                reason_code=ReceiptRejectionReason.SELF_VALIDATION,
            )

        transformations: list[dict[str, Any]] = []
        if record.transformed_args:
            for k, v in record.transformed_args.items():
                transformations.append({"field": k, "value": v})

        linkage: dict[str, Any] = dict(approval_chain_summary or {})
        linkage.update(
            {
                "proposer": proposer,
                "validator_id": validator.validator_id,
                "validator_role": validator.role,
                "authority": authority,
            }
        )

        receipt = cls(
            receipt_id=record.event_id,
            request_id=request_id,
            tenant_id=tenant_id,
            actor=proposer,
            subject=subject,
            proposed_action=record.tool,
            declared_goal=record.goal or "",
            execution_boundary=execution_boundary,
            policy_bundle_id=policy_bundle_id,
            policy_version=record.policy_version,
            policy_hash=policy_hash,
            decision=record.decision.value,
            matched_rules=list(record.matched_rules),
            constraints=constraints or {},
            transformations=transformations,
            approval_chain_summary=linkage,
            timestamp=record.timestamp_iso,
            expires_at=expires_at,
            authority=authority,
            validator_id=validator.validator_id,
            validator_role=validator.role,
            argument_hash=record.argument_hash,
            previous_audit_hash=previous_audit_hash,
            audit_event_hash=audit_hash,
            signature_algorithm=signer.algorithm if signer is not None else "none",
            signing_key_id=signer.key_id if signer is not None else "",
        )
        # Compute the hash AFTER alg+key_id are set so they bind into it
        # (anti-downgrade), THEN sign that hash so the signature attests it.
        h = receipt.compute_hash()
        signature = signer.sign(h.encode("utf-8")) if signer is not None else "unsigned_local"
        object.__setattr__(receipt, "receipt_hash", h)
        object.__setattr__(receipt, "signature", signature)
        return receipt

    @classmethod
    def from_record_v2(
        cls,
        record: DecisionRecord,
        audit_hash: str,
        previous_audit_hash: str,
        tenant_id: str,
        project_id: str,
        environment_id: str,
        trust_epoch: int,
        execution_boundary: str,
        policy_bundle_id: str,
        policy_hash: str,
        request_id: str,
        *,
        validator: Validator,
        authority: str,
        signer: ReceiptSigner,
        subject: str = "",
        constraints: dict[str, Any] | None = None,
        approval_chain_summary: dict[str, Any] | None = None,
        expires_at: str = "",
    ) -> DecisionReceipt:
        """Mint a receipt-v2 bound to project/environment/trust epoch.

        The caller must provide a signer. There is no unsigned v2 issuance
        helper because v2 is the production scoped-trust contract.
        """
        from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError
        from gove_zone.trust import RECEIPT_V2

        if not project_id or not project_id.strip():
            raise ReceiptValidationError(
                "project_id is required for receipt v2",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        if not environment_id or not environment_id.strip():
            raise ReceiptValidationError(
                "environment_id is required for receipt v2",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        if type(trust_epoch) is not int or trust_epoch <= 0:
            raise ReceiptValidationError(
                "trust_epoch must be positive for receipt v2",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        if not expires_at or not expires_at.strip():
            raise ReceiptValidationError(
                "expires_at is required for receipt v2",
                reason_code=ReceiptRejectionReason.EXPIRY_REQUIRED,
            )
        receipt = cls.from_record(
            record=record,
            audit_hash=audit_hash,
            previous_audit_hash=previous_audit_hash,
            tenant_id=tenant_id,
            execution_boundary=execution_boundary,
            policy_bundle_id=policy_bundle_id,
            policy_hash=policy_hash,
            request_id=request_id,
            validator=validator,
            authority=authority,
            subject=subject,
            constraints=constraints,
            approval_chain_summary=approval_chain_summary,
            expires_at=expires_at,
        )
        object.__setattr__(receipt, "receipt_schema_version", RECEIPT_V2)
        object.__setattr__(receipt, "project_id", project_id)
        object.__setattr__(receipt, "environment_id", environment_id)
        object.__setattr__(receipt, "trust_epoch", trust_epoch)
        object.__setattr__(receipt, "signature_algorithm", signer.algorithm)
        object.__setattr__(receipt, "signing_key_id", signer.key_id)
        h = receipt.compute_hash()
        object.__setattr__(receipt, "receipt_hash", h)
        object.__setattr__(receipt, "signature", signer.sign(h.encode("utf-8")))
        return receipt

    def verify(
        self,
        *,
        expected_tenant_id: str | None = None,
        expected_execution_boundary: str | None = None,
        expected_audit_hash: str | None = None,
        expected_args: dict[str, Any] | None = None,
        expected_action: str | None = None,
        expected_policy_hash: str | None = None,
        expected_policy_bundle_id: str | None = None,
        expected_constraints: dict[str, Any] | None = None,
        expected_project_id: str | None = None,
        expected_environment_id: str | None = None,
        expected_validator_role: str | None = None,
        expected_authority: str | None = None,
        expected_actor: str | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool = False,
        require_expiry: bool = False,
        revoked_keys: RevocationList | None = None,
        trust_registry: ReceiptTrustRegistry | None = None,
        historical_trust_verification: bool = False,
        trust_purpose: str = "decision-receipt",
        now_iso: str | None = None,
        max_clock_skew_seconds: int = DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
    ) -> None:
        """Low-level receipt verification primitive.

        NOTE: ``require_signature`` defaults to ``False`` here — this is the bare
        primitive. The secure production posture (default ``require_signature=True``)
        lives at the gate surfaces — :func:`gove_zone.executor.execute_with_receipt`,
        :class:`gove_zone.executor.GovernedExecutor`, and
        :class:`gove_zone.contracts.ReceiptVerifier`. Authorize side effects through
        those, not by calling this directly; a bare ``verify(...)`` opts into the
        unsigned posture.

        ``require_expiry`` (additive, default ``False``) mandates a *liveness*
        bound: when ``True`` a receipt whose ``expires_at`` is empty is rejected
        (:data:`ReceiptRejectionReason.EXPIRY_REQUIRED`) instead of being treated
        as never-expiring. The plain expiry check below (#13) only rejects a
        receipt *past* its lifetime — with no TTL it is silently immortal. The
        strict production profile
        (:meth:`gove_zone.profile.GovernanceProfile.production_strict`) sets this
        so a long-lived bearer receipt cannot authorize indefinitely. Default
        ``False`` keeps every existing caller unaffected.

        ``revoked_keys`` (additive, default ``None``) is a
        :class:`gove_zone.revocation.RevocationList` of compromised *signing*
        ``key_id`` values. When supplied, a receipt whose ``signing_key_id`` is
        revoked is rejected (:data:`ReceiptRejectionReason.SIGNING_KEY_REVOKED`)
        *before* the signature is trusted — independent of whether the key is
        still present in ``verifier``. ``None`` (the default) preserves current
        behavior exactly.

        ``max_clock_skew_seconds`` bounds receipt not-before liveness. A receipt
        whose signed issuance ``timestamp`` is more than this many seconds in
        the verifier's future is rejected with
        :data:`ReceiptRejectionReason.RECEIPT_EXPIRED`, the same liveness class
        used for expired receipts. The default five-minute skew preserves normal
        distributed-clock tolerance while preventing correctly signed receipts
        issued far in the future from becoming bearer authorizations before
        their issuance time.
        """
        from gove_zone.decision import Decision
        from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError
        from gove_zone.trust import (
            RECEIPT_V2,
            ReceiptTrustScope,
            TrustConfigurationError,
            TrustedReceiptKey,
        )

        verification_now_iso = now_iso if now_iso is not None else _now_iso()
        if not isinstance(trust_purpose, str) or not trust_purpose.strip():
            raise ReceiptValidationError(
                "trust_purpose is required for scoped receipt verification",
                reason_code=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
            )

        # 1. Missing fields
        required_fields = [
            "receipt_id",
            "request_id",
            "tenant_id",
            "actor",
            "proposed_action",
            "execution_boundary",
            "policy_bundle_id",
            "policy_version",
            "policy_hash",
            "decision",
            "timestamp",
            "previous_audit_hash",
            "audit_event_hash",
            "validator_id",
            "validator_role",
            "authority",
            "argument_hash",
        ]
        for field_name in required_fields:
            val = getattr(self, field_name)
            if val is None or val == "":
                raise ReceiptValidationError(
                    f"Missing or empty required field: {field_name}",
                    reason_code=ReceiptRejectionReason.MISSING_REQUIRED_FIELD,
                )

        # 2. Check receipt hash (reject altered fields or invalid hash)
        if not self.receipt_hash:
            raise ReceiptValidationError(
                "receipt_hash is missing",
                reason_code=ReceiptRejectionReason.RECEIPT_HASH_MISSING,
            )
        expected_hash = self.compute_hash()
        if self.receipt_hash != expected_hash:
            raise ReceiptValidationError(
                f"Altered field or invalid hash: receipt_hash mismatch. "
                f"Expected {expected_hash}, got {self.receipt_hash}",
                reason_code=ReceiptRejectionReason.RECEIPT_HASH_MISMATCH,
            )

        is_v2 = self.receipt_schema_version == RECEIPT_V2
        if self.receipt_schema_version and not is_v2:
            raise ReceiptValidationError(
                f"unsupported receipt schema version: {self.receipt_schema_version!r}",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        if not is_v2 and (self.project_id or self.environment_id or self.trust_epoch):
            raise ReceiptValidationError(
                "receipt v1 cannot carry v2 scoped trust fields",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        if is_v2:
            if (
                not self.project_id
                or not self.environment_id
                or type(self.trust_epoch) is not int
                or self.trust_epoch <= 0
            ):
                raise ReceiptValidationError(
                    "receipt v2 requires project_id, environment_id, and positive trust_epoch",
                    reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
                )
            if not self.expires_at:
                raise ReceiptValidationError(
                    "receipt v2 requires expires_at",
                    reason_code=ReceiptRejectionReason.EXPIRY_REQUIRED,
                )
            if (
                self.signature_algorithm == "none"
                or not self.signing_key_id
                or not self.signature
                or self.signature == "unsigned_local"
            ):
                raise ReceiptValidationError(
                    "receipt v2 requires a trusted signature",
                    reason_code=ReceiptRejectionReason.UNSIGNED_REJECTED,
                )
            if (
                expected_tenant_id is None
                or expected_project_id is None
                or expected_environment_id is None
            ):
                raise ReceiptValidationError(
                    "receipt v2 requires expected tenant/project/environment scope",
                    reason_code=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
                )
            if self.project_id != expected_project_id:
                raise ReceiptValidationError(
                    f"Project mismatch: expected {expected_project_id}, got {self.project_id}",
                    reason_code=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
                )
            if self.environment_id != expected_environment_id:
                raise ReceiptValidationError(
                    "Environment mismatch: expected "
                    f"{expected_environment_id}, got {self.environment_id}",
                    reason_code=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
                )
            if trust_registry is None:
                raise ReceiptValidationError(
                    "receipt v2 requires a scoped trust registry",
                    reason_code=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
                )

        # 2a. Asymmetric signature check. Placed AFTER the receipt_hash check
        # because the signature attests an intact hash: a tampered field is caught
        # above before we trust the signature. Fail-closed: a verification
        # *failure* raises ReceiptValidationError (stays on the single gate path),
        # never SigningError.
        #
        # Two distinct failure modes with distinct semantics:
        #
        #   (i)  ``require_signature=True`` + ``algorithm=="none"``: the gate
        #        demands a signed receipt but this one is unsigned → reject.
        #        ``require_signature`` governs ONLY unsigned receipts.
        #
        #   (ii) ``algorithm != "none"``: the receipt CLAIMS a signature. It MUST
        #        be verified, period — regardless of ``require_signature``. A signed
        #        receipt presented without a verifier is rejected. This is the
        #        fail-closed rule: a receipt that advertises a signature cannot
        #        silently skip cryptographic verification.
        #
        # signature_algorithm and signing_key_id are bound into receipt_hash, so
        # an attacker cannot downgrade the algorithm or swap the key without
        # breaking check 2 above.
        if require_signature and self.signature_algorithm == "none":
            raise ReceiptValidationError(
                "unsigned receipt rejected: signature required",
                reason_code=ReceiptRejectionReason.UNSIGNED_REJECTED,
            )
        if self.signature_algorithm != "none":
            # 2a-revoke (B2): reject a revoked signing key BEFORE resolving the
            # verifier or trusting the signature. This is independent of
            # verifier-map membership — a revoked key still present in the map,
            # with a cryptographically valid signature, is rejected. Placed
            # inside the signed branch, so it can never reject an unsigned
            # receipt (algorithm=="none" ⇒ signing_key_id=="" never reaches
            # here), and it fires regardless of require_signature (a dev-mode
            # signed receipt with a revoked key is still rejected).
            if revoked_keys is not None and revoked_keys.is_revoked(self.signing_key_id):
                raise ReceiptValidationError(
                    f"signing key revoked: {self.signing_key_id!r}",
                    reason_code=ReceiptRejectionReason.SIGNING_KEY_REVOKED,
                )
            # Resolve the verifier — a missing verifier is a hard rejection here
            # (the receipt claims a signature; we must check it).
            resolved: ReceiptSigner | None
            if is_v2:
                assert expected_tenant_id is not None
                assert expected_project_id is not None
                assert expected_environment_id is not None
                assert trust_registry is not None
                scope = ReceiptTrustScope(
                    tenant_id=expected_tenant_id,
                    project_id=expected_project_id,
                    environment_id=expected_environment_id,
                    purpose=trust_purpose,
                )
                mode: Literal["execution", "historical"] = (
                    "historical" if historical_trust_verification else "execution"
                )
                try:
                    trusted_key = trust_registry.resolve(
                        scope=scope,
                        trust_epoch=self.trust_epoch,
                        algorithm=self.signature_algorithm,
                        key_id=self.signing_key_id,
                        now_iso=verification_now_iso,
                        mode=mode,
                    )
                    if not isinstance(trusted_key, TrustedReceiptKey):
                        raise ValueError("trusted key descriptor has wrong type")
                    trusted_key.validate()
                    if (
                        trusted_key.scope != scope
                        or trusted_key.scope.purpose != trust_purpose
                        or trusted_key.key_id != self.signing_key_id
                        or trusted_key.algorithm != self.signature_algorithm
                        or not trusted_key.verifies_epoch(self.trust_epoch, mode=mode)
                    ):
                        raise ValueError("trusted key descriptor mismatch")
                    if mode == "execution" and trusted_key.status != "active":
                        raise ValueError("execution trust key must be active")
                    if mode == "execution" and not trusted_key.is_live_at(verification_now_iso):
                        raise ValueError("execution trust key expired")
                    if mode == "historical" and trusted_key.status not in ("active", "retired"):
                        raise ValueError("historical trust key status rejected")
                    resolved = trusted_key.verifier
                    if resolved.key_id != self.signing_key_id:
                        raise ValueError("verifier key id mismatch")
                except (Exception, TrustConfigurationError):
                    raise ReceiptValidationError(
                        "scoped trust key resolution failed",
                        reason_code=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
                    ) from None
            elif isinstance(verifier, Mapping):
                if self.signing_key_id not in verifier:
                    raise ReceiptValidationError(
                        "unknown signing key",
                        reason_code=ReceiptRejectionReason.SIGNING_KEY_UNKNOWN,
                    )
                resolved = verifier[self.signing_key_id]
            elif verifier is not None:
                resolved = verifier
            else:
                raise ReceiptValidationError(
                    "signed receipt requires a configured verifier",
                    reason_code=ReceiptRejectionReason.SIGNED_RECEIPT_NO_VERIFIER,
                )
            if resolved.algorithm != self.signature_algorithm:
                raise ReceiptValidationError(
                    "signature algorithm mismatch",
                    reason_code=ReceiptRejectionReason.SIGNATURE_ALG_MISMATCH,
                )
            if not resolved.verify(self.receipt_hash.encode("utf-8"), self.signature):
                raise ReceiptValidationError(
                    "invalid signature",
                    reason_code=ReceiptRejectionReason.SIGNATURE_INVALID,
                )

        # 2b. MACI actor-anchor check (authoritative when caller supplies identity).
        # expected_actor is the identity of the INVOKING PRINCIPAL at the gate,
        # supplied from outside the receipt (like expected_tenant_id), so a
        # receipt author cannot satisfy it by editing the receipt's own fields.
        # Two enforcement steps when expected_actor is provided:
        #   (i)  actor mismatch  — this receipt was not issued for this caller.
        #   (ii) self-validation — the caller IS the validator, so the caller
        #        would be authorising its own action.
        if expected_actor is not None:
            if self.actor != expected_actor:
                raise ReceiptValidationError(
                    f"actor mismatch: receipt not issued for this caller "
                    f"(expected {expected_actor!r}, got {self.actor!r})",
                    reason_code=ReceiptRejectionReason.ACTOR_MISMATCH,
                )
            if self.validator_id == expected_actor:
                raise ReceiptValidationError(
                    f"self-validation: validator is the invoking principal ({expected_actor!r})",
                    reason_code=ReceiptRejectionReason.SELF_VALIDATION,
                )

        # 2c. Naive self-validation fallback — RESIDUAL defense-in-depth only.
        # The gate surfaces (execute_with_receipt / GovernedExecutor /
        # ReceiptVerifier) now REQUIRE expected_actor, so 2b above is the
        # authoritative proposer-binding check on every gated path; this fallback
        # is no longer reachable through the gate with the anchor omitted. It
        # survives solely for direct verify() callers who pass no expected_actor.
        # It catches only the obvious case where validator_id and actor on the
        # receipt are identical. A forger who sets actor to a phantom value while
        # keeping validator_id as the real proposer bypasses THIS check; real
        # proposer-binding requires expected_actor above (and ultimately
        # authenticated/signed issuance, which is roadmap).
        if self.validator_id == self.actor:
            raise ReceiptValidationError(
                f"self-validation: validator must differ from proposer (both are {self.actor!r})",
                reason_code=ReceiptRejectionReason.SELF_VALIDATION,
            )

        # 2d. approval_chain_summary consistency: the issued summary must agree
        # with the top-level validator_id and actor fields, which are bound into
        # receipt_hash. Divergence means the receipt was either constructed
        # inconsistently or the summary was hand-edited after hashing.
        acs = self.approval_chain_summary if isinstance(self.approval_chain_summary, dict) else {}
        if acs:
            if acs.get("validator_id") != self.validator_id:
                raise ReceiptValidationError(
                    "approval_chain_summary.validator_id disagrees with receipt",
                    reason_code=ReceiptRejectionReason.APPROVAL_CHAIN_DIVERGENCE,
                )
            if acs.get("proposer") != self.actor:
                raise ReceiptValidationError(
                    "approval_chain_summary.proposer disagrees with receipt",
                    reason_code=ReceiptRejectionReason.APPROVAL_CHAIN_DIVERGENCE,
                )

        # 3. Unknown decisions
        try:
            Decision(self.decision)
        except ValueError as err:
            raise ReceiptValidationError(
                f"Unknown decision: {self.decision}",
                reason_code=ReceiptRejectionReason.UNKNOWN_DECISION,
            ) from err

        # 5. Wrong tenant
        if expected_tenant_id is not None and self.tenant_id != expected_tenant_id:
            raise ReceiptValidationError(
                f"Tenant mismatch: expected {expected_tenant_id}, got {self.tenant_id}",
                reason_code=ReceiptRejectionReason.TENANT_MISMATCH,
            )

        # 6. Wrong execution boundary
        if (
            expected_execution_boundary is not None
            and self.execution_boundary != expected_execution_boundary
        ):
            raise ReceiptValidationError(
                f"Execution boundary mismatch: expected {expected_execution_boundary}, "
                f"got {self.execution_boundary}",
                reason_code=ReceiptRejectionReason.EXECUTION_BOUNDARY_MISMATCH,
            )

        # 7. Action mismatch
        if expected_action is not None and self.proposed_action != expected_action:
            raise ReceiptValidationError(
                f"Action mismatch: expected {expected_action}, got {self.proposed_action}",
                reason_code=ReceiptRejectionReason.ACTION_MISMATCH,
            )

        # 8. Audit hash mismatch
        if expected_audit_hash is not None and self.audit_event_hash != expected_audit_hash:
            raise ReceiptValidationError(
                f"Audit hash mismatch: expected {expected_audit_hash}, got {self.audit_event_hash}",
                reason_code=ReceiptRejectionReason.AUDIT_HASH_MISMATCH,
            )

        # 9. Malformed transformations
        if not isinstance(self.transformations, list):
            raise ReceiptValidationError(
                "transformations must be a list",
                reason_code=ReceiptRejectionReason.TRANSFORMATIONS_MALFORMED,
            )
        for tx in self.transformations:
            if not isinstance(tx, dict):
                raise ReceiptValidationError(
                    "each transformation must be a dictionary",
                    reason_code=ReceiptRejectionReason.TRANSFORMATIONS_MALFORMED,
                )
            if "field" not in tx or "value" not in tx:
                raise ReceiptValidationError(
                    "transformation dictionary must contain 'field' and 'value' keys",
                    reason_code=ReceiptRejectionReason.TRANSFORMATIONS_MALFORMED,
                )
            if not isinstance(tx["field"], str):
                raise ReceiptValidationError(
                    "transformation 'field' key must be a string",
                    reason_code=ReceiptRejectionReason.TRANSFORMATIONS_MALFORMED,
                )

        # 10. Transform mismatch
        if self.decision == Decision.TRANSFORM.value and expected_args is not None:
            for tx in self.transformations:
                f = tx["field"]
                val = tx["value"]
                if f not in expected_args:
                    raise ReceiptValidationError(
                        f"Transform mismatch: field '{f}' is missing from arguments",
                        reason_code=ReceiptRejectionReason.TRANSFORM_MISMATCH,
                    )
                if expected_args[f] != val:
                    raise ReceiptValidationError(
                        f"Transform mismatch: field '{f}' expected '{val}', "
                        f"got '{expected_args[f]}'",
                        reason_code=ReceiptRejectionReason.TRANSFORM_MISMATCH,
                    )

            # 10c. Exact-match binding for TRANSFORM — symmetric with ALLOW (#10b).
            # A governed TRANSFORM must fully specify what runs; fields left
            # unspecified would execute un-approved, which is the same class of
            # hole the ALLOW argument_hash check closes. transformed_args is the
            # complete approved execution set by construction (from_record turns
            # every key of DecisionRecord.transformed_args into a transformations
            # entry), so the executed args must equal that set exactly.
            approved = {tx["field"]: tx["value"] for tx in self.transformations}
            if dict(expected_args) != approved:
                raise ReceiptValidationError(
                    "transform mismatch: executed arguments do not exactly match the approved "
                    "transformed arguments (extra, missing, or altered fields)",
                    reason_code=ReceiptRejectionReason.TRANSFORM_MISMATCH,
                )

        # 10b. Native argument binding: for ALLOW/DENY/ESCALATE decisions, verify
        # that the args presented at the gate were exactly what the receipt
        # covers. DENY/ESCALATE still cannot authorize execution, but this check
        # keeps their refusal diagnostics provenance-preserving: a correctly
        # signed non-ALLOW receipt with wrong arguments is first rejected as an
        # argument mismatch rather than being rendered as a fully bound
        # DENY/ESCALATE artifact.
        # argument_hash is sha256_json(dict(args)) — same canonicalization as
        # ToolCall.argument_hash(). This closes the substitution gap: a valid
        # ALLOW receipt for write_file(path=/tmp/safe) cannot authorize
        # write_file(path=/etc/shadow). Only triggered when expected_args is
        # provided (execute_with_receipt always provides it). Not enforced on
        # TRANSFORM because the executed args are the transformed args, which
        # differ from the original proposed args that argument_hash covers;
        # the transform-field check (#10) already binds TRANSFORM execution.
        if (
            self.decision
            in (
                Decision.ALLOW.value,
                Decision.DENY.value,
                Decision.ESCALATE.value,
            )
            and expected_args is not None
        ):
            from gove_zone.decision import sha256_json as _sha256_json

            computed_arg_hash = _sha256_json(dict(expected_args))
            if self.argument_hash != computed_arg_hash:
                raise ReceiptValidationError(
                    "argument mismatch: receipt not issued for these arguments",
                    reason_code=ReceiptRejectionReason.ARGUMENT_MISMATCH,
                )

        # 11. Policy hash mismatch
        if expected_policy_hash is not None and self.policy_hash != expected_policy_hash:
            raise ReceiptValidationError(
                f"Policy hash mismatch: expected {expected_policy_hash}, got {self.policy_hash}",
                reason_code=ReceiptRejectionReason.POLICY_HASH_MISMATCH,
            )

        # 12. Policy bundle ID mismatch
        if (
            expected_policy_bundle_id is not None
            and self.policy_bundle_id != expected_policy_bundle_id
        ):
            raise ReceiptValidationError(
                f"Policy bundle ID mismatch: expected {expected_policy_bundle_id}, "
                f"got {self.policy_bundle_id}",
                reason_code=ReceiptRejectionReason.POLICY_BUNDLE_MISMATCH,
            )

        if expected_constraints is not None:
            from gove_zone.decision import canonical_json as _canonical_json

            if _canonical_json(self.constraints) != _canonical_json(expected_constraints):
                raise ReceiptValidationError(
                    "receipt constraints do not exactly match the gate contract",
                    reason_code=ReceiptRejectionReason.CONSTRAINTS_MISMATCH,
                )

        # 12b. Validator role mismatch (optional)
        if expected_validator_role is not None and self.validator_role != expected_validator_role:
            raise ReceiptValidationError(
                f"Validator role mismatch: expected {expected_validator_role}, "
                f"got {self.validator_role}",
                reason_code=ReceiptRejectionReason.VALIDATOR_ROLE_MISMATCH,
            )

        # 12c. Authority mismatch (optional)
        if expected_authority is not None and self.authority != expected_authority:
            raise ReceiptValidationError(
                f"Authority mismatch: expected {expected_authority}, got {self.authority}",
                reason_code=ReceiptRejectionReason.AUTHORITY_MISMATCH,
            )

        # 13a. Liveness floor (opt-in, strict profile). With no TTL a receipt is
        # silently immortal — the check below only rejects one *past* its
        # lifetime. When require_expiry is set, an empty expires_at is itself a
        # failure: a long-lived bearer receipt must not authorize indefinitely.
        # Default-off, so non-strict callers are unaffected. Fail-closed.
        if (require_expiry or is_v2) and not self.expires_at:
            raise ReceiptValidationError(
                "Receipt has no expires_at but the strict profile requires a "
                "liveness/TTL bound (a receipt without an expiry can authorize "
                "indefinitely).",
                reason_code=ReceiptRejectionReason.EXPIRY_REQUIRED,
            )

        bounded_clock_skew_seconds = validate_receipt_clock_skew_seconds(max_clock_skew_seconds)

        # 13. Liveness window. ``timestamp`` and ``expires_at`` are both bound
        # into receipt_hash, so tampering is already caught by check 2. Parse
        # timezone-aware datetimes and enforce expiry for every expiring receipt.
        # For signed/v2 receipts, also enforce a closed interval with bounded
        # future issuance skew:
        #
        #   timestamp - skew <= now <= expires_at
        #
        # A correctly signed receipt issued too far in the future is not yet
        # valid. A receipt whose expiry predates issuance has no valid lifetime.
        # Both reject under RECEIPT_EXPIRED so higher-level contracts can map
        # the entire liveness class to EXPIRED.
        #
        # OPERATOR TRUST ASSUMPTION: expiry trusts the verifying host's wall
        # clock. A host whose clock is rolled BACK accepts a genuinely-expired
        # receipt as still-valid (fail-open against time, not against policy).
        # This is an operator responsibility — keep gate hosts on trusted,
        # monotonic, NTP-synced time. For expiry-sensitive deployments, inject a
        # vetted time source via ``now_iso`` rather than relying on the host
        # clock. gove-zone does not (yet) carry its own trusted time source.
        if self.expires_at:
            current = verification_now_iso
            # Compare timezone-aware datetimes, not strings: a lexicographic
            # compare is wrong across UTC offsets and would fail OPEN. Both
            # timestamp and expires_at participate in liveness; unparseable
            # timestamps are validation failures.
            try:
                current_dt = datetime.fromisoformat(current)
                issued_dt = datetime.fromisoformat(self.timestamp)
                expires_dt = datetime.fromisoformat(self.expires_at)
            except (ValueError, TypeError) as err:
                raise ReceiptValidationError(
                    f"Unparseable or mismatched expiry timestamp: "
                    f"timestamp={self.timestamp!r}, expires_at={self.expires_at!r}, "
                    f"now={current!r}",
                    reason_code=ReceiptRejectionReason.EXPIRY_UNPARSEABLE,
                ) from err
            # Reject offset-naive timestamps on either side. Two naive datetimes
            # parse and compare without error, but their implied zones are
            # ambiguous — a naive comparison can silently fail OPEN across
            # offsets. Demand aware-vs-aware so expiry is unambiguous; a naive
            # input is a validation failure, never silently accepted.
            if current_dt.tzinfo is None or issued_dt.tzinfo is None or expires_dt.tzinfo is None:
                raise ReceiptValidationError(
                    f"Expiry timestamps must be timezone-aware (offset-naive "
                    f"compares are ambiguous and can fail open): "
                    f"timestamp={self.timestamp!r}, expires_at={self.expires_at!r}, "
                    f"now={current!r}",
                    reason_code=ReceiptRejectionReason.EXPIRY_UNPARSEABLE,
                )
            authenticated_liveness = is_v2 or self.signature_algorithm != "none"
            if authenticated_liveness:
                if expires_dt < issued_dt:
                    raise ReceiptValidationError(
                        f"Receipt expired before it was issued: timestamp {self.timestamp}, "
                        f"expires_at {self.expires_at}",
                        reason_code=ReceiptRejectionReason.RECEIPT_EXPIRED,
                    )
                skew = timedelta(seconds=bounded_clock_skew_seconds)
                if issued_dt - current_dt > skew:
                    raise ReceiptValidationError(
                        f"Receipt is not yet valid: issued at {self.timestamp} "
                        f"(now {current}, allowed skew {bounded_clock_skew_seconds}s)",
                        reason_code=ReceiptRejectionReason.RECEIPT_EXPIRED,
                    )
            if current_dt > expires_dt:
                raise ReceiptValidationError(
                    f"Receipt expired at {self.expires_at} (now {current})",
                    reason_code=ReceiptRejectionReason.RECEIPT_EXPIRED,
                )

        # 14. Denied and escalated receipts. Keep this after integrity,
        # signature/trust, liveness, and all caller-supplied bindings so the
        # rejection reason reports the first real verifier failure for malformed
        # DENY/ESCALATE artifacts, while still refusing before any gate can burn
        # a ledger entry or run the side effect.
        if self.decision == Decision.DENY:
            raise ReceiptValidationError(
                "Denied receipt cannot authorize execution",
                reason_code=ReceiptRejectionReason.DENIED_RECEIPT,
            )
        if self.decision == Decision.ESCALATE:
            raise ReceiptValidationError(
                "Escalated receipt cannot authorize execution",
                reason_code=ReceiptRejectionReason.ESCALATED_RECEIPT,
            )
