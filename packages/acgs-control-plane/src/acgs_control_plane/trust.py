"""Control-plane managed receipt-v2 trust providers.

This module is route-inaccessible. It persists public verifier material,
resolves trust roots inside a caller-owned SQL transaction, and mints managed
receipt-v2 artifacts only through an injected in-process signer provider.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import sqlalchemy as sa
from gove_zone.decision import DecisionRecord
from gove_zone.errors import ReceiptValidationError
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.signing import Ed25519Signer, ReceiptSigner
from gove_zone.trust import (
    DECISION_RECEIPT_PURPOSE,
    ReceiptTrustScope,
    TrustConfigurationError,
    TrustedReceiptKey,
    TrustReadinessIssue,
    TrustReadinessReport,
    TrustResolutionMode,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from acgs_control_plane.models import (
    ManagedDecisionReceipt,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    ManagedTrustScope,
    new_id,
    utcnow,
)


class ManagedReceiptContext(Protocol):
    org_id: str
    project_id: str
    environment_id: str
    actor: str
    action: str
    execution_boundary: str
    policy_bundle_id: str
    policy_hash: str
    validator_role: str
    authority: str


class ManagedTrustError(RuntimeError):
    """Fail-closed trust lifecycle or provider error."""


class ManagedPlatformIssuer(Protocol):
    """Injected signer provider; implementations must not persist private keys."""

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def signer_for_scope(self, scope: ReceiptTrustScope, *, trust_epoch: int) -> ReceiptSigner: ...


@dataclass(frozen=True)
class InProcessPlatformIssuer:
    """Local injected signer provider with repr-safe private-key custody."""

    signer: ReceiptSigner = field(repr=False, compare=False)
    allowed_purposes: frozenset[str] = field(
        default_factory=lambda: frozenset({DECISION_RECEIPT_PURPOSE})
    )

    @property
    def key_id(self) -> str:
        return self.signer.key_id

    @property
    def algorithm(self) -> str:
        return self.signer.algorithm

    def signer_for_scope(self, scope: ReceiptTrustScope, *, trust_epoch: int) -> ReceiptSigner:
        if scope.purpose not in self.allowed_purposes:
            raise ManagedTrustError("managed platform issuer is not authorized for this purpose")
        if type(trust_epoch) is not int or trust_epoch <= 0:
            raise ManagedTrustError("managed platform issuer requires a positive trust epoch")
        return self.signer


class SqlReceiptTrustRegistry:
    """ReceiptTrustRegistry backed by the caller's active SQLAlchemy Session."""

    def __init__(
        self,
        session: Session,
        *,
        lock_rows: bool = False,
        preloaded_rows: Iterable[ManagedTrustKey] | None = None,
        preloaded_index: Mapping[tuple[str, str, str, str], tuple[ManagedTrustKey, ...]]
        | None = None,
    ) -> None:
        self._session = session
        self._lock_rows = lock_rows
        self._preloaded_rows = tuple(preloaded_rows) if preloaded_rows is not None else None
        self._preloaded_index = preloaded_index

    def resolve(
        self,
        *,
        scope: ReceiptTrustScope,
        trust_epoch: int,
        algorithm: str,
        key_id: str,
        now_iso: str,
        mode: TrustResolutionMode = "execution",
    ) -> TrustedReceiptKey:
        if mode not in ("execution", "historical"):
            raise TrustConfigurationError("unknown trust resolution mode")
        if type(trust_epoch) is not int or trust_epoch <= 0:
            raise TrustConfigurationError("trust_epoch must be a positive integer")
        now = _parse_aware_utc(now_iso, field_name="now_iso")
        scope.__post_init__()
        if self._preloaded_rows is None and self._preloaded_index is None:
            query = (
                sa.select(ManagedTrustKey)
                .where(
                    ManagedTrustKey.org_id == scope.tenant_id,
                    ManagedTrustKey.project_id == scope.project_id,
                    ManagedTrustKey.environment_id == scope.environment_id,
                    ManagedTrustKey.purpose == scope.purpose,
                )
                .order_by(ManagedTrustKey.activated_epoch.asc())
            )
            if self._lock_rows:
                query = query.with_for_update()
            rows = list(self._session.scalars(query))
        elif self._preloaded_index is not None:
            rows = list(
                self._preloaded_index.get(
                    (scope.tenant_id, scope.project_id, scope.environment_id, scope.purpose), ()
                )
            )
        else:
            assert self._preloaded_rows is not None
            rows = sorted(
                (
                    row
                    for row in self._preloaded_rows
                    if row.org_id == scope.tenant_id
                    and row.project_id == scope.project_id
                    and row.environment_id == scope.environment_id
                    and row.purpose == scope.purpose
                ),
                key=lambda row: row.activated_epoch,
            )
        active_rows = [row for row in rows if row.status == "active"]
        if len(active_rows) > 1:
            raise TrustConfigurationError("multiple active trust roots for scope")
        candidates = [
            row
            for row in rows
            if row.key_id == key_id
            and row.algorithm == algorithm
            and _row_verifies_epoch(row, trust_epoch, mode=mode)
        ]
        for row in reversed(candidates):
            key = _trusted_key_from_row(row)
            key.validate()
            if (
                key.scope != scope
                or key.key_id != key_id
                or key.algorithm != algorithm
                or not key.verifies_epoch(trust_epoch, mode=mode)
            ):
                raise TrustConfigurationError("trusted key descriptor mismatch")
            if mode == "execution":
                if key.status != "active":
                    raise TrustConfigurationError("execution trust key must be active")
                if _to_aware_utc(row.not_after) < now:
                    raise TrustConfigurationError("active trust root expired")
            return key
        raise TrustConfigurationError(
            "no trusted receipt key for scope/purpose/epoch/algorithm/key"
        )

    def readiness(
        self, scopes: Iterable[ReceiptTrustScope] = (), *, now_iso: str
    ) -> TrustReadinessReport:
        now = _parse_aware_utc(now_iso, field_name="now_iso")
        wanted = tuple(scopes)
        query = sa.select(ManagedTrustKey)
        if wanted:
            query = query.where(
                sa.tuple_(
                    ManagedTrustKey.org_id,
                    ManagedTrustKey.project_id,
                    ManagedTrustKey.environment_id,
                    ManagedTrustKey.purpose,
                ).in_(
                    [
                        (
                            scope.tenant_id,
                            scope.project_id,
                            scope.environment_id,
                            scope.purpose,
                        )
                        for scope in wanted
                    ]
                )
            )
        rows = list(self._session.scalars(query))
        discovered = {
            ReceiptTrustScope(row.org_id, row.project_id, row.environment_id, row.purpose)
            for row in rows
        }
        check_scopes = wanted or tuple(sorted(discovered, key=repr))
        issues: list[TrustReadinessIssue] = []
        if not check_scopes:
            issues.append(TrustReadinessIssue("missing-root", None, "no trust scopes configured"))
        for scope in check_scopes:
            scope_rows = [
                row
                for row in rows
                if (
                    row.org_id,
                    row.project_id,
                    row.environment_id,
                    row.purpose,
                )
                == (scope.tenant_id, scope.project_id, scope.environment_id, scope.purpose)
            ]
            if not scope_rows:
                issues.append(TrustReadinessIssue("missing-root", scope, "no keys for scope"))
                continue
            for row in scope_rows:
                try:
                    _trusted_key_from_row(row).validate()
                except TrustConfigurationError as exc:
                    issues.append(TrustReadinessIssue("malformed-root", scope, str(exc)))
            active = [row for row in scope_rows if row.status == "active"]
            if not active:
                issues.append(TrustReadinessIssue("no-active-root", scope, "no active key"))
            elif len(active) > 1:
                issues.append(TrustReadinessIssue("malformed-root", scope, "multiple active roots"))
            elif _to_aware_utc(active[0].not_after) < now:
                issues.append(TrustReadinessIssue("expired-root", scope, "active root expired"))
        return TrustReadinessReport(ready=not issues, issues=tuple(issues))


class ManagedTrustLifecycleService:
    """Rotate public receipt trust roots under the caller's SQL transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def bootstrap(
        self,
        *,
        scope: ReceiptTrustScope,
        key_id: str,
        algorithm: str,
        public_key_spki_der: bytes,
        not_after: datetime,
    ) -> ManagedTrustKey:
        scope.__post_init__()
        if self._locked_scope(scope) is not None or self._key_history_exists(scope):
            raise ManagedTrustError("trust scope bootstrap is one-time")
        return self._insert_new_active(
            scope=scope,
            key_id=key_id,
            algorithm=algorithm,
            public_key_spki_der=public_key_spki_der,
            activated_epoch=1,
            not_after=not_after,
            expected_current_epoch=None,
        )

    def rotate(
        self,
        *,
        scope: ReceiptTrustScope,
        key_id: str,
        algorithm: str,
        public_key_spki_der: bytes,
        not_after: datetime,
        expected_current_epoch: int,
    ) -> ManagedTrustKey:
        if type(expected_current_epoch) is not int or expected_current_epoch <= 0:
            raise ManagedTrustError("expected_current_epoch must be a positive integer")
        scope_row = self._locked_scope(scope)
        if scope_row is None:
            raise ManagedTrustError("trust scope is not bootstrapped")
        current = self._active_key(scope)
        if current is None or current.activated_epoch != expected_current_epoch:
            raise ManagedTrustError("trust rotation epoch precondition failed")
        current.status = "retired"
        current.retired_epoch = current.activated_epoch + 1
        current.updated_at = utcnow()
        return self._insert_new_active(
            scope=scope,
            key_id=key_id,
            algorithm=algorithm,
            public_key_spki_der=public_key_spki_der,
            activated_epoch=current.retired_epoch,
            not_after=not_after,
            expected_current_epoch=expected_current_epoch,
        )

    def revoke(self, *, scope: ReceiptTrustScope, key_id: str, algorithm: str) -> None:
        rows = list(
            self._session.scalars(
                sa.select(ManagedTrustKey)
                .where(
                    ManagedTrustKey.org_id == scope.tenant_id,
                    ManagedTrustKey.project_id == scope.project_id,
                    ManagedTrustKey.environment_id == scope.environment_id,
                    ManagedTrustKey.purpose == scope.purpose,
                    ManagedTrustKey.key_id == key_id,
                    ManagedTrustKey.algorithm == algorithm,
                )
                .with_for_update()
            )
        )
        if not rows:
            raise ManagedTrustError("trust key not found")
        for row in rows:
            if row.status == "revoked":
                continue
            row.status = "revoked"
            row.retired_epoch = None
            row.updated_at = utcnow()
        self._session.flush()

    def _insert_new_active(
        self,
        *,
        scope: ReceiptTrustScope,
        key_id: str,
        algorithm: str,
        public_key_spki_der: bytes,
        activated_epoch: int,
        not_after: datetime,
        expected_current_epoch: int | None,
    ) -> ManagedTrustKey:
        scope.__post_init__()
        not_after_utc = _to_aware_utc(not_after)
        descriptor = TrustedReceiptKey(
            scope=scope,
            key_id=key_id,
            algorithm=algorithm,
            public_key_spki_der=public_key_spki_der,
            activated_epoch=activated_epoch,
            not_after=not_after_utc.isoformat(),
            status="active",
        )
        descriptor.validate()
        scope_row = self._locked_scope(scope)
        now = utcnow()
        if scope_row is None:
            if expected_current_epoch is not None:
                raise ManagedTrustError("trust scope is not bootstrapped")
            scope_row = ManagedTrustScope(
                id=new_id(),
                org_id=scope.tenant_id,
                project_id=scope.project_id,
                environment_id=scope.environment_id,
                purpose=scope.purpose,
                created_at=now,
                updated_at=now,
            )
            self._session.add(scope_row)
            self._session.flush()
        else:
            if expected_current_epoch is None:
                raise ManagedTrustError("trust scope bootstrap is one-time")
            scope_row.updated_at = now
        row = ManagedTrustKey(
            id=new_id(),
            org_id=scope.tenant_id,
            project_id=scope.project_id,
            environment_id=scope.environment_id,
            purpose=scope.purpose,
            key_id=key_id,
            algorithm=algorithm,
            public_key_spki_der=public_key_spki_der,
            activated_epoch=activated_epoch,
            not_after=not_after_utc,
            status="active",
            retired_epoch=None,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        try:
            self._session.flush()
        except IntegrityError as exc:
            raise ManagedTrustError("trust activation conflicted with another writer") from exc
        return row

    def _locked_scope(self, scope: ReceiptTrustScope) -> ManagedTrustScope | None:
        return self._session.scalars(
            sa.select(ManagedTrustScope)
            .where(
                ManagedTrustScope.org_id == scope.tenant_id,
                ManagedTrustScope.project_id == scope.project_id,
                ManagedTrustScope.environment_id == scope.environment_id,
                ManagedTrustScope.purpose == scope.purpose,
            )
            .with_for_update()
        ).first()

    def _active_key(self, scope: ReceiptTrustScope) -> ManagedTrustKey | None:
        return self._session.scalars(
            sa.select(ManagedTrustKey)
            .where(
                ManagedTrustKey.org_id == scope.tenant_id,
                ManagedTrustKey.project_id == scope.project_id,
                ManagedTrustKey.environment_id == scope.environment_id,
                ManagedTrustKey.purpose == scope.purpose,
                ManagedTrustKey.status == "active",
            )
            .with_for_update()
        ).first()

    def _key_history_exists(self, scope: ReceiptTrustScope) -> bool:
        return bool(
            self._session.scalar(
                sa.select(ManagedTrustKey.id)
                .where(
                    ManagedTrustKey.org_id == scope.tenant_id,
                    ManagedTrustKey.project_id == scope.project_id,
                    ManagedTrustKey.environment_id == scope.environment_id,
                    ManagedTrustKey.purpose == scope.purpose,
                )
                .with_for_update()
            )
        )


def mint_managed_decision_receipt_v2(
    *,
    issuer: ManagedPlatformIssuer,
    context: ManagedReceiptContext,
    record: DecisionRecord,
    audit_hash: str,
    previous_audit_hash: str,
    trust_epoch: int,
    request_id: str,
    expires_at: str,
    purpose: str = DECISION_RECEIPT_PURPOSE,
    constraints: dict[str, Any] | None = None,
    approval_chain_summary: dict[str, Any] | None = None,
) -> DecisionReceipt:
    """Mint a scoped receipt-v2 from server-owned context and injected issuer."""

    scope = ReceiptTrustScope(
        tenant_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        purpose=purpose,
    )
    signer = issuer.signer_for_scope(scope, trust_epoch=trust_epoch)
    if signer.key_id != issuer.key_id or signer.algorithm != issuer.algorithm:
        raise ManagedTrustError("managed issuer signer metadata mismatch")
    if record.tool != context.action:
        raise ReceiptValidationError("managed receipt record action does not match context")
    if record.actor != context.actor:
        raise ReceiptValidationError("managed receipt record actor does not match context")
    return DecisionReceipt.from_record_v2(
        record=record,
        audit_hash=audit_hash,
        previous_audit_hash=previous_audit_hash,
        tenant_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        trust_epoch=trust_epoch,
        execution_boundary=context.execution_boundary,
        policy_bundle_id=context.policy_bundle_id,
        policy_hash=context.policy_hash,
        request_id=request_id,
        validator=Validator(context.authority, role=context.validator_role),
        authority=context.authority,
        signer=signer,
        constraints=constraints,
        approval_chain_summary=approval_chain_summary,
        expires_at=expires_at,
    )


def active_trust_epoch_for_scope(session: Session, scope: ReceiptTrustScope) -> int:
    row = session.scalars(
        sa.select(ManagedTrustKey)
        .where(
            ManagedTrustKey.org_id == scope.tenant_id,
            ManagedTrustKey.project_id == scope.project_id,
            ManagedTrustKey.environment_id == scope.environment_id,
            ManagedTrustKey.purpose == scope.purpose,
            ManagedTrustKey.status == "active",
        )
        .with_for_update()
    ).one_or_none()
    if row is None:
        raise ManagedTrustError("missing active trust root")
    return row.activated_epoch


def counts_for_scope(session: Session, context: ManagedReceiptContext) -> Mapping[str, int]:
    """Small test/support helper for zero-effect assertions."""

    where_scope = (
        ManagedDecisionReceipt.org_id == context.org_id,
        ManagedDecisionReceipt.project_id == context.project_id,
        ManagedDecisionReceipt.environment_id == context.environment_id,
    )
    receipts = (
        session.scalar(
            sa.select(sa.func.count()).select_from(ManagedDecisionReceipt).where(*where_scope)
        )
        or 0
    )
    consumptions = (
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedReceiptConsumption)
            .where(
                ManagedReceiptConsumption.org_id == context.org_id,
                ManagedReceiptConsumption.project_id == context.project_id,
                ManagedReceiptConsumption.environment_id == context.environment_id,
            )
        )
        or 0
    )
    return {"receipts": receipts, "consumptions": consumptions}


def public_spki_der_from_signer(signer: ReceiptSigner) -> bytes:
    """Return canonical Ed25519 SPKI DER for a signer without exposing private key bytes."""

    if signer.algorithm != "ed25519":
        raise ManagedTrustError("only Ed25519 signers are supported for receipt-v2 trust")
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:  # pragma: no cover
        raise ManagedTrustError("cryptography is required for Ed25519 SPKI DER") from exc
    if not isinstance(signer, Ed25519Signer):
        raise ManagedTrustError("managed trust bootstrap requires an Ed25519Signer")
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id=signer.key_id)
    return verifier._public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _trusted_key_from_row(row: ManagedTrustKey) -> TrustedReceiptKey:
    return TrustedReceiptKey(
        scope=ReceiptTrustScope(
            tenant_id=row.org_id,
            project_id=row.project_id,
            environment_id=row.environment_id,
            purpose=row.purpose,
        ),
        key_id=row.key_id,
        algorithm=row.algorithm,
        public_key_spki_der=bytes(row.public_key_spki_der),
        activated_epoch=row.activated_epoch,
        not_after=_to_aware_utc(row.not_after).isoformat(),
        status=row.status,
        retired_epoch=row.retired_epoch,
    )


def _row_verifies_epoch(
    row: ManagedTrustKey, trust_epoch: int, *, mode: TrustResolutionMode
) -> bool:
    if row.status == "revoked" or trust_epoch < row.activated_epoch:
        return False
    if mode == "execution":
        return row.status == "active"
    if row.status == "active":
        return True
    return (
        row.status == "retired"
        and row.retired_epoch is not None
        and trust_epoch < row.retired_epoch
    )


def _parse_aware_utc(value: str, *, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise TrustConfigurationError(f"{field_name} is required")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TrustConfigurationError(f"{field_name} must be ISO-8601") from exc
    return _to_aware_utc(parsed)


def _to_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "InProcessPlatformIssuer",
    "ManagedPlatformIssuer",
    "ManagedTrustError",
    "ManagedTrustLifecycleService",
    "SqlReceiptTrustRegistry",
    "active_trust_epoch_for_scope",
    "mint_managed_decision_receipt_v2",
    "public_spki_der_from_signer",
]
