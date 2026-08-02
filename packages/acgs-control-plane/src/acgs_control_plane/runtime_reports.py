"""Authenticated, governed acceptance of append-only runtime reports."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import timedelta
from types import MappingProxyType
from typing import Any, cast

import sqlalchemy as sa
from gove_zone.decision import Decision, sha256_json
from gove_zone.errors import ReceiptValidationError
from gove_zone.policy_sync import (
    POLICY_ENVELOPE_PURPOSE,
    POLICY_SYNC_ATTESTATION_PURPOSE,
    ManagedPolicyProvenance,
    PolicySyncError,
    PolicySyncSnapshot,
    verify_policy_sync_snapshot,
)
from gove_zone.receipt import safe_result_hash
from gove_zone.runtime_identity import (
    RuntimeIdentityDescriptor,
    RuntimeIdentityError,
    sha256_bytes,
    verify_ed25519,
    verify_signed_runtime_request,
)
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope, TrustConfigurationError
from gove_zone.wiring_attestation import (
    AttestationReplayGuard,
    ExpectedWiringContext,
    WiringAttestation,
    WiringAttestationError,
    verify_wiring_attestation,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
    ManagedMutationReplayResult,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
    ManagedReplayArtifactValidationError,
    ManagedReplayPreload,
    build_managed_replay_preload,
    validate_managed_replay_artifacts,
)
from acgs_control_plane.models import (
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedGovernanceEventHead,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    RuntimeCredentialGeneration,
    RuntimeIdentity,
    RuntimeIdentityGate,
    RuntimeOperationIdempotency,
    RuntimeReport,
    RuntimeReportHead,
    RuntimeRequestNonce,
    RuntimeWiringAttestation,
    RuntimeWiringChallengeConsumption,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_sync import _active_gate
from acgs_control_plane.runtime_enrollment import (
    RUNTIME_ENROLLMENT_AUTHORITY,
    RUNTIME_SIGNED_REQUEST_SKEW_SECONDS,
    RuntimeEnrollmentHttpError,
    RuntimeEnrollmentProviderUnavailable,
    RuntimeEnrollmentService,
    RuntimeIdentityProviderUnavailable,
    _active_policy_context,
    _context,
    _decision_audit_hash,
    _decision_record,
    _idempotency_key_hash,
    _lock_policy_head,
    _non_executable_error_for_receipt,
    _parse_runtime_timestamp,
    _refusal_payload,
    _runtime_public_key_bytes,
    _runtime_timestamp,
    _sealed_terminal_response_payload,
    _to_utc,
    _verified_stored_terminal_payload,
    validate_current_runtime_identity_binding,
)
from acgs_control_plane.schemas import (
    RuntimeAttestationChallengeResponse,
    RuntimeReportRequest,
    RuntimeReportResponse,
)
from acgs_control_plane.trust import SqlReceiptTrustRegistry

REPORT_PATH_TEMPLATE = "/v1/runtime-identities/{identity_id}/reports"
CHALLENGE_PATH_TEMPLATE = "/v1/runtime-identities/{identity_id}/attestation-challenges"
REPORT_OPERATION = "report"
REPORT_PURPOSE = "runtime-report-http"
REPORT_HISTORY_GENESIS = "0" * 64


@dataclass(frozen=True)
class _FleetLineagePreload:
    receipts: tuple[ManagedDecisionReceipt, ...]
    managed: ManagedReplayPreload
    report_heads: tuple[RuntimeReportHead, ...]
    reports: tuple[RuntimeReport, ...]
    idempotencies: tuple[RuntimeOperationIdempotency, ...]
    nonces: tuple[RuntimeRequestNonce, ...]
    attestations: tuple[RuntimeWiringAttestation, ...]
    challenges: tuple[RuntimeWiringChallengeConsumption, ...]
    receipts_by_id: Mapping[str, tuple[ManagedDecisionReceipt, ...]] = field(init=False)
    heads_by_identity: Mapping[str, tuple[RuntimeReportHead, ...]] = field(init=False)
    reports_by_identity: Mapping[str, tuple[RuntimeReport, ...]] = field(init=False)
    idempotencies_by_identity: Mapping[str, tuple[RuntimeOperationIdempotency, ...]] = field(
        init=False
    )
    idempotencies_by_receipt: Mapping[tuple[str, str], tuple[RuntimeOperationIdempotency, ...]] = (
        field(init=False)
    )
    nonces_by_identity: Mapping[str, tuple[RuntimeRequestNonce, ...]] = field(init=False)
    nonces_by_identity_nonce: Mapping[tuple[str, str], tuple[RuntimeRequestNonce, ...]] = field(
        init=False
    )
    attestations_by_report: Mapping[str, tuple[RuntimeWiringAttestation, ...]] = field(init=False)
    challenges_by_report: Mapping[str, tuple[RuntimeWiringChallengeConsumption, ...]] = field(
        init=False
    )

    def __post_init__(self) -> None:
        def grouped(
            rows: tuple[Any, ...], key: Callable[[Any], Any]
        ) -> Mapping[Any, tuple[Any, ...]]:
            values: dict[Any, list[Any]] = {}
            for row in rows:
                values.setdefault(key(row), []).append(row)
            return MappingProxyType({item_key: tuple(group) for item_key, group in values.items()})

        object.__setattr__(
            self, "receipts_by_id", grouped(self.receipts, lambda row: row.receipt_id)
        )
        object.__setattr__(
            self, "heads_by_identity", grouped(self.report_heads, lambda row: row.identity_id)
        )
        object.__setattr__(
            self, "reports_by_identity", grouped(self.reports, lambda row: row.identity_id)
        )
        object.__setattr__(
            self,
            "idempotencies_by_identity",
            grouped(self.idempotencies, lambda row: row.identity_id),
        )
        object.__setattr__(
            self,
            "idempotencies_by_receipt",
            grouped(self.idempotencies, lambda row: (row.identity_id, row.receipt_id)),
        )
        object.__setattr__(
            self, "nonces_by_identity", grouped(self.nonces, lambda row: row.identity_id)
        )
        object.__setattr__(
            self,
            "nonces_by_identity_nonce",
            grouped(self.nonces, lambda row: (row.identity_id, row.nonce)),
        )
        object.__setattr__(
            self,
            "attestations_by_report",
            grouped(self.attestations, lambda row: row.report_id),
        )
        object.__setattr__(
            self, "challenges_by_report", grouped(self.challenges, lambda row: row.report_id)
        )


CHALLENGE_PURPOSE = "wiring-attestation-challenge"
MAX_REPORT_TTL_SECONDS = 900
CHALLENGE_TTL_SECONDS = 300
IJSON_MAX_SAFE_INTEGER = 9_007_199_254_740_991
CHALLENGE_NONCE_PRF_DOMAIN = b"acgs.runtime-attestation-challenge.nonce-prf/v1\x00"
CHALLENGE_TOKEN_SIGNATURE_DOMAIN = b"acgs.runtime-attestation-challenge.token/v1\x00"


class _RuntimeReportReplay(RuntimeError):
    def __init__(self, response: RuntimeReportResponse) -> None:
        self.response = response
        super().__init__("validated runtime report replay")


class RuntimeReportProviderUnavailable(RuntimeError):
    """A runtime-report cryptographic provider failed at an explicit boundary."""


def _provider_sign(provider: Any, payload: bytes) -> str:
    try:
        return cast(str, provider.sign(payload))
    except Exception as exc:
        raise RuntimeReportProviderUnavailable from exc


def _provider_public_key_bytes(provider: Any) -> bytes:
    try:
        return cast(bytes, provider.public_key_bytes())
    except Exception as exc:
        raise RuntimeReportProviderUnavailable from exc


@dataclass(frozen=True)
class RuntimeReportAuth:
    key_id: str
    credential_id: str
    credential_generation: int
    audience: str
    timestamp: str
    nonce: str
    body_sha256: str
    signature: str


class _SqlAttestationReplayGuard(AttestationReplayGuard):
    def __init__(
        self,
        session: Session,
        *,
        identity: RuntimeIdentity,
        idempotency_key_hash: str,
        request_hash: str,
        expected_nonce: str,
        expected_sequence: int,
        credential: RuntimeCredentialGeneration,
        report_id: str,
        receipt_id: str,
        projection_commitment: str,
        consumed_at: Any,
    ) -> None:
        self._session = session
        self._identity = identity
        self._idempotency_key_hash = idempotency_key_hash
        self._request_hash = request_hash
        self._expected_nonce = expected_nonce
        self._expected_sequence = expected_sequence
        self._credential = credential
        self._report_id = report_id
        self._receipt_id = receipt_id
        self._projection_commitment = projection_commitment
        self._consumed_at = consumed_at

    def consume(self, *, namespace_digest: str, nonce: str, sequence: int) -> bool:
        if nonce != self._expected_nonce or sequence != self._expected_sequence:
            return False
        existing = self._session.scalars(
            sa.select(RuntimeWiringChallengeConsumption).where(
                RuntimeWiringChallengeConsumption.org_id == self._identity.org_id,
                RuntimeWiringChallengeConsumption.project_id == self._identity.project_id,
                RuntimeWiringChallengeConsumption.environment_id == self._identity.environment_id,
                RuntimeWiringChallengeConsumption.identity_id == self._identity.id,
                RuntimeWiringChallengeConsumption.challenge_nonce == nonce,
            )
        ).one_or_none()
        if existing is not None:
            return False
        self._session.add(
            RuntimeWiringChallengeConsumption(
                id=new_id(),
                org_id=self._identity.org_id,
                project_id=self._identity.project_id,
                environment_id=self._identity.environment_id,
                identity_id=self._identity.id,
                credential_id=self._credential.id,
                credential_generation=self._credential.generation,
                sequence=sequence,
                expected_sequence=self._expected_sequence,
                report_kind="wiring",
                report_id=self._report_id,
                receipt_id=self._receipt_id,
                challenge_nonce=nonce,
                namespace_digest=hashlib.sha256(namespace_digest.encode("utf-8")).hexdigest(),
                idempotency_key_hash=self._idempotency_key_hash,
                request_hash=self._request_hash,
                projection_commitment=self._projection_commitment,
                consumed_at=self._consumed_at,
            )
        )
        self._session.flush()
        return True


class _RevalidationAttestationReplayGuard(AttestationReplayGuard):
    def __init__(
        self, *, expected_nonce: str, expected_sequence: int, namespace_digest: str
    ) -> None:
        self._expected_nonce = expected_nonce
        self._expected_sequence = expected_sequence
        self._namespace_digest = namespace_digest

    def consume(self, *, namespace_digest: str, nonce: str, sequence: int) -> bool:
        return (
            nonce == self._expected_nonce
            and sequence == self._expected_sequence
            and hashlib.sha256(namespace_digest.encode("utf-8")).hexdigest()
            == self._namespace_digest
        )


class RuntimeReportService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        runtime_enrollment_service: RuntimeEnrollmentService,
        descriptor_signer: Any,
    ) -> None:
        self._session_factory = session_factory
        self._runtime_service = runtime_enrollment_service
        self._descriptor_signer = descriptor_signer
        self._runtime_binding_seal = self._runtime_binding_snapshot()
        self._accept_locks_guard = threading.Lock()
        self._accept_locks: weakref.WeakValueDictionary[str, threading.Lock] = (
            weakref.WeakValueDictionary()
        )

    def _runtime_binding_snapshot(self) -> tuple[Any, ...]:
        providers = self._runtime_service._providers

        def method_identity(value: Any, name: str) -> tuple[int, int]:
            bound = getattr(value, name)
            return id(value), id(getattr(bound, "__func__", bound))

        return (
            id(self._runtime_service),
            id(providers),
            id(self._descriptor_signer),
            getattr(self._descriptor_signer, "key_id", None),
            method_identity(self._descriptor_signer, "sign"),
            method_identity(self._descriptor_signer, "public_key_bytes"),
            id(providers.issuer),
            method_identity(providers.issuer, "signer_for_scope"),
            id(providers.receipt_sealer),
            method_identity(providers.receipt_sealer, "seal"),
            method_identity(providers.receipt_sealer, "unseal"),
            id(providers.descriptor_signer),
            method_identity(providers.descriptor_signer, "sign"),
            method_identity(providers.descriptor_signer, "public_key_bytes"),
            verify_policy_sync_snapshot,
            verify_wiring_attestation,
            verify_signed_runtime_request,
            validate_current_runtime_identity_binding,
            _decision_record,
            _authenticate_runtime_request,
            _verified_policy_provenance,
            _validate_anchored_report_lineage,
            _validate_current_report_head,
            validate_managed_replay_artifacts,
        )

    def _assert_runtime_bindings(self) -> None:
        if self._runtime_binding_snapshot() != self._runtime_binding_seal:
            raise RuntimeEnrollmentHttpError(
                503,
                "MUTATION_INVENTORY_DRIFT",
                "mutation_inventory_drift",
                "runtime report execution bindings changed after sealing",
            )

    def issue_challenge(
        self,
        *,
        identity_id: str,
        auth: RuntimeReportAuth,
        raw_path: bytes,
        raw_query: str,
        runtime_build_digest: str,
        configuration_digest: str,
        policy_snapshot_hash: str,
    ) -> RuntimeAttestationChallengeResponse:
        self._assert_runtime_bindings()
        path = CHALLENGE_PATH_TEMPLATE.format(identity_id=identity_id)
        expected_query = (
            f"runtime_build_digest={runtime_build_digest}"
            f"&configuration_digest={configuration_digest}"
            f"&policy_snapshot_hash={policy_snapshot_hash}"
        )
        if raw_path != path.encode("ascii") or raw_query != expected_query:
            raise _authentication_refused()
        with self._session_factory.begin() as session:
            identity, credential, gate = _authenticate_runtime_request(
                session,
                descriptor_signer=self._descriptor_signer,
                identity_id=identity_id,
                auth=auth,
                method="GET",
                path=path,
                query=expected_query,
                body=b"",
                idempotency_key=None,
                lock=True,
            )
            _, policy_version_id, policy_hash, _, policy_generation = _active_policy_context(
                session,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
            )
            try:
                expected_sequence = _locked_expected_report_sequence(session, identity=identity)
            except ManagedReplayArtifactValidationError as exc:
                raise _database_unavailable() from exc
            challenge_context = {
                "schema": "acgs.runtime-attestation-challenge/v1",
                "org_id": identity.org_id,
                "project_id": identity.project_id,
                "environment_id": identity.environment_id,
                "gate_id": gate.id,
                "identity_id": identity_id,
                "credential_id": credential.id,
                "credential_generation": credential.generation,
                "workload_key_id": credential.workload_key_id,
                "public_key_thumbprint": credential.public_key_thumbprint,
                "policy_version_id": policy_version_id,
                "policy_content_hash": policy_hash,
                "policy_head_generation": policy_generation,
                "expected_sequence": expected_sequence,
                "challenge_signing_key_id": self._descriptor_signer.key_id,
                "runtime_build_digest": runtime_build_digest,
                "configuration_digest": configuration_digest,
                "policy_snapshot_hash": policy_snapshot_hash,
                "request_timestamp": auth.timestamp,
                "request_nonce": auth.nonce,
            }
            prf_signature = _provider_sign(
                self._descriptor_signer,
                CHALLENGE_NONCE_PRF_DOMAIN + _canonical_bytes(challenge_context),
            )
            nonce = "attest-" + hashlib.sha256(prf_signature.encode("ascii")).hexdigest()
            issued_at = utcnow()
            expires_at = issued_at + timedelta(seconds=CHALLENGE_TTL_SECONDS)
            payload = {
                **challenge_context,
                "nonce": nonce,
                "issued_at": _runtime_timestamp(issued_at),
                "expires_at": _runtime_timestamp(expires_at),
            }
            encoded = _b64url(_canonical_bytes(payload))
            signature = _provider_sign(
                self._descriptor_signer,
                CHALLENGE_TOKEN_SIGNATURE_DOMAIN + encoded.encode("ascii"),
            )
            return RuntimeAttestationChallengeResponse(
                nonce=nonce,
                expected_sequence=expected_sequence,
                issued_at=issued_at,
                expires_at=expires_at,
                token=f"{encoded}.{signature}",
            )

    def accept(
        self,
        *,
        identity_id: str,
        auth: RuntimeReportAuth,
        body: RuntimeReportRequest,
        raw_body: bytes,
        raw_path: bytes,
        idempotency_key: str | None,
    ) -> RuntimeReportResponse:
        self._assert_runtime_bindings()
        idempotency_key = _require_idempotency_key(idempotency_key)
        if auth.body_sha256 != sha256_bytes(raw_body):
            raise _authentication_refused()
        path = REPORT_PATH_TEMPLATE.format(identity_id=identity_id)
        if raw_path != path.encode("ascii"):
            raise _authentication_refused()
        with self._session_factory() as session:
            _authenticate_runtime_request(
                session,
                descriptor_signer=self._descriptor_signer,
                identity_id=identity_id,
                auth=auth,
                method="POST",
                path=path,
                body=raw_body,
                idempotency_key=idempotency_key,
            )
        with self._accept_locks_guard:
            identity_lock = self._accept_locks.get(identity_id)
            if identity_lock is None:
                identity_lock = threading.Lock()
                self._accept_locks[identity_id] = identity_lock
        with identity_lock:
            self._assert_runtime_bindings()
            return self._accept_serialized(
                identity_id=identity_id,
                auth=auth,
                body=body,
                raw_body=raw_body,
                raw_path=raw_path,
                idempotency_key=idempotency_key,
            )

    def _accept_serialized(
        self,
        *,
        identity_id: str,
        auth: RuntimeReportAuth,
        body: RuntimeReportRequest,
        raw_body: bytes,
        raw_path: bytes,
        idempotency_key: str | None,
    ) -> RuntimeReportResponse:
        self._assert_runtime_bindings()
        idempotency_key = _require_idempotency_key(idempotency_key)
        if auth.body_sha256 != sha256_bytes(raw_body):
            raise _authentication_refused()
        path = REPORT_PATH_TEMPLATE.format(identity_id=identity_id)
        if raw_path != path.encode("ascii"):
            raise _authentication_refused()
        report_hash = hashlib.sha256(_canonical_bytes(body.model_dump(mode="json"))).hexdigest()
        request_hash = hashlib.sha256(
            _canonical_bytes({"identity_id": identity_id, "report_hash": report_hash})
        ).hexdigest()
        key_hash = _idempotency_key_hash(idempotency_key)
        accepted_at = utcnow()
        report_id = new_id()
        try:
            with self._session_factory() as session:
                identity, credential, gate = _authenticate_runtime_request(
                    session,
                    descriptor_signer=self._descriptor_signer,
                    identity_id=identity_id,
                    auth=auth,
                    method="POST",
                    path=path,
                    body=raw_body,
                    idempotency_key=idempotency_key,
                )
                existing = _idempotency(session, identity=identity, key_hash=key_hash)
                if existing is not None:
                    if existing.request_hash != request_hash:
                        raise _conflict("IDEMPOTENCY_CONFLICT")
                    stored_report = session.scalars(
                        sa.select(RuntimeReport).where(
                            RuntimeReport.org_id == existing.org_id,
                            RuntimeReport.project_id == existing.project_id,
                            RuntimeReport.environment_id == existing.environment_id,
                            RuntimeReport.identity_id == existing.identity_id,
                            RuntimeReport.receipt_id == existing.receipt_id,
                        )
                    ).one_or_none()
                    if stored_report is not None:
                        return _replay_report_operation(
                            session,
                            existing=existing,
                            identity=identity,
                            credential=credential,
                            body=body,
                            auth=auth,
                            expected_args={
                                "identity_id": identity.id,
                                "kind": body.kind,
                                "sequence": body.sequence,
                                "challenge_expected_sequence": stored_report.request_projection.get(
                                    "challenge_expected_sequence"
                                ),
                                "report_hash": report_hash,
                                "policy_version_id": body.policy_version_id,
                                "projection_commitment": stored_report.projection_commitment,
                            },
                            receipt_sealer=self._runtime_service._providers.receipt_sealer,
                            descriptor_signer=self._descriptor_signer,
                        )
                policy, policy_version_id, policy_hash, _, policy_generation = (
                    _active_policy_context(
                        session,
                        org_id=identity.org_id,
                        project_id=identity.project_id,
                        environment_id=identity.environment_id,
                    )
                )
                _require_current_binding(
                    body=body,
                    credential=credential,
                    policy_version_id=policy_version_id,
                    policy_hash=policy_hash,
                    policy_generation=policy_generation,
                )
                descriptor = RuntimeIdentityDescriptor.from_dict(identity.descriptor)
                initial_snapshot, initial_provenance = _verified_policy_provenance(
                    session,
                    body=body,
                    descriptor=descriptor,
                    now=accepted_at,
                )
                challenge_nonce = None
                challenge_expected_sequence = None
                if body.kind == "wiring":
                    if body.artifact is None or body.challenge_token is None:
                        raise ReceiptValidationError(
                            "wiring report requires artifact and challenge"
                        )
                    challenge_nonce, challenge_expected_sequence = self._verify_challenge(
                        body.challenge_token,
                        identity=identity,
                        credential=credential,
                        gate=gate,
                        body=body,
                        now=accepted_at,
                    )
                elif body.artifact is not None or body.challenge_token is not None:
                    raise ReceiptValidationError("status report cannot carry wiring evidence")
                request_projection = _runtime_report_projection(
                    report_id=report_id,
                    identity=identity,
                    credential=credential,
                    gate=gate,
                    body=body,
                    auth=auth,
                    report_hash=report_hash,
                    snapshot=initial_snapshot,
                    provenance=initial_provenance,
                    accepted_at=accepted_at,
                    challenge_nonce=challenge_nonce,
                    challenge_expected_sequence=challenge_expected_sequence,
                    history_checkpoint=_next_history_checkpoint(
                        session,
                        identity=identity,
                        report_id=report_id,
                        report_hash=report_hash,
                        kind=body.kind,
                        sequence=body.sequence,
                    ),
                )
                projection_commitment = sha256_json(request_projection)
                decision_projection = dict(request_projection)
                for server_field in (
                    "report_id",
                    "observed_at",
                    "created_at",
                    "history_checkpoint",
                ):
                    decision_projection.pop(server_field)
                args = {
                    "identity_id": identity.id,
                    "kind": body.kind,
                    "sequence": body.sequence,
                    "challenge_expected_sequence": challenge_expected_sequence,
                    "report_hash": report_hash,
                    "policy_version_id": policy_version_id,
                    "projection_commitment": sha256_json(decision_projection),
                }
                existing = _idempotency(session, identity=identity, key_hash=key_hash)
                if existing is not None:
                    if existing.request_hash != request_hash:
                        raise _conflict("IDEMPOTENCY_CONFLICT")
                    return _replay_report_operation(
                        session,
                        existing=existing,
                        identity=identity,
                        credential=credential,
                        body=body,
                        auth=auth,
                        expected_args=args,
                        receipt_sealer=self._runtime_service._providers.receipt_sealer,
                        descriptor_signer=self._descriptor_signer,
                    )
                context = _context(
                    org_id=identity.org_id,
                    project_id=identity.project_id,
                    environment_id=identity.environment_id,
                    actor=identity.actor,
                    action=CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
                    policy_bundle_id=policy_version_id,
                    policy_hash=policy_hash,
                    policy_head_generation=policy_generation,
                )
                record = _decision_record(
                    policy=policy,
                    context=context,
                    args=args,
                    goal="accept authenticated runtime report",
                )
                if record.decision is Decision.ALLOW:
                    args = {**args, "projection_commitment": projection_commitment}
                    record = _decision_record(
                        policy=policy,
                        context=context,
                        args=args,
                        goal="accept authenticated runtime report",
                    )
                audit_hash = _decision_audit_hash(record)
                context = replace(context, expected_audit_hash=audit_hash)
                try:
                    receipt = self._runtime_service._issue_receipt(
                        session=session,
                        context=context,
                        record=record,
                        audit_hash=audit_hash,
                        request_id=new_id(),
                    )
                except RuntimeEnrollmentHttpError as exc:
                    if exc.code == "SIGNER_UNAVAILABLE":
                        raise RuntimeReportProviderUnavailable from exc
                    raise
        except ReceiptValidationError as exc:
            raise _conflict("REPORT_REJECTED") from exc
        if record.decision is not Decision.ALLOW:
            try:
                raise self._runtime_service._record_non_executable(
                    context=context,
                    receipt=receipt,
                    args=args,
                    operation_name=REPORT_OPERATION,
                    idempotency_key_hash=key_hash,
                    request_hash=request_hash,
                    identity_id=identity_id,
                )
            except RuntimeEnrollmentProviderUnavailable as exc:
                raise RuntimeReportProviderUnavailable from exc
            except RuntimeEnrollmentHttpError as exc:
                if exc.code != "TX_ABORTED":
                    raise
                self._replay_after_conflict(
                    identity_id=identity_id,
                    auth=auth,
                    body=body,
                    raw_body=raw_body,
                    path=path,
                    idempotency_key=idempotency_key,
                    key_hash=key_hash,
                    request_hash=request_hash,
                    expected_args=args,
                )
                raise AssertionError(
                    "non-executable replay must raise its terminal response"
                ) from exc

        holder: dict[str, Any] = {}

        def before_attempt_reservation(
            session: Session,
        ) -> ManagedMutationReplayResult | None:
            locked_identity, locked_credential, locked_gate = _authenticate_runtime_request(
                session,
                descriptor_signer=self._descriptor_signer,
                identity_id=identity_id,
                auth=auth,
                method="POST",
                path=path,
                body=raw_body,
                idempotency_key=idempotency_key,
                lock=True,
            )
            _lock_policy_head(session, context=context)
            locked_existing = _idempotency(
                session, identity=locked_identity, key_hash=key_hash, lock=True
            )
            if locked_existing is not None:
                if locked_existing.request_hash != request_hash:
                    raise _conflict("IDEMPOTENCY_CONFLICT")
                return ManagedMutationReplayResult(
                    result=_replay_report_operation(
                        session,
                        existing=locked_existing,
                        identity=locked_identity,
                        credential=locked_credential,
                        body=body,
                        auth=auth,
                        expected_args=args,
                        receipt_sealer=self._runtime_service._providers.receipt_sealer,
                        descriptor_signer=self._descriptor_signer,
                    )
                )
            if (
                session.scalars(
                    sa.select(RuntimeRequestNonce).where(
                        RuntimeRequestNonce.org_id == locked_identity.org_id,
                        RuntimeRequestNonce.project_id == locked_identity.project_id,
                        RuntimeRequestNonce.environment_id == locked_identity.environment_id,
                        RuntimeRequestNonce.identity_id == locked_identity.id,
                        RuntimeRequestNonce.nonce == auth.nonce,
                    )
                ).one_or_none()
                is not None
            ):
                raise ReceiptValidationError("runtime report request nonce replayed")
            _require_current_binding(
                body=body,
                credential=locked_credential,
                policy_version_id=context.policy_bundle_id,
                policy_hash=context.policy_hash,
                policy_generation=cast(int, context.expected_policy_head_generation),
            )
            head = session.scalars(
                sa.select(RuntimeReportHead)
                .where(
                    RuntimeReportHead.org_id == locked_identity.org_id,
                    RuntimeReportHead.project_id == locked_identity.project_id,
                    RuntimeReportHead.environment_id == locked_identity.environment_id,
                    RuntimeReportHead.identity_id == locked_identity.id,
                )
                .with_for_update()
            ).one_or_none()
            if head is not None and head.last_sequence >= IJSON_MAX_SAFE_INTEGER:
                raise RuntimeEnrollmentHttpError(
                    409,
                    "SEQUENCE_EXHAUSTED",
                    "conflict",
                    "runtime report sequence is exhausted",
                )
            expected_sequence = (head.last_sequence if head is not None else 0) + 1
            if body.sequence != expected_sequence:
                raise ReceiptValidationError("runtime report sequence must advance exactly once")
            locked_challenge_nonce: str | None = None
            locked_challenge_expected_sequence: int | None = None
            if body.kind == "wiring":
                if body.artifact is None or body.challenge_token is None:
                    raise ReceiptValidationError("wiring report requires artifact and challenge")
                locked_challenge_nonce, locked_challenge_expected_sequence = self._verify_challenge(
                    body.challenge_token,
                    identity=locked_identity,
                    credential=locked_credential,
                    gate=locked_gate,
                    body=body,
                )
                try:
                    artifact = WiringAttestation.from_dict(body.artifact)
                except (KeyError, TypeError, ValueError) as exc:
                    raise ReceiptValidationError("wiring attestation is malformed") from exc
                if (
                    locked_challenge_expected_sequence != expected_sequence
                    or artifact.sequence != expected_sequence
                    or artifact.nonce != locked_challenge_nonce
                ):
                    raise ReceiptValidationError(
                        "wiring challenge is not bound to the current exact-next report"
                    )
            holder["locked_identity"] = locked_identity
            holder["locked_credential"] = locked_credential
            holder["locked_gate"] = locked_gate
            holder["head"] = head
            holder["minimum_sequence"] = head.last_sequence if head is not None else 0
            holder["challenge_nonce"] = locked_challenge_nonce
            holder["challenge_expected_sequence"] = locked_challenge_expected_sequence
            return None

        def operation_effect(session: Session, _args: dict[str, Any]) -> dict[str, Any]:
            now = utcnow()
            if (
                not now
                < _to_utc(body.expires_at)
                <= now + timedelta(seconds=MAX_REPORT_TTL_SECONDS)
            ):
                raise ReceiptValidationError("runtime report expiry is not current and bounded")
            identity = cast(RuntimeIdentity, holder["locked_identity"])
            credential = cast(RuntimeCredentialGeneration, holder["locked_credential"])
            gate = cast(RuntimeIdentityGate, holder["locked_gate"])
            minimum_sequence = int(holder["minimum_sequence"])
            if body.sequence != minimum_sequence + 1:
                raise ReceiptValidationError("runtime report sequence must advance exactly once")
            artifact: WiringAttestation | None = None
            descriptor = RuntimeIdentityDescriptor.from_dict(identity.descriptor)
            verified_snapshot, verified_provenance = _verified_policy_provenance(
                session,
                body=body,
                descriptor=descriptor,
                now=now,
            )
            policy_snapshot_hash = sha256_bytes(_canonical_bytes(body.policy_snapshot))
            policy_provenance_hash = verified_provenance.compute_hash()
            policy_issued_at = _parse_runtime_timestamp(verified_snapshot.issued_at)
            policy_revocation_checked_at = _parse_runtime_timestamp(
                verified_snapshot.revocation_checked_at
            )
            policy_fresh_until = _parse_runtime_timestamp(verified_snapshot.fresh_until)
            policy_expires_at = _parse_runtime_timestamp(verified_snapshot.expires_at)
            locked_projection = _runtime_report_projection(
                report_id=report_id,
                identity=identity,
                credential=credential,
                gate=gate,
                body=body,
                auth=auth,
                report_hash=report_hash,
                snapshot=verified_snapshot,
                provenance=verified_provenance,
                accepted_at=accepted_at,
                challenge_nonce=cast(str | None, request_projection["challenge_nonce"]),
                challenge_expected_sequence=cast(
                    int | None, request_projection["challenge_expected_sequence"]
                ),
                history_checkpoint=_next_history_checkpoint_from_head(
                    cast(RuntimeReportHead | None, holder["head"]),
                    report_id=report_id,
                    report_hash=report_hash,
                    kind=body.kind,
                    sequence=body.sequence,
                ),
            )
            if (
                locked_projection != request_projection
                or sha256_json(locked_projection) != projection_commitment
            ):
                raise ReceiptValidationError("runtime report projection changed before acceptance")
            if body.kind == "wiring":
                if body.artifact is None or body.challenge_token is None:
                    raise ReceiptValidationError(
                        "wiring report requires artifact, challenge, build, configuration, "
                        "and policy snapshot"
                    )
                challenge_nonce, challenge_expected_sequence = self._verify_challenge(
                    body.challenge_token,
                    identity=identity,
                    credential=credential,
                    gate=gate,
                    body=body,
                    now=now,
                )
                if (
                    challenge_nonce != holder["challenge_nonce"]
                    or challenge_expected_sequence != holder["challenge_expected_sequence"]
                    or challenge_expected_sequence != body.sequence
                ):
                    raise ReceiptValidationError("wiring challenge sequence binding changed")
                try:
                    artifact = WiringAttestation.from_dict(body.artifact)
                    verify_wiring_attestation(
                        artifact,
                        expected=ExpectedWiringContext(
                            scope=descriptor.scope,
                            runtime_identity_descriptor=descriptor,
                            runtime_identity_issuer_public_key=_provider_public_key_bytes(
                                self._descriptor_signer
                            ),
                            runtime_identity_audience=RUNTIME_ENROLLMENT_AUTHORITY,
                            receipt_trust_registry=SqlReceiptTrustRegistry(session, lock_rows=True),
                            receipt_trust_purpose=DECISION_RECEIPT_PURPOSE,
                            workload_key_id=credential.workload_key_id,
                            execution_boundary=gate.id,
                            runtime_build_digest=body.runtime_build_digest,
                            configuration_digest=body.configuration_digest,
                            policy_head=verified_provenance.to_dict(),
                            policy_provenance_hash=verified_provenance.compute_hash(),
                            policy_issued_at=verified_snapshot.issued_at,
                            policy_fresh_until=verified_snapshot.fresh_until,
                            policy_expires_at=verified_snapshot.expires_at,
                            policy_mode="fresh",
                            expected_nonce=challenge_nonce,
                            minimum_sequence=minimum_sequence,
                            now=now,
                            replay_guard=_SqlAttestationReplayGuard(
                                session,
                                identity=identity,
                                idempotency_key_hash=key_hash,
                                request_hash=request_hash,
                                expected_nonce=challenge_nonce,
                                expected_sequence=challenge_expected_sequence,
                                credential=credential,
                                report_id=report_id,
                                receipt_id=receipt.receipt_id,
                                projection_commitment=projection_commitment,
                                consumed_at=accepted_at,
                            ),
                        ),
                    )
                except (RuntimeIdentityError, WiringAttestationError, ValueError) as exc:
                    raise ReceiptValidationError("wiring attestation verification failed") from exc
                if (
                    artifact.scope.org_id != identity.org_id
                    or artifact.scope.project_id != identity.project_id
                    or artifact.scope.environment != identity.environment_id
                    or artifact.scope.gate_id != gate.id
                    or artifact.runtime.runtime_identity_id != identity.id
                    or artifact.runtime.credential_id != credential.id
                    or artifact.runtime.credential_generation != credential.generation
                    or artifact.policy_head.policy_version_id != body.policy_version_id
                    or artifact.policy_head.head_generation != body.policy_head_generation
                    or artifact.policy_head.content_hash != body.policy_content_hash
                    or artifact.sequence != body.sequence
                ):
                    raise ReceiptValidationError("wiring attestation binding is not current")
            elif body.artifact is not None or body.challenge_token is not None:
                raise ReceiptValidationError("status report cannot carry wiring evidence")
            report = RuntimeReport(
                id=report_id,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
                gate_id=gate.id,
                actor=identity.actor,
                identity_id=identity.id,
                credential_id=credential.id,
                credential_generation=credential.generation,
                workload_key_id=credential.workload_key_id,
                public_key_thumbprint=credential.public_key_thumbprint,
                policy_version_id=body.policy_version_id,
                policy_head_generation=body.policy_head_generation,
                policy_content_hash=body.policy_content_hash,
                runtime_build_digest=body.runtime_build_digest,
                configuration_digest=body.configuration_digest,
                policy_snapshot_hash=policy_snapshot_hash,
                policy_provenance_hash=policy_provenance_hash,
                policy_issued_at=policy_issued_at,
                policy_revocation_checked_at=policy_revocation_checked_at,
                policy_fresh_until=policy_fresh_until,
                policy_expires_at=policy_expires_at,
                kind=body.kind,
                sequence=body.sequence,
                nonce=auth.nonce,
                report_hash=report_hash,
                projection_commitment=projection_commitment,
                request_projection=request_projection,
                request_signature=auth.signature,
                receipt_id=receipt.receipt_id,
                observed_at=accepted_at,
                expires_at=body.expires_at,
                created_at=accepted_at,
            )
            session.add(report)
            session.add(
                RuntimeRequestNonce(
                    id=new_id(),
                    org_id=identity.org_id,
                    project_id=identity.project_id,
                    environment_id=identity.environment_id,
                    identity_id=identity.id,
                    nonce=auth.nonce,
                    idempotency_key_hash=key_hash,
                    request_hash=request_hash,
                    purpose=REPORT_PURPOSE,
                )
            )
            if artifact is not None:
                session.add(
                    RuntimeWiringAttestation(
                        id=new_id(),
                        org_id=identity.org_id,
                        project_id=identity.project_id,
                        environment_id=identity.environment_id,
                        gate_id=gate.id,
                        identity_id=identity.id,
                        report_kind="wiring",
                        report_id=report.id,
                        attestation_hash=artifact.attestation_hash,
                        assurance_class=artifact.assurance_class,
                        evidence_kind=artifact.evidence_kind,
                        suite_id=artifact.suite_id,
                        suite_hash=artifact.suite_hash,
                        artifact=artifact.to_dict(),
                        created_at=accepted_at,
                    )
                )
            head = cast(RuntimeReportHead | None, holder["head"])
            if head is None:
                head = RuntimeReportHead(
                    identity_id=identity.id,
                    org_id=identity.org_id,
                    project_id=identity.project_id,
                    environment_id=identity.environment_id,
                    last_sequence=body.sequence,
                    latest_report_id=report.id,
                    latest_report_hash=report_hash,
                    latest_projection_commitment=projection_commitment,
                    history_count=body.sequence,
                    history_accumulator=cast(
                        str, request_projection["history_checkpoint"]["accumulator"]
                    ),
                    latest_wiring_kind="wiring" if artifact is not None else None,
                    latest_wiring_sequence=body.sequence if artifact is not None else None,
                    latest_wiring_report_id=report.id if artifact is not None else None,
                    latest_wiring_report_hash=report_hash if artifact is not None else None,
                    latest_wiring_projection_commitment=(
                        projection_commitment if artifact is not None else None
                    ),
                    updated_at=accepted_at,
                )
                session.add(head)
            else:
                head.last_sequence = body.sequence
                head.latest_report_id = report.id
                head.latest_report_hash = report_hash
                head.latest_projection_commitment = projection_commitment
                head.history_count = body.sequence
                head.history_accumulator = cast(
                    str, request_projection["history_checkpoint"]["accumulator"]
                )
                if artifact is not None:
                    head.latest_wiring_kind = "wiring"
                    head.latest_wiring_sequence = body.sequence
                    head.latest_wiring_report_id = report.id
                    head.latest_wiring_report_hash = report_hash
                    head.latest_wiring_projection_commitment = projection_commitment
                head.updated_at = accepted_at
            session.flush()
            return {"report_id": report.id, "accepted_at": _runtime_timestamp(accepted_at)}

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            response = RuntimeReportResponse(
                report_id=str(result.result["report_id"]),
                identity_id=identity_id,
                kind=body.kind,
                sequence=body.sequence,
                report_hash=report_hash,
                receipt_id=receipt_row.receipt_id,
                accepted_at=_parse_runtime_timestamp(str(result.result["accepted_at"])),
            )
            payload = response.model_dump(mode="json")
            try:
                sealed_payload = _sealed_terminal_response_payload(
                    payload,
                    receipt_sealer=self._runtime_service._providers.receipt_sealer,
                    org_id=receipt_row.org_id,
                    project_id=receipt_row.project_id,
                    environment_id=receipt_row.environment_id,
                    identity_id=identity_id,
                    action=CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
                    operation=REPORT_OPERATION,
                    request_hash=request_hash,
                    idempotency_key_hash=key_hash,
                    receipt_id=receipt_row.receipt_id,
                    receipt_hash=receipt_row.receipt_hash,
                )
            except RuntimeEnrollmentProviderUnavailable as exc:
                raise RuntimeReportProviderUnavailable from exc
            session.add(
                RuntimeOperationIdempotency(
                    id=new_id(),
                    idempotency_key_hash=key_hash,
                    request_hash=request_hash,
                    org_id=receipt_row.org_id,
                    project_id=receipt_row.project_id,
                    environment_id=receipt_row.environment_id,
                    identity_id=identity_id,
                    operation=REPORT_OPERATION,
                    receipt_id=receipt_row.receipt_id,
                    response=sealed_payload,
                )
            )
            nonce_row = session.scalars(
                sa.select(RuntimeRequestNonce).where(
                    RuntimeRequestNonce.org_id == receipt_row.org_id,
                    RuntimeRequestNonce.identity_id == identity_id,
                    RuntimeRequestNonce.nonce == auth.nonce,
                )
            ).one()
            nonce_row.receipt_id = receipt_row.receipt_id
            nonce_row.response = sealed_payload
            holder["response"] = response

        try:
            mutation_result = ManagedMutationUnitOfWork(
                self._session_factory,
                receipt_sealer=self._runtime_service._providers.receipt_sealer,
            ).execute(
                context=context,
                receipt=receipt,
                args=args,
                before_execute=None,
                before_attempt_reservation=before_attempt_reservation,
                operation_effect=operation_effect,
                after_success=after_success,
            )
            if isinstance(mutation_result, ManagedMutationReplayResult):
                return cast(RuntimeReportResponse, mutation_result.result)
        except IntegrityError as exc:
            constraint = _integrity_constraint_name(exc)
            if constraint == "uq_runtime_operation_idempotency_scope_operation_key":
                return self._replay_after_conflict(
                    identity_id=identity_id,
                    auth=auth,
                    body=body,
                    raw_body=raw_body,
                    path=path,
                    idempotency_key=idempotency_key,
                    key_hash=key_hash,
                    request_hash=request_hash,
                    expected_args=args,
                )
            if constraint in _EXPECTED_REPORT_CONFLICTS:
                try:
                    return self._replay_after_conflict(
                        identity_id=identity_id,
                        auth=auth,
                        body=body,
                        raw_body=raw_body,
                        path=path,
                        idempotency_key=idempotency_key,
                        key_hash=key_hash,
                        request_hash=request_hash,
                        expected_args=args,
                    )
                except RuntimeEnrollmentHttpError as replay_exc:
                    if replay_exc.code == "DATABASE_UNAVAILABLE":
                        raise _conflict("REPORT_REPLAYED") from exc
                    raise
            raise _database_unavailable() from exc
        except ReceiptValidationError as exc:
            raise RuntimeEnrollmentHttpError(
                409,
                "REPORT_REJECTED",
                "conflict",
                "runtime report acceptance was rejected",
            ) from exc
        except SQLAlchemyError as exc:
            raise _database_unavailable() from exc
        return cast(RuntimeReportResponse, holder["response"])

    def validate_stored_report_lineage(
        self,
        session: Session,
        *,
        report: RuntimeReport,
        identity: RuntimeIdentity,
        receipt: ManagedDecisionReceipt | None = None,
        preload: _FleetLineagePreload | None = None,
        current_trust_at: Any | None = None,
    ) -> None:
        if receipt is None:
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.org_id == report.org_id,
                    ManagedDecisionReceipt.project_id == report.project_id,
                    ManagedDecisionReceipt.environment_id == report.environment_id,
                    ManagedDecisionReceipt.receipt_id == report.receipt_id,
                )
            ).one_or_none()
        if receipt is None:
            raise ManagedReplayArtifactValidationError("runtime report receipt is missing")
        projection = report.request_projection
        if not isinstance(projection, dict):
            raise ManagedReplayArtifactValidationError("runtime report projection is invalid")
        expected_args = {
            "identity_id": projection.get("identity_id"),
            "kind": projection.get("kind"),
            "sequence": projection.get("sequence"),
            "challenge_expected_sequence": projection.get("challenge_expected_sequence"),
            "report_hash": projection.get("report_hash"),
            "policy_version_id": projection.get("policy_version_id"),
            "projection_commitment": report.projection_commitment,
        }
        try:
            _validate_anchored_report_lineage(
                session,
                report=report,
                identity=identity,
                receipt=receipt,
                expected_args=expected_args,
                receipt_sealer=self._runtime_service._providers.receipt_sealer,
                descriptor_signer=self._descriptor_signer,
                preload=preload,
                current_trust_at=current_trust_at,
            )
        except (
            ManagedReplayArtifactValidationError,
            PolicySyncError,
            ReceiptValidationError,
            RuntimeIdentityError,
            TrustConfigurationError,
            WiringAttestationError,
            ValueError,
            TypeError,
            KeyError,
        ) as exc:
            raise ManagedReplayArtifactValidationError(
                "stored runtime report lineage is invalid"
            ) from exc

    def validate_stored_report_lineages(
        self,
        session: Session,
        *,
        reports: list[tuple[RuntimeReport, RuntimeIdentity]],
        now: Any,
        reconcile_history: bool = False,
    ) -> dict[str, bool]:
        """Validate current projections with bounded reads, or reconcile full history.

        Fleet reads trust only receipt-authenticated current report projections and
        their exact durable terminal rows. Historical chain gaps are intentionally
        checked by ``reconcile_history=True`` rather than making request cost grow
        with retained history. Consequently, corruption confined to an unqueried old
        row is detected by reconciliation, not immediately by a fleet read. A database
        rollback also requires an independent external witness; this local checkpoint
        does not provide one.
        """
        unique = {report.id: (report, identity) for report, identity in reports}
        if not unique:
            return {}
        first_report = next(iter(unique.values()))[0]
        identity_ids = {identity.id for _report, identity in unique.values()}
        scope_filter = (
            first_report.org_id,
            first_report.project_id,
            first_report.environment_id,
        )
        org_id, project_id, environment_id = scope_filter
        heads_rows = tuple(
            session.scalars(
                sa.select(RuntimeReportHead).where(
                    RuntimeReportHead.org_id == org_id,
                    RuntimeReportHead.project_id == project_id,
                    RuntimeReportHead.environment_id == environment_id,
                    RuntimeReportHead.identity_id.in_(identity_ids),
                )
            )
        )
        selected_report_ids = set(unique)
        if reconcile_history:
            report_predicate = RuntimeReport.identity_id.in_(identity_ids)
        else:
            for head in heads_rows:
                selected_report_ids.add(head.latest_report_id)
                if head.latest_wiring_report_id is not None:
                    selected_report_ids.add(head.latest_wiring_report_id)
            report_predicate = RuntimeReport.id.in_(selected_report_ids)
        reports_rows = tuple(
            session.scalars(
                sa.select(RuntimeReport).where(
                    RuntimeReport.org_id == org_id,
                    RuntimeReport.project_id == project_id,
                    RuntimeReport.environment_id == environment_id,
                    report_predicate,
                )
            )
        )
        receipt_ids = {row.receipt_id for row in reports_rows}
        receipts_rows = tuple(
            session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.org_id == org_id,
                    ManagedDecisionReceipt.project_id == project_id,
                    ManagedDecisionReceipt.environment_id == environment_id,
                    ManagedDecisionReceipt.receipt_id.in_(receipt_ids),
                )
            )
        )
        receipt_row_ids = {row.id for row in receipts_rows}
        receipt_hashes = {row.receipt_hash for row in receipts_rows}
        report_ids = {row.id for row in reports_rows}
        event_heads_rows = tuple(
            session.scalars(
                sa.select(ManagedGovernanceEventHead).where(
                    ManagedGovernanceEventHead.org_id == org_id,
                    ManagedGovernanceEventHead.project_id == project_id,
                    ManagedGovernanceEventHead.environment_id == environment_id,
                )
            )
        )
        events_rows = tuple(
            session.scalars(
                sa.select(ManagedGovernanceEvent)
                .where(
                    ManagedGovernanceEvent.org_id == org_id,
                    ManagedGovernanceEvent.project_id == project_id,
                    ManagedGovernanceEvent.environment_id == environment_id,
                    (
                        sa.true()
                        if reconcile_history
                        else ManagedGovernanceEvent.managed_receipt_id.in_(receipt_row_ids)
                    ),
                )
                .order_by(ManagedGovernanceEvent.sequence)
            )
        )
        preload = _FleetLineagePreload(
            receipts=receipts_rows,
            managed=build_managed_replay_preload(
                trust_keys=tuple(
                    session.scalars(
                        sa.select(ManagedTrustKey).where(
                            ManagedTrustKey.org_id == org_id,
                            ManagedTrustKey.project_id == project_id,
                            ManagedTrustKey.environment_id == environment_id,
                        )
                    )
                ),
                events=events_rows,
                event_heads=event_heads_rows,
                outboxes=tuple(
                    session.scalars(
                        sa.select(ManagedOutboxMessage).where(
                            ManagedOutboxMessage.managed_receipt_id.in_(receipt_row_ids)
                        )
                    )
                ),
                consumptions=tuple(
                    session.scalars(
                        sa.select(ManagedReceiptConsumption).where(
                            ManagedReceiptConsumption.managed_receipt_id.in_(receipt_row_ids)
                        )
                    )
                ),
                attempts=tuple(
                    session.scalars(
                        sa.select(ManagedMutationAttempt).where(
                            ManagedMutationAttempt.receipt_hash.in_(receipt_hashes)
                        )
                    )
                ),
                bounded_current_projection=not reconcile_history,
            ),
            report_heads=heads_rows,
            reports=reports_rows,
            idempotencies=tuple(
                session.scalars(
                    sa.select(RuntimeOperationIdempotency).where(
                        RuntimeOperationIdempotency.org_id == org_id,
                        RuntimeOperationIdempotency.project_id == project_id,
                        RuntimeOperationIdempotency.environment_id == environment_id,
                        (
                            RuntimeOperationIdempotency.identity_id.in_(identity_ids)
                            if reconcile_history
                            else RuntimeOperationIdempotency.receipt_id.in_(receipt_ids)
                        ),
                    )
                )
            ),
            nonces=tuple(
                session.scalars(
                    sa.select(RuntimeRequestNonce).where(
                        RuntimeRequestNonce.org_id == org_id,
                        RuntimeRequestNonce.project_id == project_id,
                        RuntimeRequestNonce.environment_id == environment_id,
                        (
                            RuntimeRequestNonce.identity_id.in_(identity_ids)
                            if reconcile_history
                            else sa.or_(
                                RuntimeRequestNonce.receipt_id.in_(receipt_ids),
                                RuntimeRequestNonce.nonce.in_({row.nonce for row in reports_rows}),
                            )
                        ),
                    )
                )
            ),
            attestations=tuple(
                session.scalars(
                    sa.select(RuntimeWiringAttestation).where(
                        RuntimeWiringAttestation.report_id.in_(report_ids)
                    )
                )
            ),
            challenges=tuple(
                session.scalars(
                    sa.select(RuntimeWiringChallengeConsumption).where(
                        RuntimeWiringChallengeConsumption.report_id.in_(report_ids)
                    )
                )
            ),
        )
        results: dict[str, bool] = {}
        for report_id, (report, identity) in unique.items():
            receipt_matches = preload.receipts_by_id.get(report.receipt_id, ())
            if len(receipt_matches) != 1:
                results[report_id] = False
                continue
            try:
                self.validate_stored_report_lineage(
                    session,
                    report=report,
                    identity=identity,
                    receipt=receipt_matches[0],
                    preload=preload,
                    current_trust_at=now,
                )
            except ManagedReplayArtifactValidationError:
                results[report_id] = False
            else:
                results[report_id] = True
        return results

    def reconcile_stored_report_history(
        self,
        session: Session,
        *,
        identity: RuntimeIdentity,
        now: Any,
    ) -> bool:
        reports = list(
            session.scalars(
                sa.select(RuntimeReport).where(
                    RuntimeReport.org_id == identity.org_id,
                    RuntimeReport.project_id == identity.project_id,
                    RuntimeReport.environment_id == identity.environment_id,
                    RuntimeReport.identity_id == identity.id,
                )
            )
        )
        if not reports:
            return False
        results = self.validate_stored_report_lineages(
            session,
            reports=[(report, identity) for report in reports],
            now=now,
            reconcile_history=True,
        )
        if len(results) != len(reports) or not all(results.values()):
            return False
        previous = REPORT_HISTORY_GENESIS
        for expected_count, report in enumerate(sorted(reports, key=lambda row: row.sequence), 1):
            checkpoint = report.request_projection.get("history_checkpoint")
            if not _valid_history_checkpoint(
                checkpoint,
                previous_accumulator=previous,
                expected_count=expected_count,
                report=report,
            ):
                return False
            previous = cast(dict[str, Any], checkpoint)["accumulator"]
        return True

    def validate_current_identity_binding(
        self,
        *,
        identity: RuntimeIdentity,
        credential: RuntimeCredentialGeneration,
        now: Any,
    ) -> None:
        try:
            validate_current_runtime_identity_binding(
                identity,
                credential,
                descriptor_signer=self._descriptor_signer,
                now=_to_utc(now),
            )
        except RuntimeIdentityProviderUnavailable as exc:
            raise RuntimeReportProviderUnavailable from exc
        except RuntimeIdentityError as exc:
            raise ManagedReplayArtifactValidationError(
                "current runtime identity binding is invalid"
            ) from exc

    def _replay_after_conflict(
        self,
        *,
        identity_id: str,
        auth: RuntimeReportAuth,
        body: RuntimeReportRequest,
        raw_body: bytes,
        path: str,
        idempotency_key: str,
        key_hash: str,
        request_hash: str,
        expected_args: dict[str, Any],
    ) -> RuntimeReportResponse:
        with self._session_factory.begin() as session:
            identity, credential, _gate = _authenticate_runtime_request(
                session,
                descriptor_signer=self._descriptor_signer,
                identity_id=identity_id,
                auth=auth,
                method="POST",
                path=path,
                body=raw_body,
                idempotency_key=idempotency_key,
                lock=True,
            )
            _, policy_version_id, policy_hash, _, policy_generation = _active_policy_context(
                session,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
            )
            _require_current_binding(
                body=body,
                credential=credential,
                policy_version_id=policy_version_id,
                policy_hash=policy_hash,
                policy_generation=policy_generation,
            )
            existing = _idempotency(session, identity=identity, key_hash=key_hash, lock=True)
            if existing is None:
                raise _database_unavailable()
            if existing.request_hash != request_hash:
                raise _conflict("IDEMPOTENCY_CONFLICT")
            return _replay_report_operation(
                session,
                existing=existing,
                identity=identity,
                credential=credential,
                body=body,
                auth=auth,
                expected_args=expected_args,
                receipt_sealer=self._runtime_service._providers.receipt_sealer,
                descriptor_signer=self._descriptor_signer,
            )

    def _verify_challenge(
        self,
        token: str,
        *,
        identity: RuntimeIdentity,
        credential: RuntimeCredentialGeneration,
        gate: RuntimeIdentityGate,
        body: RuntimeReportRequest,
        now: Any | None = None,
    ) -> tuple[str, int]:
        try:
            encoded, supplied = token.split(".", 1)
            if not verify_ed25519(
                _provider_public_key_bytes(self._descriptor_signer),
                CHALLENGE_TOKEN_SIGNATURE_DOMAIN + encoded.encode("ascii"),
                supplied,
            ):
                raise ValueError
            payload = json.loads(_b64url_decode(encoded))
            expected_keys = {
                "schema",
                "org_id",
                "project_id",
                "environment_id",
                "gate_id",
                "identity_id",
                "credential_id",
                "credential_generation",
                "workload_key_id",
                "public_key_thumbprint",
                "policy_version_id",
                "policy_content_hash",
                "policy_head_generation",
                "expected_sequence",
                "challenge_signing_key_id",
                "runtime_build_digest",
                "configuration_digest",
                "policy_snapshot_hash",
                "request_timestamp",
                "request_nonce",
                "nonce",
                "issued_at",
                "expires_at",
            }
            if not isinstance(payload, dict) or set(payload) != expected_keys:
                raise ValueError
            expected = {
                "schema": "acgs.runtime-attestation-challenge/v1",
                "org_id": identity.org_id,
                "project_id": identity.project_id,
                "environment_id": identity.environment_id,
                "gate_id": gate.id,
                "identity_id": identity.id,
                "credential_id": credential.id,
                "credential_generation": credential.generation,
                "workload_key_id": credential.workload_key_id,
                "public_key_thumbprint": credential.public_key_thumbprint,
                "policy_version_id": body.policy_version_id,
                "policy_content_hash": body.policy_content_hash,
                "policy_head_generation": body.policy_head_generation,
                "expected_sequence": body.sequence,
                "challenge_signing_key_id": self._descriptor_signer.key_id,
                "runtime_build_digest": body.runtime_build_digest,
                "configuration_digest": body.configuration_digest,
                "policy_snapshot_hash": hashlib.sha256(
                    _canonical_bytes(cast(dict[str, Any], body.policy_snapshot))
                ).hexdigest(),
            }
            verification_time = utcnow() if now is None else _to_utc(now)
            issued_at = _parse_runtime_timestamp(payload["issued_at"])
            expires_at = _parse_runtime_timestamp(payload["expires_at"])
            binding_changed = any(payload[key] != value for key, value in expected.items())
            if (
                binding_changed
                or issued_at > verification_time
                or expires_at - issued_at != timedelta(seconds=CHALLENGE_TTL_SECONDS)
                or verification_time >= expires_at
            ):
                raise ValueError
            nonce = payload["nonce"]
            expected_sequence = payload["expected_sequence"]
            if (
                not isinstance(nonce, str)
                or not nonce.startswith("attest-")
                or type(expected_sequence) is not int
                or not 1 <= expected_sequence <= IJSON_MAX_SAFE_INTEGER
            ):
                raise ValueError
            return nonce, expected_sequence
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ReceiptValidationError("attestation challenge is invalid or expired") from exc


def _verified_policy_provenance(
    session: Session,
    *,
    body: RuntimeReportRequest,
    descriptor: RuntimeIdentityDescriptor,
    now: Any,
    historical_trust_verification: bool = False,
    preloaded_trust_keys: tuple[ManagedTrustKey, ...] | None = None,
    preloaded_trust_index: Mapping[tuple[str, str, str, str], tuple[ManagedTrustKey, ...]]
    | None = None,
    verification_now: Any | None = None,
) -> tuple[PolicySyncSnapshot, ManagedPolicyProvenance]:
    try:
        snapshot = PolicySyncSnapshot.from_dict(cast(dict[str, Any], body.policy_snapshot))
        registry = SqlReceiptTrustRegistry(
            session,
            lock_rows=preloaded_trust_keys is None,
            preloaded_rows=preloaded_trust_keys,
            preloaded_index=preloaded_trust_index,
        )
        verify_policy_sync_snapshot(
            snapshot,
            descriptor=descriptor,
            trust_registry=registry,
            now=now,
            historical_trust_verification=historical_trust_verification,
        )
        if verification_now is not None:
            verify_policy_sync_snapshot(
                snapshot,
                descriptor=descriptor,
                trust_registry=SqlReceiptTrustRegistry(
                    session,
                    preloaded_rows=preloaded_trust_keys,
                    preloaded_index=preloaded_trust_index,
                ),
                now=_to_utc(verification_now),
                historical_trust_verification=False,
            )
        if (
            snapshot.policy_version_id != body.policy_version_id
            or snapshot.head_generation != body.policy_head_generation
            or snapshot.content_hash != body.policy_content_hash
            or snapshot.credential_id != descriptor.credential_id
            or snapshot.credential_generation != descriptor.credential_generation
        ):
            raise ValueError("signed policy snapshot is not the current report binding")
        policy_key = registry.resolve(
            scope=ReceiptTrustScope(
                snapshot.scope.org_id,
                snapshot.scope.project_id,
                snapshot.scope.environment_id,
                POLICY_ENVELOPE_PURPOSE,
            ),
            trust_epoch=cast(int, snapshot.policy_envelope["trust_epoch"]),
            algorithm=cast(str, snapshot.policy_envelope["signature_algorithm"]),
            key_id=cast(str, snapshot.policy_envelope["key_id"]),
            now_iso=_runtime_timestamp(now),
            mode="historical" if historical_trust_verification else "execution",
        )
        attestation_key = registry.resolve(
            scope=ReceiptTrustScope(
                snapshot.scope.org_id,
                snapshot.scope.project_id,
                snapshot.scope.environment_id,
                POLICY_SYNC_ATTESTATION_PURPOSE,
            ),
            trust_epoch=snapshot.attestation_trust_epoch,
            algorithm=snapshot.attestation_signature_algorithm,
            key_id=snapshot.attestation_key_id,
            now_iso=_runtime_timestamp(now),
            mode="historical" if historical_trust_verification else "execution",
        )
        provenance = ManagedPolicyProvenance.from_snapshot(
            snapshot,
            policy_key_fingerprint=policy_key.public_key_fingerprint,
            attestation_key_fingerprint=attestation_key.public_key_fingerprint,
        )
        return snapshot, provenance
    except (PolicySyncError, RuntimeIdentityError, TrustConfigurationError) as exc:
        raise ReceiptValidationError("signed current policy snapshot verification failed") from exc


def _runtime_report_projection(
    *,
    report_id: str,
    identity: RuntimeIdentity,
    credential: RuntimeCredentialGeneration,
    gate: RuntimeIdentityGate,
    body: RuntimeReportRequest,
    auth: RuntimeReportAuth,
    report_hash: str,
    snapshot: PolicySyncSnapshot,
    provenance: ManagedPolicyProvenance,
    accepted_at: Any,
    challenge_nonce: str | None,
    challenge_expected_sequence: int | None,
    history_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    observed_at = _runtime_timestamp(_to_utc(accepted_at))
    return {
        "schema": "acgs.runtime-report-projection/v1",
        "report_id": report_id,
        "org_id": identity.org_id,
        "project_id": identity.project_id,
        "environment_id": identity.environment_id,
        "gate_id": gate.id,
        "actor": identity.actor,
        "identity_id": identity.id,
        "credential_id": credential.id,
        "credential_generation": credential.generation,
        "workload_key_id": credential.workload_key_id,
        "public_key_thumbprint": credential.public_key_thumbprint,
        "runtime_identity_descriptor": identity.descriptor,
        "policy_version_id": body.policy_version_id,
        "policy_head_generation": body.policy_head_generation,
        "policy_content_hash": body.policy_content_hash,
        "runtime_build_digest": body.runtime_build_digest,
        "configuration_digest": body.configuration_digest,
        "policy_snapshot": body.policy_snapshot,
        "policy_snapshot_hash": sha256_bytes(_canonical_bytes(body.policy_snapshot)),
        "policy_provenance": provenance.to_dict(),
        "policy_provenance_hash": provenance.compute_hash(),
        "policy_issued_at": snapshot.issued_at,
        "policy_revocation_checked_at": snapshot.revocation_checked_at,
        "policy_fresh_until": snapshot.fresh_until,
        "policy_expires_at": snapshot.expires_at,
        "kind": body.kind,
        "sequence": body.sequence,
        "request_nonce": auth.nonce,
        "request_timestamp": auth.timestamp,
        "request_body_sha256": auth.body_sha256,
        "request_signature": auth.signature,
        "report_hash": report_hash,
        "challenge_token_hash": (
            sha256_bytes(cast(str, body.challenge_token).encode("utf-8"))
            if body.challenge_token is not None
            else None
        ),
        "challenge_nonce": challenge_nonce,
        "challenge_expected_sequence": challenge_expected_sequence,
        "history_checkpoint": history_checkpoint,
        "artifact": body.artifact,
        "observed_at": observed_at,
        "expires_at": _runtime_timestamp(_to_utc(body.expires_at)),
        "created_at": observed_at,
    }


def _next_history_checkpoint(
    session: Session,
    *,
    identity: RuntimeIdentity,
    report_id: str,
    report_hash: str,
    kind: str,
    sequence: int,
) -> dict[str, Any]:
    head = session.scalars(
        sa.select(RuntimeReportHead).where(
            RuntimeReportHead.org_id == identity.org_id,
            RuntimeReportHead.project_id == identity.project_id,
            RuntimeReportHead.environment_id == identity.environment_id,
            RuntimeReportHead.identity_id == identity.id,
        )
    ).one_or_none()
    return _next_history_checkpoint_from_head(
        head,
        report_id=report_id,
        report_hash=report_hash,
        kind=kind,
        sequence=sequence,
    )


def _next_history_checkpoint_from_head(
    head: RuntimeReportHead | None,
    *,
    report_id: str,
    report_hash: str,
    kind: str,
    sequence: int,
) -> dict[str, Any]:
    previous = REPORT_HISTORY_GENESIS if head is None else head.history_accumulator
    previous_count = 0 if head is None else head.history_count
    if sequence != previous_count + 1:
        raise ReceiptValidationError("runtime report history checkpoint sequence mismatch")
    wiring_sequence = (
        sequence if kind == "wiring" else getattr(head, "latest_wiring_sequence", None)
    )
    wiring_report_id = (
        report_id if kind == "wiring" else getattr(head, "latest_wiring_report_id", None)
    )
    wiring_report_hash = (
        report_hash if kind == "wiring" else getattr(head, "latest_wiring_report_hash", None)
    )
    unsigned = {
        "schema": "acgs.runtime-report-history-checkpoint/v1",
        "previous_accumulator": previous,
        "count": sequence,
        "report_id": report_id,
        "report_hash": report_hash,
        "latest_wiring_sequence": wiring_sequence,
        "latest_wiring_report_id": wiring_report_id,
        "latest_wiring_report_hash": wiring_report_hash,
    }
    return {**unsigned, "accumulator": sha256_json(unsigned)}


def _authenticate_runtime_request(
    session: Session,
    *,
    descriptor_signer: Any,
    identity_id: str,
    auth: RuntimeReportAuth,
    method: str,
    path: str,
    body: bytes,
    idempotency_key: str | None,
    query: str = "",
    lock: bool = False,
) -> tuple[RuntimeIdentity, RuntimeCredentialGeneration, RuntimeIdentityGate]:
    if auth.body_sha256 != sha256_bytes(body) or auth.audience != RUNTIME_ENROLLMENT_AUTHORITY:
        raise _authentication_refused()
    stmt = sa.select(RuntimeIdentity).where(RuntimeIdentity.id == identity_id)
    if lock:
        stmt = stmt.with_for_update()
    identity = session.scalars(stmt).one_or_none()
    if identity is None or identity.status != "active" or identity.workload_key_id != auth.key_id:
        raise _authentication_refused()
    credential_stmt = sa.select(RuntimeCredentialGeneration).where(
        RuntimeCredentialGeneration.org_id == identity.org_id,
        RuntimeCredentialGeneration.project_id == identity.project_id,
        RuntimeCredentialGeneration.environment_id == identity.environment_id,
        RuntimeCredentialGeneration.identity_id == identity.id,
        RuntimeCredentialGeneration.id == auth.credential_id,
        RuntimeCredentialGeneration.generation == auth.credential_generation,
    )
    if lock:
        credential_stmt = credential_stmt.with_for_update()
    credential = session.scalars(credential_stmt).one_or_none()
    if credential is None:
        raise _authentication_refused()
    now = utcnow()
    try:
        validate_current_runtime_identity_binding(
            identity,
            credential,
            descriptor_signer=descriptor_signer,
            now=now,
        )
    except RuntimeIdentityProviderUnavailable as exc:
        raise RuntimeReportProviderUnavailable from exc
    except RuntimeIdentityError as exc:
        raise _authentication_refused() from exc
    try:
        verify_signed_runtime_request(
            public_key=_runtime_public_key_bytes(identity.public_key),
            signature=auth.signature,
            method=method,
            path=path,
            query=query,
            body=body,
            timestamp=auth.timestamp,
            nonce=auth.nonce,
            key_id=auth.key_id,
            identity_id=identity.id,
            credential_id=auth.credential_id,
            credential_generation=auth.credential_generation,
            idempotency_key=idempotency_key,
            audience=auth.audience,
        )
    except RuntimeIdentityError as exc:
        raise _authentication_refused() from exc
    if abs((_parse_runtime_timestamp(auth.timestamp) - utcnow()).total_seconds()) > (
        RUNTIME_SIGNED_REQUEST_SKEW_SECONDS
    ):
        raise _authentication_refused()
    if lock:
        gate = session.scalars(
            sa.select(RuntimeIdentityGate)
            .where(
                RuntimeIdentityGate.org_id == identity.org_id,
                RuntimeIdentityGate.project_id == identity.project_id,
                RuntimeIdentityGate.environment_id == identity.environment_id,
                RuntimeIdentityGate.id == identity.gate_id,
            )
            .with_for_update()
        ).one_or_none()
        if gate is None or gate.status != "active":
            raise _authentication_refused()
    else:
        gate = _active_gate(session, identity=identity)
    return identity, credential, gate


def _require_current_binding(
    *,
    body: RuntimeReportRequest,
    credential: RuntimeCredentialGeneration,
    policy_version_id: str,
    policy_hash: str,
    policy_generation: int,
) -> None:
    if (
        body.policy_version_id != policy_version_id
        or body.policy_content_hash != policy_hash
        or body.policy_head_generation != policy_generation
        or credential.status != "active"
    ):
        raise RuntimeEnrollmentHttpError(
            409, "STALE_POLICY_BINDING", "conflict", "runtime report policy binding is stale"
        )


def _idempotency(
    session: Session, *, identity: RuntimeIdentity, key_hash: str, lock: bool = False
) -> RuntimeOperationIdempotency | None:
    stmt = sa.select(RuntimeOperationIdempotency).where(
        RuntimeOperationIdempotency.org_id == identity.org_id,
        RuntimeOperationIdempotency.project_id == identity.project_id,
        RuntimeOperationIdempotency.environment_id == identity.environment_id,
        RuntimeOperationIdempotency.identity_id == identity.id,
        RuntimeOperationIdempotency.operation == REPORT_OPERATION,
        RuntimeOperationIdempotency.idempotency_key_hash == key_hash,
    )
    if lock:
        stmt = stmt.with_for_update()
    return session.scalars(stmt).one_or_none()


def _replay_report_operation(
    session: Session,
    *,
    existing: RuntimeOperationIdempotency,
    identity: RuntimeIdentity,
    credential: RuntimeCredentialGeneration,
    body: RuntimeReportRequest,
    auth: RuntimeReportAuth,
    expected_args: dict[str, Any],
    receipt_sealer: Any,
    descriptor_signer: Any,
) -> RuntimeReportResponse:
    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt).where(
            ManagedDecisionReceipt.org_id == existing.org_id,
            ManagedDecisionReceipt.project_id == existing.project_id,
            ManagedDecisionReceipt.environment_id == existing.environment_id,
            ManagedDecisionReceipt.receipt_id == existing.receipt_id,
        )
    ).one_or_none()
    if receipt is None:
        raise _terminal_tampered()
    try:
        terminal_payload = _verified_stored_terminal_payload(
            existing.response,
            receipt_sealer=receipt_sealer,
            org_id=existing.org_id,
            project_id=existing.project_id,
            environment_id=existing.environment_id,
            identity_id=existing.identity_id,
            action=CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
            operation=REPORT_OPERATION,
            request_hash=existing.request_hash,
            idempotency_key_hash=existing.idempotency_key_hash,
            receipt_id=existing.receipt_id,
            receipt_hash=receipt.receipt_hash,
        )
    except RuntimeEnrollmentProviderUnavailable as exc:
        raise RuntimeReportProviderUnavailable from exc
    try:
        if receipt.decision in {Decision.DENY.value, Decision.ESCALATE.value}:
            artifacts = validate_managed_replay_artifacts(
                session,
                receipt,
                expected_action=CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
                expected_actor=identity.actor,
                expected_decision=receipt.decision,
                expected_args=expected_args,
                expected_result_hash=safe_result_hash(
                    {"status": "non_executable", "decision": receipt.decision}
                ),
                receipt_sealer=receipt_sealer,
            )
            canonical_error = _non_executable_error_for_receipt(artifacts.sealed_receipt)
            canonical_payload = _refusal_payload(canonical_error)
            canonical_payload["receipt_id"] = receipt.receipt_id
            if terminal_payload != canonical_payload:
                raise ManagedReplayArtifactValidationError("runtime report refusal mismatch")
            _validate_non_executable_report_lineage(session, existing=existing)
            raise canonical_error
        response = RuntimeReportResponse.model_validate(terminal_payload)
        report = session.scalars(
            sa.select(RuntimeReport).where(
                RuntimeReport.org_id == existing.org_id,
                RuntimeReport.project_id == existing.project_id,
                RuntimeReport.environment_id == existing.environment_id,
                RuntimeReport.identity_id == existing.identity_id,
                RuntimeReport.id == response.report_id,
                RuntimeReport.receipt_id == existing.receipt_id,
            )
        ).one_or_none()
        if report is None:
            raise ManagedReplayArtifactValidationError("runtime report row is missing")
        anchored_args = {
            **expected_args,
            "projection_commitment": report.projection_commitment,
        }
        if (
            response.identity_id != identity.id
            or response.kind != body.kind
            or response.sequence != body.sequence
            or response.report_hash != report.report_hash
            or response.receipt_id != receipt.receipt_id
            or _to_utc(response.accepted_at) != _to_utc(report.observed_at)
            or report.actor != identity.actor
            or report.credential_id != credential.id
            or report.credential_generation != credential.generation
            or report.kind != body.kind
            or report.sequence != body.sequence
            or report.nonce != auth.nonce
            or report.request_signature != auth.signature
            or report.policy_version_id != body.policy_version_id
            or report.policy_head_generation != body.policy_head_generation
            or report.policy_content_hash != body.policy_content_hash
            or report.runtime_build_digest != body.runtime_build_digest
            or report.configuration_digest != body.configuration_digest
        ):
            raise ManagedReplayArtifactValidationError("runtime report lineage is invalid")
        validate_managed_replay_artifacts(
            session,
            receipt,
            expected_action=CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
            expected_actor=identity.actor,
            expected_decision=Decision.ALLOW.value,
            expected_args=anchored_args,
            expected_result_hash=safe_result_hash(
                {
                    "report_id": report.id,
                    "accepted_at": _runtime_timestamp(_to_utc(report.observed_at)),
                }
            ),
            receipt_sealer=receipt_sealer,
        )
        nonce_rows = list(
            session.scalars(
                sa.select(RuntimeRequestNonce).where(
                    RuntimeRequestNonce.org_id == report.org_id,
                    RuntimeRequestNonce.project_id == report.project_id,
                    RuntimeRequestNonce.environment_id == report.environment_id,
                    RuntimeRequestNonce.identity_id == report.identity_id,
                    RuntimeRequestNonce.nonce == report.nonce,
                    RuntimeRequestNonce.purpose == REPORT_PURPOSE,
                )
            )
        )
        if (
            len(nonce_rows) != 1
            or nonce_rows[0].receipt_id != receipt.receipt_id
            or nonce_rows[0].request_hash != existing.request_hash
            or nonce_rows[0].idempotency_key_hash != existing.idempotency_key_hash
            or nonce_rows[0].response != existing.response
        ):
            raise ManagedReplayArtifactValidationError("runtime report nonce lineage is invalid")
        attestations = list(
            session.scalars(
                sa.select(RuntimeWiringAttestation).where(
                    RuntimeWiringAttestation.org_id == report.org_id,
                    RuntimeWiringAttestation.project_id == report.project_id,
                    RuntimeWiringAttestation.environment_id == report.environment_id,
                    RuntimeWiringAttestation.identity_id == report.identity_id,
                    RuntimeWiringAttestation.report_id == report.id,
                )
            )
        )
        if report.kind == "status" and attestations:
            raise ManagedReplayArtifactValidationError("status report has wiring lineage")
        if report.kind == "wiring":
            if len(attestations) != 1:
                raise ManagedReplayArtifactValidationError("wiring report attestation is missing")
            _validate_attestation_projection(
                attestations[0], report=report, projection=report.request_projection
            )
        _validate_anchored_report_lineage(
            session,
            report=report,
            identity=identity,
            receipt=receipt,
            expected_args=anchored_args,
            body=body,
            auth=auth,
            receipt_sealer=receipt_sealer,
            descriptor_signer=descriptor_signer,
            historical_trust_verification=True,
        )
        return response
    except RuntimeEnrollmentHttpError:
        raise
    except (
        ManagedReplayArtifactValidationError,
        WiringAttestationError,
        ValueError,
        TypeError,
    ) as exc:
        raise _terminal_tampered() from exc


def _validate_anchored_report_lineage(
    session: Session,
    *,
    report: RuntimeReport,
    identity: RuntimeIdentity,
    receipt: ManagedDecisionReceipt,
    expected_args: dict[str, Any],
    receipt_sealer: Any,
    descriptor_signer: Any,
    body: RuntimeReportRequest | None = None,
    auth: RuntimeReportAuth | None = None,
    historical_trust_verification: bool = False,
    preload: _FleetLineagePreload | None = None,
    current_trust_at: Any | None = None,
) -> None:
    projection = report.request_projection
    if not isinstance(projection, dict) or sha256_json(projection) != report.projection_commitment:
        raise ManagedReplayArtifactValidationError("runtime report projection commitment mismatch")
    if expected_args.get("projection_commitment") != report.projection_commitment:
        raise ManagedReplayArtifactValidationError("runtime report receipt commitment mismatch")
    _validate_report_row_against_projection(report, projection)
    if body is not None:
        if hashlib.sha256(_canonical_bytes(body.model_dump(mode="json"))).hexdigest() != (
            projection.get("report_hash")
        ):
            raise ManagedReplayArtifactValidationError("runtime report request body mismatch")
        if projection.get("artifact") != body.artifact or projection.get(
            "challenge_token_hash"
        ) != (
            sha256_bytes(cast(str, body.challenge_token).encode("utf-8"))
            if body.challenge_token is not None
            else None
        ):
            raise ManagedReplayArtifactValidationError("runtime report request evidence mismatch")
    if auth is not None and (
        projection.get("request_nonce") != auth.nonce
        or projection.get("request_timestamp") != auth.timestamp
        or projection.get("request_body_sha256") != auth.body_sha256
        or projection.get("request_signature") != auth.signature
    ):
        raise ManagedReplayArtifactValidationError("runtime report request signature mismatch")

    validate_managed_replay_artifacts(
        session,
        receipt,
        expected_action=CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
        expected_actor=identity.actor,
        expected_decision=Decision.ALLOW.value,
        expected_args=expected_args,
        expected_result_hash=safe_result_hash(
            {
                "report_id": report.id,
                "accepted_at": _runtime_timestamp(_to_utc(report.observed_at)),
            }
        ),
        receipt_sealer=receipt_sealer,
        historical_trust_verification=historical_trust_verification,
        preload=preload.managed if preload is not None else None,
        current_trust_at=(
            _runtime_timestamp(_to_utc(current_trust_at)) if current_trust_at is not None else None
        ),
    )
    head = _validate_current_report_head(session, identity=identity, preload=preload)
    if report.sequence > head.last_sequence:
        raise ManagedReplayArtifactValidationError("runtime report is beyond the current head")

    descriptor = RuntimeIdentityDescriptor.from_dict(
        cast(dict[str, Any], projection["runtime_identity_descriptor"])
    )
    projected_body = RuntimeReportRequest.model_validate(
        {
            "kind": projection["kind"],
            "sequence": projection["sequence"],
            "expires_at": projection["expires_at"],
            "policy_version_id": projection["policy_version_id"],
            "policy_head_generation": projection["policy_head_generation"],
            "policy_content_hash": projection["policy_content_hash"],
            "runtime_build_digest": projection["runtime_build_digest"],
            "configuration_digest": projection["configuration_digest"],
            "policy_snapshot": projection["policy_snapshot"],
            "artifact": projection["artifact"],
        }
    )
    snapshot, provenance = _verified_policy_provenance(
        session,
        body=projected_body,
        descriptor=descriptor,
        now=_to_utc(report.observed_at),
        historical_trust_verification=historical_trust_verification,
        preloaded_trust_keys=(preload.managed.trust_keys if preload is not None else None),
        preloaded_trust_index=(
            preload.managed.trust_keys_by_scope_purpose if preload is not None else None
        ),
        verification_now=current_trust_at,
    )
    if (
        provenance.to_dict() != projection["policy_provenance"]
        or provenance.compute_hash() != report.policy_provenance_hash
    ):
        raise ManagedReplayArtifactValidationError("runtime report policy provenance mismatch")
    attestations = (
        preload.attestations_by_report.get(report.id, ())
        if preload is not None
        else list(
            session.scalars(
                sa.select(RuntimeWiringAttestation).where(
                    RuntimeWiringAttestation.org_id == report.org_id,
                    RuntimeWiringAttestation.project_id == report.project_id,
                    RuntimeWiringAttestation.environment_id == report.environment_id,
                    RuntimeWiringAttestation.identity_id == report.identity_id,
                    RuntimeWiringAttestation.report_id == report.id,
                )
            )
        )
    )
    challenges = (
        preload.challenges_by_report.get(report.id, ())
        if preload is not None
        else list(
            session.scalars(
                sa.select(RuntimeWiringChallengeConsumption).where(
                    RuntimeWiringChallengeConsumption.org_id == report.org_id,
                    RuntimeWiringChallengeConsumption.project_id == report.project_id,
                    RuntimeWiringChallengeConsumption.environment_id == report.environment_id,
                    RuntimeWiringChallengeConsumption.identity_id == report.identity_id,
                    RuntimeWiringChallengeConsumption.report_id == report.id,
                )
            )
        )
    )
    idempotency_rows = (
        tuple(
            row
            for row in preload.idempotencies_by_receipt.get(
                (report.identity_id, receipt.receipt_id), ()
            )
            if row.operation == REPORT_OPERATION
        )
        if preload is not None
        else list(
            session.scalars(
                sa.select(RuntimeOperationIdempotency).where(
                    RuntimeOperationIdempotency.org_id == report.org_id,
                    RuntimeOperationIdempotency.project_id == report.project_id,
                    RuntimeOperationIdempotency.environment_id == report.environment_id,
                    RuntimeOperationIdempotency.identity_id == report.identity_id,
                    RuntimeOperationIdempotency.operation == REPORT_OPERATION,
                    RuntimeOperationIdempotency.receipt_id == receipt.receipt_id,
                )
            )
        )
    )
    nonce_rows = (
        preload.nonces_by_identity_nonce.get((report.identity_id, report.nonce), ())
        if preload is not None
        else list(
            session.scalars(
                sa.select(RuntimeRequestNonce).where(
                    RuntimeRequestNonce.org_id == report.org_id,
                    RuntimeRequestNonce.project_id == report.project_id,
                    RuntimeRequestNonce.environment_id == report.environment_id,
                    RuntimeRequestNonce.identity_id == report.identity_id,
                    RuntimeRequestNonce.nonce == report.nonce,
                )
            )
        )
    )
    if len(idempotency_rows) != 1 or len(nonce_rows) != 1:
        raise ManagedReplayArtifactValidationError("runtime report terminal lineage is incomplete")
    idempotency = idempotency_rows[0]
    nonce = nonce_rows[0]
    if (
        nonce.purpose != REPORT_PURPOSE
        or nonce.receipt_id != receipt.receipt_id
        or nonce.request_hash != idempotency.request_hash
        or nonce.idempotency_key_hash != idempotency.idempotency_key_hash
        or nonce.response != idempotency.response
        or projection.get("request_nonce") != nonce.nonce
    ):
        raise ManagedReplayArtifactValidationError("runtime report terminal lineage is invalid")
    try:
        terminal = _verified_stored_terminal_payload(
            idempotency.response,
            receipt_sealer=receipt_sealer,
            org_id=report.org_id,
            project_id=report.project_id,
            environment_id=report.environment_id,
            identity_id=report.identity_id,
            action=CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
            operation=REPORT_OPERATION,
            request_hash=idempotency.request_hash,
            idempotency_key_hash=idempotency.idempotency_key_hash,
            receipt_id=receipt.receipt_id,
            receipt_hash=receipt.receipt_hash,
        )
    except RuntimeEnrollmentProviderUnavailable as exc:
        raise RuntimeReportProviderUnavailable from exc
    except RuntimeEnrollmentHttpError as exc:
        raise ManagedReplayArtifactValidationError(
            "runtime report terminal response seal is invalid"
        ) from exc
    if (
        terminal.get("report_id") != report.id
        or terminal.get("identity_id") != report.identity_id
        or terminal.get("kind") != report.kind
        or terminal.get("sequence") != report.sequence
        or terminal.get("report_hash") != report.report_hash
        or terminal.get("receipt_id") != receipt.receipt_id
        or terminal.get("accepted_at") != _runtime_timestamp(_to_utc(report.observed_at))
    ):
        raise ManagedReplayArtifactValidationError("runtime report terminal response is invalid")
    if report.kind == "status":
        if attestations or challenges:
            raise ManagedReplayArtifactValidationError("status report has wiring lineage")
        return
    if len(attestations) != 1 or len(challenges) != 1:
        raise ManagedReplayArtifactValidationError("wiring report lineage is incomplete")
    challenge = challenges[0]
    if (
        len(idempotency_rows) != 1
        or challenge.receipt_id != receipt.receipt_id
        or challenge.credential_id != report.credential_id
        or challenge.credential_generation != report.credential_generation
        or challenge.sequence != report.sequence
        or challenge.expected_sequence != report.sequence
        or challenge.expected_sequence != projection["challenge_expected_sequence"]
        or challenge.challenge_nonce != projection["challenge_nonce"]
        or challenge.request_hash != idempotency_rows[0].request_hash
        or challenge.idempotency_key_hash != idempotency_rows[0].idempotency_key_hash
        or challenge.projection_commitment != report.projection_commitment
    ):
        raise ManagedReplayArtifactValidationError("wiring challenge lineage is invalid")
    artifact = _validate_attestation_projection(
        attestations[0], report=report, projection=projection
    )
    verify_wiring_attestation(
        artifact,
        expected=ExpectedWiringContext(
            scope=descriptor.scope,
            runtime_identity_descriptor=descriptor,
            runtime_identity_issuer_public_key=_provider_public_key_bytes(descriptor_signer),
            runtime_identity_audience=RUNTIME_ENROLLMENT_AUTHORITY,
            receipt_trust_registry=SqlReceiptTrustRegistry(
                session,
                lock_rows=preload is None,
                historical_trust_verification=(
                    historical_trust_verification and current_trust_at is None
                ),
                preloaded_rows=preload.managed.trust_keys if preload is not None else None,
                preloaded_index=(
                    preload.managed.trust_keys_by_scope_purpose if preload is not None else None
                ),
            ),
            receipt_trust_purpose=DECISION_RECEIPT_PURPOSE,
            workload_key_id=report.workload_key_id,
            execution_boundary=report.gate_id,
            runtime_build_digest=report.runtime_build_digest,
            configuration_digest=report.configuration_digest,
            policy_head=provenance.to_dict(),
            policy_provenance_hash=provenance.compute_hash(),
            policy_issued_at=snapshot.issued_at,
            policy_fresh_until=snapshot.fresh_until,
            policy_expires_at=snapshot.expires_at,
            policy_mode="fresh",
            expected_nonce=challenge.challenge_nonce,
            minimum_sequence=report.sequence - 1,
            now=_to_utc(current_trust_at or report.observed_at),
            replay_guard=_RevalidationAttestationReplayGuard(
                expected_nonce=challenge.challenge_nonce,
                expected_sequence=challenge.expected_sequence,
                namespace_digest=challenge.namespace_digest,
            ),
        ),
    )


def _locked_expected_report_sequence(session: Session, *, identity: RuntimeIdentity) -> int:
    head = session.scalars(
        sa.select(RuntimeReportHead)
        .where(
            RuntimeReportHead.org_id == identity.org_id,
            RuntimeReportHead.project_id == identity.project_id,
            RuntimeReportHead.environment_id == identity.environment_id,
            RuntimeReportHead.identity_id == identity.id,
        )
        .with_for_update()
    ).one_or_none()
    if head is not None:
        validated = _validate_current_report_head(session, identity=identity)
        if validated.last_sequence >= IJSON_MAX_SAFE_INTEGER:
            raise RuntimeEnrollmentHttpError(
                409,
                "SEQUENCE_EXHAUSTED",
                "conflict",
                "runtime report sequence is exhausted",
            )
        return validated.last_sequence + 1

    report_scope = (
        RuntimeReport.org_id == identity.org_id,
        RuntimeReport.project_id == identity.project_id,
        RuntimeReport.environment_id == identity.environment_id,
        RuntimeReport.identity_id == identity.id,
    )
    report_count = session.scalar(
        sa.select(sa.func.count()).select_from(RuntimeReport).where(*report_scope)
    )
    allow_operation_count = session.scalar(
        sa.select(sa.func.count())
        .select_from(RuntimeOperationIdempotency)
        .join(
            ManagedDecisionReceipt,
            sa.and_(
                ManagedDecisionReceipt.org_id == RuntimeOperationIdempotency.org_id,
                ManagedDecisionReceipt.project_id == RuntimeOperationIdempotency.project_id,
                ManagedDecisionReceipt.environment_id == RuntimeOperationIdempotency.environment_id,
                ManagedDecisionReceipt.receipt_id == RuntimeOperationIdempotency.receipt_id,
            ),
        )
        .where(
            RuntimeOperationIdempotency.org_id == identity.org_id,
            RuntimeOperationIdempotency.project_id == identity.project_id,
            RuntimeOperationIdempotency.environment_id == identity.environment_id,
            RuntimeOperationIdempotency.identity_id == identity.id,
            RuntimeOperationIdempotency.operation == REPORT_OPERATION,
            ManagedDecisionReceipt.decision == Decision.ALLOW.value,
        )
    )
    nonce_count = session.scalar(
        sa.select(sa.func.count())
        .select_from(RuntimeRequestNonce)
        .where(
            RuntimeRequestNonce.org_id == identity.org_id,
            RuntimeRequestNonce.project_id == identity.project_id,
            RuntimeRequestNonce.environment_id == identity.environment_id,
            RuntimeRequestNonce.identity_id == identity.id,
            RuntimeRequestNonce.purpose == REPORT_PURPOSE,
        )
    )
    if report_count != 0 or allow_operation_count != 0 or nonce_count != 0:
        raise ManagedReplayArtifactValidationError("runtime report head is missing")
    return 1


def _validate_current_report_head(
    session: Session,
    *,
    identity: RuntimeIdentity,
    preload: _FleetLineagePreload | None = None,
) -> RuntimeReportHead:
    heads = preload.heads_by_identity.get(identity.id, ()) if preload is not None else ()
    head = (
        heads[0]
        if len(heads) == 1
        else None
        if preload is not None
        else session.scalars(
            sa.select(RuntimeReportHead).where(
                RuntimeReportHead.org_id == identity.org_id,
                RuntimeReportHead.project_id == identity.project_id,
                RuntimeReportHead.environment_id == identity.environment_id,
                RuntimeReportHead.identity_id == identity.id,
            )
        ).one_or_none()
    )
    if head is None:
        raise ManagedReplayArtifactValidationError("runtime report head is missing")
    report_scope = (
        RuntimeReport.org_id == identity.org_id,
        RuntimeReport.project_id == identity.project_id,
        RuntimeReport.environment_id == identity.environment_id,
        RuntimeReport.identity_id == identity.id,
    )
    scoped_reports = (
        preload.reports_by_identity.get(identity.id, ()) if preload is not None else None
    )
    highest_sequence = (
        max((row.sequence for row in scoped_reports), default=None)
        if scoped_reports is not None
        else session.scalar(sa.select(sa.func.max(RuntimeReport.sequence)).where(*report_scope))
    )
    latest_matches = [
        row
        for row in scoped_reports or ()
        if row.sequence == head.last_sequence and row.id == head.latest_report_id
    ]
    latest = (
        (latest_matches[0] if len(latest_matches) == 1 else None)
        if scoped_reports is not None
        else session.scalars(
            sa.select(RuntimeReport).where(
                *report_scope,
                RuntimeReport.sequence == head.last_sequence,
                RuntimeReport.id == head.latest_report_id,
            )
        ).one_or_none()
    )
    if (
        highest_sequence is None
        or head.last_sequence != highest_sequence
        or latest is None
        or latest.report_hash != head.latest_report_hash
        or latest.projection_commitment != head.latest_projection_commitment
        or sha256_json(latest.request_projection) != head.latest_projection_commitment
    ):
        raise ManagedReplayArtifactValidationError("runtime report latest head anchor is invalid")
    _validate_report_row_against_projection(latest, latest.request_projection)
    checkpoint = latest.request_projection.get("history_checkpoint")
    if (
        not _valid_history_checkpoint(
            checkpoint,
            previous_accumulator=None,
            expected_count=head.last_sequence,
            report=latest,
        )
        or cast(dict[str, Any], checkpoint)["accumulator"] != head.history_accumulator
        or head.history_count != head.last_sequence
        or cast(dict[str, Any], checkpoint)["latest_wiring_sequence"] != head.latest_wiring_sequence
        or cast(dict[str, Any], checkpoint)["latest_wiring_report_id"]
        != head.latest_wiring_report_id
        or cast(dict[str, Any], checkpoint)["latest_wiring_report_hash"]
        != head.latest_wiring_report_hash
    ):
        raise ManagedReplayArtifactValidationError("runtime report history checkpoint is invalid")

    highest_wiring_sequence = (
        max((row.sequence for row in scoped_reports or () if row.kind == "wiring"), default=None)
        if scoped_reports is not None
        else session.scalar(
            sa.select(sa.func.max(RuntimeReport.sequence)).where(
                *report_scope,
                RuntimeReport.kind == "wiring",
            )
        )
    )
    if highest_wiring_sequence is None:
        if any(
            value is not None
            for value in (
                head.latest_wiring_kind,
                head.latest_wiring_sequence,
                head.latest_wiring_report_id,
                head.latest_wiring_report_hash,
                head.latest_wiring_projection_commitment,
            )
        ):
            raise ManagedReplayArtifactValidationError("runtime wiring head must be empty")
    else:
        wiring_matches = [
            row
            for row in scoped_reports or ()
            if row.kind == "wiring" and row.sequence == highest_wiring_sequence
        ]
        latest_wiring = (
            (wiring_matches[0] if len(wiring_matches) == 1 else None)
            if scoped_reports is not None
            else session.scalars(
                sa.select(RuntimeReport).where(
                    *report_scope,
                    RuntimeReport.kind == "wiring",
                    RuntimeReport.sequence == highest_wiring_sequence,
                )
            ).one_or_none()
        )
        if (
            latest_wiring is None
            or head.latest_wiring_kind != "wiring"
            or head.latest_wiring_sequence != highest_wiring_sequence
            or head.latest_wiring_report_id != latest_wiring.id
            or head.latest_wiring_report_hash != latest_wiring.report_hash
            or head.latest_wiring_projection_commitment != latest_wiring.projection_commitment
            or sha256_json(latest_wiring.request_projection)
            != head.latest_wiring_projection_commitment
        ):
            raise ManagedReplayArtifactValidationError("runtime wiring head anchor is invalid")
        _validate_report_row_against_projection(latest_wiring, latest_wiring.request_projection)

    report_count = (
        len(scoped_reports)
        if scoped_reports is not None
        else session.scalar(
            sa.select(sa.func.count()).select_from(RuntimeReport).where(*report_scope)
        )
    )
    allow_operation_count: int | None
    if preload is not None:
        allow_operation_count = sum(
            1
            for row in preload.idempotencies_by_identity.get(identity.id, ())
            if row.operation == REPORT_OPERATION
            and len(preload.receipts_by_id.get(row.receipt_id, ())) == 1
            and preload.receipts_by_id[row.receipt_id][0].decision == Decision.ALLOW.value
        )
    else:
        allow_operation_count = session.scalar(
            sa.select(sa.func.count())
            .select_from(RuntimeOperationIdempotency)
            .join(
                ManagedDecisionReceipt,
                sa.and_(
                    ManagedDecisionReceipt.org_id == RuntimeOperationIdempotency.org_id,
                    ManagedDecisionReceipt.project_id == RuntimeOperationIdempotency.project_id,
                    ManagedDecisionReceipt.environment_id
                    == RuntimeOperationIdempotency.environment_id,
                    ManagedDecisionReceipt.receipt_id == RuntimeOperationIdempotency.receipt_id,
                ),
            )
            .where(
                RuntimeOperationIdempotency.org_id == identity.org_id,
                RuntimeOperationIdempotency.project_id == identity.project_id,
                RuntimeOperationIdempotency.environment_id == identity.environment_id,
                RuntimeOperationIdempotency.identity_id == identity.id,
                RuntimeOperationIdempotency.operation == REPORT_OPERATION,
                ManagedDecisionReceipt.decision == Decision.ALLOW.value,
            )
        )
    nonce_count = (
        sum(
            1
            for row in preload.nonces_by_identity.get(identity.id, ())
            if row.purpose == REPORT_PURPOSE
        )
        if preload is not None
        else session.scalar(
            sa.select(sa.func.count())
            .select_from(RuntimeRequestNonce)
            .where(
                RuntimeRequestNonce.org_id == identity.org_id,
                RuntimeRequestNonce.project_id == identity.project_id,
                RuntimeRequestNonce.environment_id == identity.environment_id,
                RuntimeRequestNonce.identity_id == identity.id,
                RuntimeRequestNonce.purpose == REPORT_PURPOSE,
            )
        )
    )
    if report_count != allow_operation_count or report_count != nonce_count:
        raise ManagedReplayArtifactValidationError("runtime report durable lineage count mismatch")
    return head


def _validate_attestation_projection(
    evidence: RuntimeWiringAttestation,
    *,
    report: RuntimeReport,
    projection: dict[str, Any],
) -> WiringAttestation:
    projected_artifact = projection.get("artifact")
    if not isinstance(projected_artifact, dict):
        raise ManagedReplayArtifactValidationError("wiring artifact projection is missing")
    artifact = WiringAttestation.from_dict(projected_artifact)
    expected_columns = {
        "org_id": report.org_id,
        "project_id": report.project_id,
        "environment_id": report.environment_id,
        "gate_id": report.gate_id,
        "identity_id": report.identity_id,
        "report_kind": report.kind,
        "report_id": report.id,
        "attestation_hash": artifact.attestation_hash,
        "assurance_class": artifact.assurance_class,
        "evidence_kind": artifact.evidence_kind,
        "suite_id": artifact.suite_id,
        "suite_hash": artifact.suite_hash,
        "created_at": _runtime_timestamp(_to_utc(report.observed_at)),
    }
    actual_columns = {
        "org_id": evidence.org_id,
        "project_id": evidence.project_id,
        "environment_id": evidence.environment_id,
        "gate_id": evidence.gate_id,
        "identity_id": evidence.identity_id,
        "report_kind": evidence.report_kind,
        "report_id": evidence.report_id,
        "attestation_hash": evidence.attestation_hash,
        "assurance_class": evidence.assurance_class,
        "evidence_kind": evidence.evidence_kind,
        "suite_id": evidence.suite_id,
        "suite_hash": evidence.suite_hash,
        "created_at": _runtime_timestamp(_to_utc(evidence.created_at)),
    }
    if (
        artifact.to_dict() != projected_artifact
        or evidence.artifact != projected_artifact
        or artifact.attestation_hash != sha256_json(artifact.unsigned_payload())
        or actual_columns != expected_columns
    ):
        raise ManagedReplayArtifactValidationError("wiring artifact lineage is invalid")
    return artifact


def _validate_report_row_against_projection(
    report: RuntimeReport, projection: dict[str, Any]
) -> None:
    expected = {
        "id": projection.get("report_id"),
        "org_id": projection.get("org_id"),
        "project_id": projection.get("project_id"),
        "environment_id": projection.get("environment_id"),
        "gate_id": projection.get("gate_id"),
        "actor": projection.get("actor"),
        "identity_id": projection.get("identity_id"),
        "credential_id": projection.get("credential_id"),
        "credential_generation": projection.get("credential_generation"),
        "workload_key_id": projection.get("workload_key_id"),
        "public_key_thumbprint": projection.get("public_key_thumbprint"),
        "policy_version_id": projection.get("policy_version_id"),
        "policy_head_generation": projection.get("policy_head_generation"),
        "policy_content_hash": projection.get("policy_content_hash"),
        "runtime_build_digest": projection.get("runtime_build_digest"),
        "configuration_digest": projection.get("configuration_digest"),
        "policy_snapshot_hash": projection.get("policy_snapshot_hash"),
        "policy_provenance_hash": projection.get("policy_provenance_hash"),
        "policy_issued_at": projection.get("policy_issued_at"),
        "policy_revocation_checked_at": projection.get("policy_revocation_checked_at"),
        "policy_fresh_until": projection.get("policy_fresh_until"),
        "policy_expires_at": projection.get("policy_expires_at"),
        "kind": projection.get("kind"),
        "sequence": projection.get("sequence"),
        "nonce": projection.get("request_nonce"),
        "report_hash": projection.get("report_hash"),
        "request_signature": projection.get("request_signature"),
        "observed_at": projection.get("observed_at"),
        "expires_at": projection.get("expires_at"),
        "created_at": projection.get("created_at"),
    }
    actual = {
        "id": report.id,
        "org_id": report.org_id,
        "project_id": report.project_id,
        "environment_id": report.environment_id,
        "gate_id": report.gate_id,
        "actor": report.actor,
        "identity_id": report.identity_id,
        "credential_id": report.credential_id,
        "credential_generation": report.credential_generation,
        "workload_key_id": report.workload_key_id,
        "public_key_thumbprint": report.public_key_thumbprint,
        "policy_version_id": report.policy_version_id,
        "policy_head_generation": report.policy_head_generation,
        "policy_content_hash": report.policy_content_hash,
        "runtime_build_digest": report.runtime_build_digest,
        "configuration_digest": report.configuration_digest,
        "policy_snapshot_hash": report.policy_snapshot_hash,
        "policy_provenance_hash": report.policy_provenance_hash,
        "policy_issued_at": _runtime_timestamp(_to_utc(report.policy_issued_at)),
        "policy_revocation_checked_at": _runtime_timestamp(
            _to_utc(report.policy_revocation_checked_at)
        ),
        "policy_fresh_until": _runtime_timestamp(_to_utc(report.policy_fresh_until)),
        "policy_expires_at": _runtime_timestamp(_to_utc(report.policy_expires_at)),
        "kind": report.kind,
        "sequence": report.sequence,
        "nonce": report.nonce,
        "report_hash": report.report_hash,
        "request_signature": report.request_signature,
        "observed_at": _runtime_timestamp(_to_utc(report.observed_at)),
        "expires_at": _runtime_timestamp(_to_utc(report.expires_at)),
        "created_at": _runtime_timestamp(_to_utc(report.created_at)),
    }
    if actual != expected:
        raise ManagedReplayArtifactValidationError("runtime report immutable projection mismatch")


def _valid_history_checkpoint(
    value: Any,
    *,
    previous_accumulator: str | None,
    expected_count: int,
    report: RuntimeReport,
) -> bool:
    expected_keys = {
        "schema",
        "previous_accumulator",
        "count",
        "report_id",
        "report_hash",
        "latest_wiring_sequence",
        "latest_wiring_report_id",
        "latest_wiring_report_hash",
        "accumulator",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        return False
    unsigned = dict(value)
    accumulator = unsigned.pop("accumulator", None)
    return bool(
        value.get("schema") == "acgs.runtime-report-history-checkpoint/v1"
        and type(value.get("count")) is int
        and value["count"] == expected_count
        and value.get("report_id") == report.id
        and value.get("report_hash") == report.report_hash
        and type(value.get("previous_accumulator")) is str
        and (previous_accumulator is None or value["previous_accumulator"] == previous_accumulator)
        and type(accumulator) is str
        and accumulator == sha256_json(unsigned)
    )


def _validate_non_executable_report_lineage(
    session: Session, *, existing: RuntimeOperationIdempotency
) -> None:
    report_count = session.scalar(
        sa.select(sa.func.count())
        .select_from(RuntimeReport)
        .where(
            RuntimeReport.org_id == existing.org_id,
            RuntimeReport.project_id == existing.project_id,
            RuntimeReport.environment_id == existing.environment_id,
            RuntimeReport.identity_id == existing.identity_id,
            RuntimeReport.receipt_id == existing.receipt_id,
        )
    )
    nonce_count = session.scalar(
        sa.select(sa.func.count())
        .select_from(RuntimeRequestNonce)
        .where(
            RuntimeRequestNonce.org_id == existing.org_id,
            RuntimeRequestNonce.project_id == existing.project_id,
            RuntimeRequestNonce.environment_id == existing.environment_id,
            RuntimeRequestNonce.identity_id == existing.identity_id,
            RuntimeRequestNonce.idempotency_key_hash == existing.idempotency_key_hash,
            RuntimeRequestNonce.request_hash == existing.request_hash,
            RuntimeRequestNonce.purpose == REPORT_PURPOSE,
        )
    )
    if report_count != 0 or nonce_count != 0:
        raise ManagedReplayArtifactValidationError("non-executable report has executable lineage")


_EXPECTED_REPORT_CONFLICTS = frozenset(
    {
        "uq_runtime_reports_identity_sequence",
        "uq_runtime_reports_identity_nonce",
        "uq_runtime_reports_scope_receipt",
        "uq_runtime_request_nonce_identity",
        "uq_runtime_wiring_attestations_attestation_hash",
        "uq_runtime_wiring_attestations_report",
        "uq_runtime_wiring_challenge_identity_nonce",
        "uq_runtime_wiring_challenge_report",
    }
)


def _integrity_constraint_name(exc: IntegrityError) -> str | None:
    diagnostic = getattr(exc.orig, "diag", None)
    name = getattr(diagnostic, "constraint_name", None)
    if isinstance(name, str):
        return name
    message = str(exc.orig)
    sqlite_unique_map = {
        "runtime_operation_idempotency.org_id, runtime_operation_idempotency.project_id, "
        "runtime_operation_idempotency.environment_id, runtime_operation_idempotency.identity_id, "
        "runtime_operation_idempotency.operation, "
        "runtime_operation_idempotency.idempotency_key_hash": (
            "uq_runtime_operation_idempotency_scope_operation_key"
        ),
        "runtime_reports.org_id, runtime_reports.project_id, runtime_reports.environment_id, "
        "runtime_reports.identity_id, runtime_reports.sequence": (
            "uq_runtime_reports_identity_sequence"
        ),
        "runtime_reports.org_id, runtime_reports.project_id, runtime_reports.environment_id, "
        "runtime_reports.identity_id, runtime_reports.nonce": "uq_runtime_reports_identity_nonce",
        "runtime_wiring_challenge_consumptions.org_id, "
        "runtime_wiring_challenge_consumptions.project_id, "
        "runtime_wiring_challenge_consumptions.environment_id, "
        "runtime_wiring_challenge_consumptions.identity_id, "
        "runtime_wiring_challenge_consumptions.challenge_nonce": (
            "uq_runtime_wiring_challenge_identity_nonce"
        ),
        "runtime_wiring_challenge_consumptions.report_id": "uq_runtime_wiring_challenge_report",
    }
    return next((value for key, value in sqlite_unique_map.items() if key in message), None)


def _terminal_tampered() -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(
        503,
        "TERMINAL_RESPONSE_TAMPERED",
        "terminal_response_tampered",
        "runtime report terminal response could not be verified",
    )


def _database_unavailable() -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(
        503,
        "DATABASE_UNAVAILABLE",
        "service_unavailable",
        "runtime report persistence is unavailable",
    )


def _require_idempotency_key(value: str | None) -> str:
    if value is None or not 8 <= len(value) <= 200:
        raise RuntimeEnrollmentHttpError(
            400, "IDEMPOTENCY_KEY_REQUIRED", "bad_request", "valid Idempotency-Key required"
        )
    return value


def _authentication_refused() -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(
        401, "RUNTIME_AUTHENTICATION_FAILED", "unauthorized", "runtime authentication failed"
    )


def _conflict(code: str) -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(409, code, "conflict", "runtime report conflict")


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


__all__ = [
    "RuntimeReportAuth",
    "RuntimeReportService",
]
