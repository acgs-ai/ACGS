"""Strict, externally verifiable proof packs for one release deployment.

The pack is an evidence projection, never an executable authorization.  It
contains no nonce, idempotency key, authentication context, private key, or
``SideEffectAuthorization``.  Verification requires caller-supplied public
keys and an out-of-band expected pack digest; embedded trust roots are not
accepted.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import json
import os
import shlex
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import gove_zone.proof_pack as sealed_pack
from gove_zone.audit import (
    AuditCheckpoint,
    AuditCheckpointAnchor,
    ChainHashAuditStore,
)
from gove_zone.authorization import (
    ARGUMENT_CANONICALIZATION_PROFILE,
    RESERVED_BINDING_REQUIRED_KEYS,
    SECRET_DIGEST_PROFILE,
    SIDE_EFFECT_BINDING_KEY,
    AuthorizationReasonCode,
    EvidenceRef,
    ExecutionReasonCode,
    ExecutionRefusalEvidence,
    ExecutionRefusalPhase,
    compute_evidence_digest,
    deep_thaw_json,
    strict_json_hash,
)
from gove_zone.consumption import (
    ConsumptionState,
    ConsumptionStateAnchor,
    ReceiptConsumptionStore,
)
from gove_zone.decision import RecordKind, canonical_json
from gove_zone.path_capability import (
    AttestedDirectory,
    PathCapabilityError,
    require_attested_directory,
)
from gove_zone.policy import PolicyArtifactSnapshot
from gove_zone.proof_pack import SealedPackCodec, SealedPackSchema, read_exact_pack_by_schema
from gove_zone.receipt import DecisionReceipt
from gove_zone.release_gate import (
    RELEASE_GATE_EXECUTION_BOUNDARY,
    RELEASE_GATE_OPERATION,
    RELEASE_GATE_SERVER_ID,
    RELEASE_GATE_SIDE_EFFECT_CLASS,
    RELEASE_GATE_TOOL,
    ReleaseDeployment,
    ReleaseEvidenceClaim,
    ReleaseEvidenceRequirement,
    ReleaseGate,
    ReleaseGatePolicy,
    ReleaseGateRequirements,
    ReleaseProofContext,
    ReleaseProofSinkError,
)
from gove_zone.replay import execution_refusal_error, replay_checkpointed_bundle
from gove_zone.replay_store import ReplaySideStore
from gove_zone.signing import Ed25519Signer, LifecycleVerifierRegistry, ReceiptSigner

PROOF_PACK_SCHEMA = "gove-zone.release-proof-pack/v1"
DISASTER_PROOF_PACK_SCHEMA = "gove-zone.release-proof-pack/v2"
DISASTER_SCENARIO_SCHEMA = "gove-zone.release-artifact-tamper-scenario/v1"
CONSUMPTION_SUMMARY_SCHEMA = "gove-zone.release-consumption-summary/v1"
CONSUMPTION_EVIDENCE_MODE = "signed-redacted-attestation-not-state-root-membership-proof"
LIFECYCLE_TRUST_SCHEMA = "gove-zone.release-lifecycle-trust/v1"
_CONSUMPTION_DOMAIN = b"gove-zone:release-consumption-summary:v1\x00"
_PACK_DOMAIN = b"gove-zone:release-proof-pack:v1\x00"
_DISASTER_PACK_DOMAIN = b"gove-zone:release-proof-pack:v2\x00"
_SHA256 = frozenset("0123456789abcdef")
_MAX_FILE_SIZE = 2 * 1024 * 1024
_MAX_TOTAL_SIZE = 8 * 1024 * 1024
_MAX_REFERENCE_ARTIFACT_SIZE = 256 * 1024 * 1024
_EXECUTION_EVIDENCE_DOMAIN = "gove-zone:standalone-execution-evidence:v1"
_LIFECYCLE_AUTHORITY_ID = "release-execution-validator"
_EXECUTION_EVIDENCE_KEYS = frozenset(
    {
        "tenant_digest",
        "execution_boundary_digest",
        "adapter_id_digest",
        "adapter_artifact_digest",
        "receipt_id_digest",
        "receipt_hash",
        "request_id_digest",
        "authorization_audit_digest",
        "nonce_digest",
        "idempotency_digest",
        "attempt_id_digest",
        "binding_hash",
        "argument_hash",
        "phase",
        "reason_code",
        "consumption_state",
    }
)

_MEDIA_TYPES = {
    "audit-checkpoint.json": "application/json",
    "audit.jsonl": "application/x-ndjson",
    "consumption-summary.json": "application/json",
    "lifecycle-trust.json": "application/json",
    "policy.json": "application/json",
    "receipt.json": "application/json",
    "replay.jsonl": "application/x-ndjson",
    "request.json": "application/json",
}
_RECEIPT_KEYS = frozenset(DecisionReceipt.__dataclass_fields__) - {"_action_tier_was_present"}
_CHECKPOINT_KEYS = frozenset(
    {
        "namespace",
        "generation",
        "head_hash",
        "previous_checkpoint_hash",
        "key_id",
        "algorithm",
        "signature",
    }
)
_REQUEST_KEYS = frozenset(
    {
        "schema",
        "request_id",
        "tenant_id",
        "actor_id",
        "actor_role",
        "authority",
        "server_id",
        "tool",
        "operation",
        "resource",
        "environment",
        "execution_boundary",
        "policy_ref",
        "requested_at",
        "args",
        "evidence",
        "side_effect_class",
        "goal_claim",
    }
)
_SUMMARY_KEYS = frozenset(
    {
        "schema",
        "tenant_id",
        "receipt_id",
        "state",
        "adapter_result_digest",
        "store_id",
        "generation",
        "chain_head",
        "state_root",
        "anchor_namespace",
        "key_id",
        "algorithm",
        "evidence_mode",
        "signature",
    }
)
_LIFECYCLE_TRUST_KEYS = frozenset(
    {"schema", "checkpoint_authority_id", "authority_id", "key_id", "algorithm"}
)
_DISASTER_SCENARIO_KEYS = frozenset(
    {
        "approved_arguments",
        "approved_receipt",
        "baseline_side_effect_calls",
        "claim_boundary",
        "companion_allow_side_effect_calls",
        "decision",
        "governed_side_effect_calls",
        "reason_codes",
        "scenario",
        "scenario_digest",
        "schema",
        "attempted_arguments",
    }
)
_DISASTER_PROTOCOL_KEYS = frozenset(
    {
        "argument_hash",
        "arguments",
        "decision",
        "event_id",
        "phase",
        "reason_codes",
        "receipt_id",
        "record_id",
        "side_effect_calls",
    }
)
_DISASTER_REFUSAL_KEYS = frozenset({"event_id", "reason_codes", "receipt", "record_id"})


class ReleaseProofError(RuntimeError):
    """A proof pack cannot be exported or strongly verified."""


class ReleaseProofExportError(ReleaseProofError, sealed_pack.SealedPackExportState):
    """Release proof export failure with explicit filesystem commit state."""

    reason_code = "release.proof.export_failed"
    redact_export_cause = True

    def __init__(
        self,
        message: str,
        *,
        committed: bool,
        parent_identity_preserved: bool | None,
        pinned_final_entry_exists: bool | None,
        lexical_final_path_exists: bool | None,
        final_path_exists: bool | None,
        cleanup_attempted: bool,
        cleanup_succeeded: bool | None,
        durability_uncertain: bool,
        retry_safe: bool,
        phase: str,
        final_path: Path,
        temp_path: Path | None,
        temp_path_exists: bool | None,
    ) -> None:
        del message
        safe_message = (
            f"{self.reason_code}: release proof export failed during {phase}; "
            f"committed={committed}; durability_uncertain={durability_uncertain}; "
            f"retry_safe={retry_safe}"
        )
        ReleaseProofError.__init__(self, safe_message)
        self._initialize_export_state(
            committed=committed,
            parent_identity_preserved=parent_identity_preserved,
            pinned_final_entry_exists=pinned_final_entry_exists,
            lexical_final_path_exists=lexical_final_path_exists,
            final_path_exists=final_path_exists,
            cleanup_attempted=cleanup_attempted,
            cleanup_succeeded=cleanup_succeeded,
            durability_uncertain=durability_uncertain,
            retry_safe=retry_safe,
            phase=phase,
            final_path=final_path,
            temp_path=temp_path,
            temp_path_exists=temp_path_exists,
        )


def _execution_evidence_digest(label: str, value: str) -> str:
    return strict_json_hash({"domain": _EXECUTION_EVIDENCE_DOMAIN, "field": label, "value": value})


# Every binding that an execution refusal and an execution lifecycle both
# commit. A refusal claiming the target's receipt must agree with the selected
# lifecycle on all of them; matching only ``receipt_id_digest`` would accept a
# record that claims this receipt while substituting the receipt hash, reserved
# binding, adapter route, or authorizing audit event. Nonce and idempotency
# digests are absent because the refusal evidence schema does not carry them;
# the record's tool and policy_version are enforced against the release chain by
# the caller.
_REFUSAL_BINDING_FIELDS = (
    "request_id_digest",
    "receipt_id_digest",
    "receipt_hash",
    "tenant_digest",
    "execution_boundary_digest",
    "adapter_id_digest",
    "authorization_audit_digest",
    "binding_hash",
    "argument_hash",
)

# Bindings that identify *which* receipted attempt a record is about. A refusal
# that claims some other receipt id may not share any of these with the target:
# doing so would be a refusal of this exact operation wearing another receipt's
# identity, which is a substitution rather than a coincidence.
_REFUSAL_DISTINCT_FIELDS = (
    "receipt_hash",
    "binding_hash",
    "authorization_audit_digest",
)


def _release_refusal_is_permitted(
    event: dict[str, Any],
    *,
    reference: Mapping[str, str],
    forbidden_attempt_digests: frozenset[str],
) -> bool:
    """Return whether one interleaved refusal record may coexist with the proof.

    A refusal is tolerated only because it is provably inert with respect to
    this release: it must independently satisfy the shared refusal contract,
    prove that no adapter ran, never claim an attempt the selected success
    lifecycle accounts for, and be *consistently* about one operation. Anything
    else — a policy decision, an unrelated execution lifecycle, an unverifiable
    or malformed refusal — is rejected by the caller.

    Concurrent gates legitimately interleave refusals of the target receipt and
    of entirely different receipts, so both are permitted; what is never
    permitted is a record whose identity claims disagree with each other.
    ``reference`` is the already-validated lifecycle evidence of the selected
    attempt, so every comparison is against proven values rather than against
    claims the refusal makes about itself.
    """

    if execution_refusal_error(event) is not None:
        return False
    evidence = cast(dict[str, str], event.get("execution_evidence"))
    if evidence.get("adapter_invoked") != "false":
        return False
    if evidence.get("attempt_id_digest") in forbidden_attempt_digests:
        # Claims one of the exact attempts this pack reports as succeeding.
        return False
    if evidence.get("receipt_id_digest") == reference["receipt_id_digest"]:
        # Same receipt, different attempt: every other binding must match, so a
        # refusal of this receipt cannot substitute the receipt hash, reserved
        # binding, adapter route, or authorizing audit event and still pass.
        return all(evidence.get(name) == reference[name] for name in _REFUSAL_BINDING_FIELDS)
    # A different receipt is inert only when it is consistently about a
    # different operation.
    return all(evidence.get(name) != reference[name] for name in _REFUSAL_DISTINCT_FIELDS)


def _release_audit_partition(
    events: list[dict[str, Any]],
    *,
    receipt: DecisionReceipt,
    request: Mapping[str, Any],
    policy_version: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Select one authorization and validate its exact committed execution pair.

    Selection is by receipt/attempt/nonce/authorization digest binding, not by
    position: concurrent attempts on the same receipt legitimately interleave
    refusal records into the chain. Interleaving is *permitted*, never ignored —
    every non-selected record must prove it is an inert execution refusal.
    """

    matches = [
        index
        for index, event in enumerate(events)
        if event.get("event_id") == receipt.receipt_id
        and event.get("event_hash") == receipt.audit_event_hash
    ]
    if len(matches) != 1:
        raise ReleaseProofError("release authorization audit event is missing or ambiguous")
    target_index = matches[0]
    if any(
        event.get("tool") != RELEASE_GATE_OPERATION or event.get("policy_version") != policy_version
        for event in events
    ):
        raise ReleaseProofError("release proof audit contains unrelated events")

    # Classify strictly by authenticated record_kind. Evidence presence never
    # decides classification.
    authorization_events: list[dict[str, Any]] = []
    lifecycle_events: list[dict[str, Any]] = []
    refusal_events: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        kind = event.get("record_kind", RecordKind.POLICY_DECISION.value)
        if kind == RecordKind.POLICY_DECISION.value:
            if "execution_evidence" in event or "lifecycle_attestation" in event:
                raise ReleaseProofError("release authorization record kind mismatch")
            if index > target_index:
                raise ReleaseProofError("release proof audit interleaves a later policy decision")
            authorization_events.append(event)
        elif kind == RecordKind.EXECUTION_LIFECYCLE.value:
            if index < target_index:
                raise ReleaseProofError("release execution lifecycle predates its authorization")
            lifecycle_events.append(event)
        elif kind == RecordKind.EXECUTION_REFUSAL.value:
            refusal_events.append(event)
        else:
            raise ReleaseProofError("release proof audit contains an unknown record kind")
    if not authorization_events or authorization_events[-1] is not events[target_index]:
        raise ReleaseProofError("release authorization record kind mismatch")

    # Every lifecycle record in the chain must belong to this exact receipt;
    # an unrelated one is never silently dropped.
    expected_receipt_id_digest = _execution_evidence_digest("receipt_id", receipt.receipt_id)
    for event in lifecycle_events:
        evidence = event.get("execution_evidence")
        if (
            type(evidence) is not dict
            or evidence.get("receipt_id_digest") != expected_receipt_id_digest
        ):
            raise ReleaseProofError("release proof audit contains unrelated execution lifecycle")
    if len(lifecycle_events) != 2:
        raise ReleaseProofError("release proof requires an exact claim and terminal audit suffix")

    authorization = authorization_events[-1]
    claim, terminal = lifecycle_events
    expected_common: dict[str, object] = {
        "tool": RELEASE_GATE_OPERATION,
        "actor": receipt.actor,
        "argument_hash": receipt.argument_hash,
        "policy_version": policy_version,
        "decision": "allow",
        "goal": "",
        "path": [],
        "state_hash": None,
        "decision_request_hash": "",
        "transformed_args": None,
    }
    # The pair is ordered by chain position and bound by digest. Adjacency is
    # deliberately NOT required: a concurrent attempt's refusal may legitimately
    # be committed between the authorization, the claim, and the terminal.
    phases = (
        (claim, "claim_committed", "receipt.execution.reserved", "RESERVED"),
        (terminal, "terminal", "receipt.execution.succeeded", "SUCCEEDED"),
    )
    evidence_rows: list[dict[str, str]] = []
    for event, phase, reason, state in phases:
        evidence = event.get("execution_evidence")
        if event.get("record_kind") != RecordKind.EXECUTION_LIFECYCLE.value:
            raise ReleaseProofError("release execution lifecycle record kind mismatch")
        if (
            any(event.get(name) != value for name, value in expected_common.items())
            or event.get("reason") != reason
            or event.get("matched_rules") != [reason]
            or type(evidence) is not dict
            or set(evidence) != _EXECUTION_EVIDENCE_KEYS
            or any(type(value) is not str for value in evidence.values())
        ):
            raise ReleaseProofError("release execution lifecycle audit is malformed")
        typed = cast(dict[str, str], evidence)
        if (
            typed["phase"] != phase
            or typed["reason_code"] != reason
            or typed["consumption_state"] != state
            or typed["receipt_hash"] != receipt.receipt_hash
            or typed["argument_hash"] != receipt.argument_hash
            or typed["receipt_id_digest"]
            != _execution_evidence_digest("receipt_id", receipt.receipt_id)
            or typed["request_id_digest"]
            != _execution_evidence_digest("request_id", receipt.request_id)
            or typed["tenant_digest"] != _execution_evidence_digest("tenant", receipt.tenant_id)
            or typed["execution_boundary_digest"]
            != _execution_evidence_digest("execution_boundary", receipt.execution_boundary)
            or typed["authorization_audit_digest"]
            != _execution_evidence_digest("authorization_audit", receipt.audit_event_hash)
        ):
            raise ReleaseProofError("release execution lifecycle binding mismatch")
        evidence_rows.append(typed)
    varying = {"phase", "reason_code", "consumption_state"}
    if any(
        evidence_rows[0][name] != evidence_rows[1][name]
        for name in _EXECUTION_EVIDENCE_KEYS - varying
    ):
        raise ReleaseProofError("release execution lifecycle attempt binding diverges")

    # Only now is the selected attempt's binding proven, so it is the reference
    # every interleaved refusal must match. Checking earlier would compare
    # against unvalidated claims.
    selected_attempts = frozenset(row["attempt_id_digest"] for row in evidence_rows)
    for event in refusal_events:
        if not _release_refusal_is_permitted(
            event,
            reference=evidence_rows[0],
            forbidden_attempt_digests=selected_attempts,
        ):
            raise ReleaseProofError("release proof audit contains a non-inert interleaved record")
    requested_at = _timestamp(str(request.get("requested_at")), "request.requested_at")
    if any(
        _timestamp(str(event.get("timestamp_iso")), "audit.timestamp_iso") < requested_at
        for event in lifecycle_events
    ):
        raise ReleaseProofError("release execution lifecycle timestamp predates the request")
    return authorization, authorization_events, lifecycle_events


def _release_lifecycle_trust(
    lifecycle_events: list[dict[str, Any]], checkpoint: AuditCheckpoint
) -> dict[str, str]:
    metadata: set[tuple[str, str, str]] = set()
    for event in lifecycle_events:
        attestation = event.get("lifecycle_attestation")
        if type(attestation) is not dict or set(attestation) != {
            "authority_id",
            "key_id",
            "algorithm",
            "payload_hash",
            "signature",
        }:
            raise ReleaseProofError("release lifecycle attestation is missing or malformed")
        metadata.add(
            (
                _required_text(attestation.get("authority_id"), "lifecycle.authority_id"),
                _required_text(attestation.get("key_id"), "lifecycle.key_id"),
                _required_text(attestation.get("algorithm"), "lifecycle.algorithm"),
            )
        )
    if len(metadata) != 1:
        raise ReleaseProofError("release lifecycle trust metadata is not stable")
    authority_id, key_id, algorithm = metadata.pop()
    checkpoint_authority_id = f"audit-checkpoint:{checkpoint.namespace}"
    if (
        algorithm != "ed25519"
        or authority_id == checkpoint_authority_id
        or authority_id == "audit-checkpoint"
        or key_id == checkpoint.key_id
    ):
        raise ReleaseProofError("release lifecycle/checkpoint duties are not separated")
    return {
        "schema": LIFECYCLE_TRUST_SCHEMA,
        "checkpoint_authority_id": checkpoint_authority_id,
        "authority_id": authority_id,
        "key_id": key_id,
        "algorithm": algorithm,
    }


_RELEASE_PACK_SCHEMA = SealedPackSchema(
    schema=PROOF_PACK_SCHEMA,
    digest_domain=_PACK_DOMAIN,
    media_types=_MEDIA_TYPES,
    verification={
        "checkpoint": "external-ed25519-public-key",
        "consumption": CONSUMPTION_EVIDENCE_MODE,
        "expected_pack_digest": "required-out-of-band-sha256",
        "receipt": "external-ed25519-public-key",
        "replay": "strict-complete-audit-id-ordered-rederivation",
    },
    max_file_size=_MAX_FILE_SIZE,
    max_total_size=_MAX_TOTAL_SIZE,
    error_type=ReleaseProofError,
)
_RELEASE_PACK_CODEC = SealedPackCodec(
    _RELEASE_PACK_SCHEMA,
    error_type=ReleaseProofError,
    export_error_type=ReleaseProofExportError,
)
_DISASTER_MEDIA_TYPES = {
    **_MEDIA_TYPES,
    "protocol-results.jsonl": "application/x-ndjson",
    "refusals.jsonl": "application/x-ndjson",
    "scenario.json": "application/json",
}
_RELEASE_DISASTER_PACK_SCHEMA = SealedPackSchema(
    schema=DISASTER_PROOF_PACK_SCHEMA,
    digest_domain=_DISASTER_PACK_DOMAIN,
    media_types=_DISASTER_MEDIA_TYPES,
    verification={
        "checkpoint": "external-ed25519-public-key",
        "consumption": CONSUMPTION_EVIDENCE_MODE,
        "expected_pack_digest": "required-out-of-band-sha256",
        "receipt": "external-ed25519-public-key",
        "replay": "strict-complete-audit-id-ordered-rederivation",
        "scenario": "artifact-tamper-cross-linked-v1",
    },
    max_file_size=_MAX_FILE_SIZE,
    max_total_size=_MAX_TOTAL_SIZE,
    error_type=ReleaseProofError,
)
_RELEASE_DISASTER_PACK_CODEC = SealedPackCodec(
    _RELEASE_DISASTER_PACK_SCHEMA,
    error_type=ReleaseProofError,
    export_error_type=ReleaseProofExportError,
)
_PAYLOAD_FILES = _RELEASE_PACK_SCHEMA.payload_files
_PACK_FILES = _RELEASE_PACK_SCHEMA.pack_files


@dataclass(frozen=True, slots=True)
class ReleaseProofSources:
    """Explicit public proof sources owned by the release-gate caller."""

    output_directory: Path
    policy_snapshot: PolicyArtifactSnapshot
    audit_store: ChainHashAuditStore
    audit_anchor: AuditCheckpointAnchor
    audit_namespace: str
    replay_store: ReplaySideStore
    consumption_store: ReceiptConsumptionStore
    consumption_anchor: ConsumptionStateAnchor
    consumption_namespace: str
    consumption_signer: ReceiptSigner

    def __post_init__(self) -> None:
        object.__setattr__(self, "output_directory", Path(self.output_directory))
        if not isinstance(self.policy_snapshot, PolicyArtifactSnapshot):
            raise TypeError("policy_snapshot must be PolicyArtifactSnapshot")
        if not isinstance(self.audit_store, ChainHashAuditStore):
            raise TypeError("audit_store must be ChainHashAuditStore")
        if not isinstance(self.audit_anchor, AuditCheckpointAnchor):
            raise TypeError("audit_anchor must implement AuditCheckpointAnchor")
        if not isinstance(self.replay_store, ReplaySideStore):
            raise TypeError("replay_store must be ReplaySideStore")
        if not isinstance(self.consumption_store, ReceiptConsumptionStore):
            raise TypeError("consumption_store must be ReceiptConsumptionStore")
        if not isinstance(self.consumption_anchor, ConsumptionStateAnchor):
            raise TypeError("consumption_anchor must implement ConsumptionStateAnchor")
        if not isinstance(self.consumption_signer, ReceiptSigner):
            raise TypeError("consumption_signer must implement ReceiptSigner")
        if self.consumption_signer.algorithm != "ed25519":
            raise ReleaseProofError("consumption summary requires an Ed25519 signer")
        _text(self.audit_namespace, "audit_namespace")
        _text(self.consumption_namespace, "consumption_namespace")


@dataclass(frozen=True, slots=True)
class ReleaseProofPack:
    directory: Path
    pack_digest: str
    receipt_id: str


@dataclass(frozen=True, slots=True)
class ReleaseProofVerification:
    valid: bool
    pack_digest: str
    receipt_id: str
    replay: Mapping[str, Any]
    consumption_evidence_mode: str = CONSUMPTION_EVIDENCE_MODE

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "pack_digest": self.pack_digest,
            "receipt_id": self.receipt_id,
            "consumption_evidence_mode": self.consumption_evidence_mode,
            "replay": dict(self.replay),
        }


@dataclass(frozen=True, slots=True)
class ReleaseReferenceBinding:
    """One immutable release/evidence subject for the local GitHub reference.

    The reference integration intentionally accepts an approved binding and a
    separately requested binding.  Policy is pinned to the former while only
    the latter is presented to :class:`ReleaseGate`; changing a commit,
    artifact, environment, approval, or evidence digest therefore produces a
    normal fail-closed policy denial before the fixture adapter.
    """

    repository: str
    ref: str
    branch: str
    commit_sha: str
    workflow_identity: str
    artifact_digest: str
    environment: str
    deployment_target: str
    approval_identity: str
    approval_evidence_digest: str
    security_evidence_digest: str
    tests_evidence_digest: str

    def __post_init__(self) -> None:
        for name in (
            "repository",
            "ref",
            "branch",
            "commit_sha",
            "workflow_identity",
            "environment",
            "deployment_target",
            "approval_identity",
        ):
            _required_text(getattr(self, name), name)
        _required_sha256(self.artifact_digest, "artifact_digest")
        _required_sha256(self.approval_evidence_digest, "approval_evidence_digest")
        _required_sha256(self.security_evidence_digest, "security_evidence_digest")
        _required_sha256(self.tests_evidence_digest, "tests_evidence_digest")
        if not self.deployment_target.startswith("fixture://"):
            raise ValueError("reference deployment_target must use fixture://")
        if not self.workflow_identity.startswith(("github-actions:", "fixture:")):
            raise ValueError("workflow_identity must be github-actions: or fixture: scoped")

        # Reuse the product adapter's canonical validators rather than
        # introducing a second repository/ref/commit schema.
        ReleaseDeployment(
            repository=self.repository,
            ref=self.ref,
            branch=self.branch,
            commit_sha=self.commit_sha,
            workflow_identity=self.workflow_identity,
            artifact_digest=self.artifact_digest,
            environment=self.environment,
            deployment_target=self.deployment_target,
            approval_identity=self.approval_identity,
            evidence=(
                _reference_claim(
                    self,
                    evidence_type="approval",
                    digest=self.approval_evidence_digest,
                    issuer="fixture-validation",
                    verifier_id="fixture-validation",
                    issued_at="2026-01-01T00:00:00Z",
                    expires_at="2027-01-01T00:00:00Z",
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class ReleaseReferenceInput:
    """Strict immutable input to the network-free P0 GitHub reference runner."""

    approved: ReleaseReferenceBinding
    requested: ReleaseReferenceBinding
    artifact_path: Path
    request_id: str
    tenant_id: str
    actor_id: str
    actor_role: str
    authority: str
    evidence_issuer: str
    evidence_verifier_id: str
    validator_role: str
    requested_at: str
    observed_at: str
    principal_verified_at: str
    principal_expires_at: str
    evidence_issued_at: str
    evidence_expires_at: str
    nonce: str = field(repr=False)
    idempotency_key: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.approved, ReleaseReferenceBinding):
            raise TypeError("approved must be ReleaseReferenceBinding")
        if not isinstance(self.requested, ReleaseReferenceBinding):
            raise TypeError("requested must be ReleaseReferenceBinding")
        if not isinstance(self.artifact_path, Path) or not self.artifact_path.is_absolute():
            raise TypeError("artifact_path must be an absolute pathlib.Path")
        for name in (
            "request_id",
            "tenant_id",
            "actor_id",
            "actor_role",
            "authority",
            "evidence_issuer",
            "evidence_verifier_id",
            "validator_role",
            "nonce",
            "idempotency_key",
        ):
            _required_text(getattr(self, name), name)
        requested = _timestamp(self.requested_at, "requested_at")
        observed = _timestamp(self.observed_at, "observed_at")
        principal_verified = _timestamp(self.principal_verified_at, "principal_verified_at")
        principal_expires = _timestamp(self.principal_expires_at, "principal_expires_at")
        evidence_issued = _timestamp(self.evidence_issued_at, "evidence_issued_at")
        evidence_expires = _timestamp(self.evidence_expires_at, "evidence_expires_at")
        if not (
            principal_verified <= requested <= observed < principal_expires
            and evidence_issued <= requested < evidence_expires
        ):
            raise ValueError("reference identity/evidence timestamps have invalid ordering")


class ReleaseProofPackExporter:
    """Callable post-execution sink that writes one immutable proof pack."""

    def __init__(
        self,
        sources: ReleaseProofSources,
        *,
        path_capability: AttestedDirectory | None = None,
        commit_guard: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(sources, ReleaseProofSources):
            raise TypeError("sources must be ReleaseProofSources")
        if path_capability is not None:
            require_attested_directory(path_capability, error_type=ReleaseProofError)
        self.sources = sources
        self.path_capability = path_capability
        self.commit_guard = commit_guard
        self.last_pack: ReleaseProofPack | None = None

    def __call__(self, context: ReleaseProofContext) -> None:
        if self.commit_guard is not None:
            self.commit_guard("before-base-pack")
        self.last_pack = export_release_proof_pack(
            context,
            self.sources,
            path_capability=self.path_capability,
        )
        if self.commit_guard is not None:
            self.commit_guard("base-pack-committed")


def export_release_proof_pack(
    context: ReleaseProofContext,
    sources: ReleaseProofSources,
    *,
    path_capability: AttestedDirectory | None = None,
) -> ReleaseProofPack:
    """Export a fixed, redacted allowlist after confirmed schema-v4 success."""

    if not isinstance(context, ReleaseProofContext):
        raise TypeError("context must be ReleaseProofContext")
    if not isinstance(sources, ReleaseProofSources):
        raise TypeError("sources must be ReleaseProofSources")
    if path_capability is not None:
        require_attested_directory(path_capability, error_type=ReleaseProofError)
    authorization = context.authorization
    receipt = authorization.receipt
    if receipt is None or not authorization.executable:
        raise ReleaseProofError("proof export requires an executable receipt")
    if not _sha256(context.result_digest):
        raise ReleaseProofError("adapter result digest is invalid")

    output = sources.output_directory

    checkpoint_report = sources.audit_store.verify_checkpointed_chain()
    if not sources.audit_store.strict_integrity_ready or not checkpoint_report.get("valid"):
        raise ReleaseProofError("release audit is not strict-integrity ready")
    events = list(sources.audit_store.iter_events())
    _target_event, authorization_events, lifecycle_events = _release_audit_partition(
        events,
        receipt=receipt,
        request={"requested_at": context.request.requested_at},
        policy_version=sources.policy_snapshot.policy_version,
    )
    checkpoint = sources.audit_anchor.read(sources.audit_namespace)
    if checkpoint is None or checkpoint.to_dict() != checkpoint_report.get("checkpoint"):
        raise ReleaseProofError("caller-owned audit checkpoint does not match release audit")
    lifecycle_trust = _release_lifecycle_trust(lifecycle_events, checkpoint)

    # The generic ReplaySideStore intentionally skips malformed records for
    # best-effort lookup.  A release proof has a stronger contract: consume the
    # entire file once, canonically, and require exact ordered coverage.
    replay_raw = (
        path_capability.read_bytes(
            path_capability.relative_from_display(sources.replay_store.path),
            max_size=_MAX_FILE_SIZE,
        )
        if path_capability is not None
        else _secure_read_file(sources.replay_store.path, "release replay store")
    )
    side_records = _strict_jsonl(replay_raw, "release replay store")
    event_ids = [
        _required_text(event.get("event_id"), "audit.event_id") for event in authorization_events
    ]
    side_ids = [
        _required_text(record.get("event_id"), "replay.event_id") for record in side_records
    ]
    if (
        side_ids != event_ids
        or any(record.get("redacted") is True for record in side_records)
        or len(side_records) != len(authorization_events)
    ):
        raise ReleaseProofError(
            "strict release replay must exactly cover every authorization event in order"
        )

    if not sources.consumption_store.strict_integrity_ready:
        raise ReleaseProofError("release consumption store is not strict-integrity ready")
    status = sources.consumption_store.status(context.request.tenant_id, receipt.receipt_id)
    if status is None or status.state is not ConsumptionState.SUCCEEDED:
        raise ReleaseProofError("receipt consumption is not SUCCEEDED")
    anchored = sources.consumption_anchor.read(sources.consumption_namespace)
    if anchored is None:
        raise ReleaseProofError("caller-owned consumption anchor is unavailable")
    if not sources.consumption_store.strict_integrity_ready:
        raise ReleaseProofError("consumption state changed during proof export")

    request_payload = {
        "schema": "gove-zone.release-request-redacted/v1",
        "request_id": context.request.request_id,
        "tenant_id": context.request.tenant_id,
        "actor_id": context.request.actor_id,
        "actor_role": context.request.actor_role,
        "authority": context.request.authority,
        "server_id": context.request.server_id,
        "tool": context.request.tool,
        "operation": context.request.operation,
        "resource": context.request.resource,
        "environment": context.request.environment,
        "execution_boundary": context.request.execution_boundary,
        "policy_ref": context.request.policy_ref.to_dict(),
        "requested_at": context.request.requested_at,
        "args": _plain(context.request.args),
        "evidence": [item.to_dict() for item in context.request.evidence],
        "side_effect_class": context.request.side_effect_class,
        "goal_claim": receipt.declared_goal,
    }
    summary_unsigned: dict[str, Any] = {
        "schema": CONSUMPTION_SUMMARY_SCHEMA,
        "tenant_id": context.request.tenant_id,
        "receipt_id": receipt.receipt_id,
        "state": ConsumptionState.SUCCEEDED.value,
        "adapter_result_digest": context.result_digest,
        "store_id": anchored.store_id,
        "generation": anchored.generation,
        "chain_head": anchored.chain_head,
        "state_root": anchored.state_root,
        "anchor_namespace": sources.consumption_namespace,
        "evidence_mode": CONSUMPTION_EVIDENCE_MODE,
        "key_id": sources.consumption_signer.key_id,
        "algorithm": sources.consumption_signer.algorithm,
    }
    signature = sources.consumption_signer.sign(_summary_payload(summary_unsigned))
    summary = {**summary_unsigned, "signature": signature}

    payloads = {
        "audit-checkpoint.json": _json_bytes(checkpoint.to_dict()),
        "audit.jsonl": _jsonl_bytes(events),
        "consumption-summary.json": _json_bytes(summary),
        "lifecycle-trust.json": _json_bytes(lifecycle_trust),
        "policy.json": (sources.policy_snapshot.canonical_artifact + "\n").encode("utf-8"),
        "receipt.json": _json_bytes(receipt.to_dict()),
        "replay.jsonl": _jsonl_bytes(side_records),
        "request.json": _json_bytes(request_payload),
    }
    directory_opener = (
        path_capability.open_directory_path if path_capability is not None else _open_directory
    )
    identity_assertion = (
        path_capability.assert_path_identity
        if path_capability is not None
        else _assert_path_identity
    )
    _, pack_digest = _RELEASE_PACK_CODEC.export_new_pack(
        output,
        payloads,
        open_directory=directory_opener,
        read_file_at=_read_file_at,
        write_new_at=_write_new_at,
        assert_membership=_assert_exact_membership,
        assert_path_identity=identity_assertion,
    )
    return ReleaseProofPack(output, pack_digest, receipt.receipt_id)


def verify_release_proof_pack(
    directory: str | Path,
    *,
    receipt_public_key: str | Path,
    checkpoint_public_key: str | Path,
    consumption_public_key: str | Path,
    lifecycle_public_key: str | Path,
    expected_pack_digest: str,
    path_capability: AttestedDirectory | None = None,
) -> ReleaseProofVerification:
    """Strongly verify a pack using only external trust roots and digest pins."""

    if path_capability is not None:
        require_attested_directory(path_capability, error_type=ReleaseProofError)
    expected = _required_sha256(expected_pack_digest, "expected_pack_digest")
    root = Path(directory)
    directory_opener = (
        path_capability.open_directory_path if path_capability is not None else _open_directory
    )
    identity_assertion = (
        path_capability.assert_path_identity
        if path_capability is not None
        else _assert_path_identity
    )
    codec, raw = read_exact_pack_by_schema(
        root,
        {
            PROOF_PACK_SCHEMA: _RELEASE_PACK_CODEC,
            DISASTER_PROOF_PACK_SCHEMA: _RELEASE_DISASTER_PACK_CODEC,
        },
        open_directory=directory_opener,
        read_file_at=_read_file_at,
        assert_membership=_assert_exact_membership,
        assert_path_identity=identity_assertion,
    )
    if codec is _RELEASE_DISASTER_PACK_CODEC:
        return _verify_release_disaster_pack(
            root,
            raw,
            receipt_public_key=receipt_public_key,
            checkpoint_public_key=checkpoint_public_key,
            consumption_public_key=consumption_public_key,
            lifecycle_public_key=lifecycle_public_key,
            expected_pack_digest=expected,
            path_capability=path_capability,
        )
    manifest = _strict_json(raw["manifest.json"], "manifest.json")
    if type(manifest) is not dict or set(manifest) != {
        "schema",
        "pack_digest",
        "files",
        "verification",
    }:
        raise ReleaseProofError("manifest has an incompatible shape")
    if manifest["schema"] != PROOF_PACK_SCHEMA or manifest["pack_digest"] != expected:
        raise ReleaseProofError("manifest schema or expected digest mismatch")
    files = manifest["files"]
    if type(files) is not list or len(files) != len(_PAYLOAD_FILES):
        raise ReleaseProofError("manifest file list is incompatible")
    entries = _manifest_entries({name: raw[name] for name in _PAYLOAD_FILES})
    verification = manifest.get("verification")
    expected_verification = _verification_metadata()
    manifest_payload = {
        "schema": manifest["schema"],
        "files": files,
        "verification": verification,
    }
    if (
        files != entries
        or verification != expected_verification
        or not hmac.compare_digest(_pack_digest(manifest_payload), expected)
    ):
        raise ReleaseProofError("manifest hashes, sizes, media types, or pack digest mismatch")

    request = _strict_json(raw["request.json"], "request.json")
    receipt_data = _strict_json(raw["receipt.json"], "receipt.json")
    policy_data = _strict_json(raw["policy.json"], "policy.json")
    checkpoint_data = _strict_json(raw["audit-checkpoint.json"], "audit-checkpoint.json")
    summary = _strict_json(raw["consumption-summary.json"], "consumption-summary.json")
    lifecycle_trust = _strict_json(raw["lifecycle-trust.json"], "lifecycle-trust.json")
    events = _strict_jsonl(raw["audit.jsonl"], "audit.jsonl")
    side_records = _strict_jsonl(raw["replay.jsonl"], "replay.jsonl")
    if type(request) is not dict or set(request) != _REQUEST_KEYS:
        raise ReleaseProofError("request has an incompatible redacted shape")
    if type(receipt_data) is not dict or set(receipt_data) != _RECEIPT_KEYS:
        raise ReleaseProofError("receipt wire keys are incompatible")
    if type(policy_data) is not dict or set(policy_data) != {"kind", "version", "requirements"}:
        raise ReleaseProofError("policy artifact has an incompatible shape")
    if type(checkpoint_data) is not dict or set(checkpoint_data) != _CHECKPOINT_KEYS:
        raise ReleaseProofError("audit checkpoint has an incompatible shape")
    if type(summary) is not dict or set(summary) != _SUMMARY_KEYS:
        raise ReleaseProofError("consumption summary has an incompatible shape")
    if type(lifecycle_trust) is not dict or set(lifecycle_trust) != _LIFECYCLE_TRUST_KEYS:
        raise ReleaseProofError("lifecycle trust metadata has an incompatible shape")
    if not events or not side_records:
        raise ReleaseProofError("proof pack requires nonempty audit/replay evidence")
    event_ids = [_required_text(item.get("event_id"), "audit.event_id") for item in events]
    side_ids = [_required_text(item.get("event_id"), "replay.event_id") for item in side_records]
    if len(set(event_ids)) != len(event_ids) or len(set(side_ids)) != len(side_ids):
        raise ReleaseProofError("audit/replay identifiers are not unique")

    receipt = DecisionReceipt.from_dict(cast(dict[str, Any], receipt_data))
    receipt_verifier = _public_key(
        receipt_public_key,
        receipt.signing_key_id,
        path_capability=path_capability,
    )
    checkpoint = _checkpoint(cast(dict[str, Any], checkpoint_data))
    checkpoint_verifier = _public_key(
        checkpoint_public_key,
        checkpoint.key_id,
        path_capability=path_capability,
    )
    try:
        checkpoint_signature_valid = checkpoint_verifier.verify(
            checkpoint.signing_payload(), checkpoint.signature
        )
    except Exception as exc:
        raise ReleaseProofError("audit checkpoint signature verification failed") from exc
    if checkpoint_signature_valid is not True:
        raise ReleaseProofError("audit checkpoint signature is invalid under external key")
    consumption_verifier = _public_key(
        consumption_public_key,
        _required_text(summary.get("key_id"), "summary.key_id"),
        path_capability=path_capability,
    )
    expected_checkpoint_authority = f"audit-checkpoint:{checkpoint.namespace}"
    if (
        lifecycle_trust.get("schema") != LIFECYCLE_TRUST_SCHEMA
        or lifecycle_trust.get("checkpoint_authority_id") != expected_checkpoint_authority
        or lifecycle_trust.get("authority_id")
        in {
            "audit-checkpoint",
            expected_checkpoint_authority,
        }
        or lifecycle_trust.get("key_id") == checkpoint.key_id
        or lifecycle_trust.get("algorithm") != "ed25519"
    ):
        raise ReleaseProofError("lifecycle/checkpoint trust separation is invalid")
    lifecycle_verifier = _public_key(
        lifecycle_public_key,
        _required_text(lifecycle_trust.get("key_id"), "lifecycle.key_id"),
        path_capability=path_capability,
    )
    try:
        lifecycle_verifiers = LifecycleVerifierRegistry(
            {
                _required_text(
                    lifecycle_trust.get("authority_id"), "lifecycle.authority_id"
                ): lifecycle_verifier
            }
        )
    except (TypeError, ValueError) as exc:
        raise ReleaseProofError("lifecycle verifier registry is invalid") from exc

    policy = _policy(cast(dict[str, Any], policy_data))
    snapshot = PolicyArtifactSnapshot.from_artifact(
        cast(dict[str, Any], policy_data), evaluator=policy
    )
    policy_ref = request.get("policy_ref")
    if type(policy_ref) is not dict or set(policy_ref) != {
        "tenant_id",
        "bundle_id",
        "version",
        "digest",
    }:
        raise ReleaseProofError("request policy reference is incompatible")
    args = request.get("args")
    if type(args) is not dict:
        raise ReleaseProofError("request args must be an object")
    event, authorization_events, lifecycle_events = _release_audit_partition(
        events,
        receipt=receipt,
        request=cast(dict[str, Any], request),
        policy_version=snapshot.policy_version,
    )
    authorization_ids = [
        _required_text(item.get("event_id"), "audit.event_id") for item in authorization_events
    ]
    if side_ids != authorization_ids:
        raise ReleaseProofError("audit/replay authorization coverage diverges")
    # The issuance checkpoint generation counts every committed record, so it is
    # the authorization's position in the full chain — not its position among the
    # policy decisions, which interleaved refusals no longer make equal.
    target_positions = [
        index
        for index, item in enumerate(events)
        if item.get("event_id") == receipt.receipt_id
        and item.get("event_hash") == receipt.audit_event_hash
    ]
    if len(target_positions) != 1:
        raise ReleaseProofError("release authorization audit event is missing or ambiguous")
    target_generation = target_positions[0] + 1
    binding = receipt.constraints.get(SIDE_EFFECT_BINDING_KEY)
    issuance_wire = binding.get("audit_checkpoint") if type(binding) is dict else None
    if type(issuance_wire) is not dict or set(issuance_wire) != _CHECKPOINT_KEYS | {
        "checkpoint_hash"
    }:
        raise ReleaseProofError("receipt issuance checkpoint binding is incompatible")
    issuance_checkpoint = _checkpoint({name: issuance_wire[name] for name in _CHECKPOINT_KEYS})
    try:
        issuance_signature_valid = checkpoint_verifier.verify(
            issuance_checkpoint.signing_payload(), issuance_checkpoint.signature
        )
    except Exception as exc:
        raise ReleaseProofError("receipt issuance checkpoint signature failed") from exc
    if (
        issuance_signature_valid is not True
        or issuance_wire["checkpoint_hash"] != issuance_checkpoint.checkpoint_hash
        or issuance_checkpoint.namespace != checkpoint.namespace
        or issuance_checkpoint.key_id != checkpoint.key_id
        or issuance_checkpoint.generation != target_generation
        or issuance_checkpoint.head_hash != event["event_hash"]
    ):
        raise ReleaseProofError("receipt issuance checkpoint does not bind the authorization")
    side = side_records[-1]
    event_id = _required_text(event.get("event_id"), "audit.event_id")
    if (
        event_id != receipt.receipt_id
        or side.get("event_id") != event_id
        or receipt.request_id != request.get("request_id")
        or side.get("args") != args
        or side.get("tool") != RELEASE_GATE_OPERATION
        or request.get("operation") != RELEASE_GATE_OPERATION
        or event.get("tool") != RELEASE_GATE_OPERATION
        or receipt.decision != "allow"
        or event.get("decision") != "allow"
        or side.get("decision") != "allow"
        or event.get("event_hash") != receipt.audit_event_hash
        or event.get("previous_hash") != receipt.previous_audit_hash
        or event.get("argument_hash") != strict_json_hash(args)
        or side.get("argument_hash") != event.get("argument_hash")
        or event.get("actor") != request.get("actor_id")
        or event.get("policy_version") != snapshot.policy_version
        or event.get("timestamp_iso") != receipt.timestamp
        or side.get("actor") != request.get("actor_id")
        or side.get("policy_version") != snapshot.policy_version
        or request.get("server_id") != RELEASE_GATE_SERVER_ID
        or request.get("tool") != RELEASE_GATE_TOOL
        or request.get("execution_boundary") != RELEASE_GATE_EXECUTION_BOUNDARY
        or request.get("side_effect_class") != RELEASE_GATE_SIDE_EFFECT_CLASS
        or args.get("approval_identity") != receipt.validator_id
    ):
        raise ReleaseProofError("request, receipt, audit, and replay identifiers diverge")
    if (
        policy_ref.get("digest") != snapshot.digest
        or policy_ref.get("version") != snapshot.policy_version
        or policy_ref.get("bundle_id") != receipt.policy_bundle_id
        or policy_ref.get("tenant_id") != request.get("tenant_id")
    ):
        raise ReleaseProofError("policy artifact does not match its full external pins")

    expected_constraints = _validated_constraints(
        receipt=receipt,
        request=cast(dict[str, Any], request),
        policy_ref=cast(dict[str, Any], policy_ref),
        checkpoint=issuance_checkpoint,
        args=cast(dict[str, Any], args),
    )
    try:
        receipt.verify(
            expected_tenant_id=_required_text(request.get("tenant_id"), "request.tenant_id"),
            expected_execution_boundary=_required_text(
                request.get("execution_boundary"), "request.execution_boundary"
            ),
            expected_audit_hash=_required_sha256(event.get("event_hash"), "audit.event_hash"),
            expected_args=cast(dict[str, Any], args),
            expected_action=RELEASE_GATE_OPERATION,
            expected_policy_hash=snapshot.digest,
            expected_policy_bundle_id=_required_text(
                policy_ref.get("bundle_id"), "policy.bundle_id"
            ),
            expected_policy_version=snapshot.policy_version,
            expected_validator_id=receipt.validator_id,
            expected_validator_role=receipt.validator_role,
            expected_authority=_required_text(request.get("authority"), "request.authority"),
            expected_constraints=expected_constraints,
            expected_request_id=_required_text(request.get("request_id"), "request.request_id"),
            expected_actor=_required_text(request.get("actor_id"), "request.actor_id"),
            verifier={receipt_verifier.key_id: receipt_verifier},
            require_signature=True,
            now_iso=receipt.timestamp,
        )
    except Exception as exc:
        raise ReleaseProofError(f"receipt verification failed: {exc}") from exc
    _verify_historical_times(request, receipt)

    anchor = _ReadOnlyAuditAnchor(checkpoint)
    with tempfile.TemporaryDirectory(prefix="gove-zone-release-proof-") as temp:
        temp_root = Path(temp)
        audit_path = temp_root / "audit.jsonl"
        replay_path = temp_root / "replay.jsonl"
        _write_new(audit_path, raw["audit.jsonl"])
        _write_new(replay_path, raw["replay.jsonl"])
        try:
            audit_store = ChainHashAuditStore(
                audit_path,
                checkpoint_anchor=anchor,
                checkpoint_namespace=checkpoint.namespace,
                checkpoint_verifier={checkpoint_verifier.key_id: checkpoint_verifier},
                require_trusted_checkpoint=True,
            )
            replay = replay_checkpointed_bundle(
                audit_store,
                ReplaySideStore(replay_path),
                policy,
                lifecycle_verifiers=lifecycle_verifiers,
            )
        except Exception as exc:
            raise ReleaseProofError(f"checkpointed audit verification failed: {exc}") from exc
    expected_lifecycle_count = len(lifecycle_events)
    if not (
        replay.get("valid") is True
        and replay.get("strict") is True
        and replay.get("checkpoint_valid") is True
        and replay.get("events_degraded") == 0
        and replay.get("events_total") == len(authorization_events)
        and replay.get("events_matched") == len(authorization_events)
        and replay.get("lifecycle_events_total") == expected_lifecycle_count
        and replay.get("mismatches") == []
    ):
        raise ReleaseProofError("strict checkpointed replay failed")

    replay = {**replay, "lifecycle_events_verified": expected_lifecycle_count}

    _verify_summary(summary, receipt, consumption_verifier)
    return ReleaseProofVerification(
        True,
        expected,
        receipt.receipt_id,
        replay,
        CONSUMPTION_EVIDENCE_MODE,
    )


def replay_release_proof_pack(**kwargs: Any) -> ReleaseProofVerification:
    """Alias emphasizing that strong verification always includes strict replay."""

    return verify_release_proof_pack(**kwargs)


def _export_release_denial_bundle(
    directory: Path,
    *,
    audit: ChainHashAuditStore,
    audit_anchor: Any,
    audit_namespace: str,
) -> None:
    """Write a minimal, externally verifiable audit bundle for one denial.

    A denied release produces no proof pack (there is no confirmed side effect),
    so the honest artifact is the audit evidence itself: the full committed
    chain plus its signed head checkpoint. Both are consumed by
    :func:`verify_release_denial_evidence` against separately loaded public keys.
    """

    checkpoint = audit_anchor.read(audit_namespace)
    if checkpoint is None:
        raise ReleaseProofError("denial bundle requires a trusted audit checkpoint")
    fd, identity = _open_or_create_empty_directory(directory)
    os.close(fd)
    _assert_path_identity(directory, identity)
    events = list(audit.iter_events())
    _write_new(directory / "audit.jsonl", _jsonl_bytes(events))
    _write_new(directory / "audit-checkpoint.json", _json_bytes(checkpoint.to_dict()))


def _execution_refusal_evidence_from_wire(wire: Mapping[str, Any]) -> ExecutionRefusalEvidence:
    """Reconstruct signed/audited refusal evidence from a response wire object.

    The response only supplies *claims*; whether they are real is decided by
    verifying the reconstructed evidence's signature under a separately loaded
    public key and its audited inclusion in the independently checkpointed chain.
    """

    if type(wire) is not dict:
        raise ReleaseProofError("refusal evidence wire must be an object")
    try:
        return ExecutionRefusalEvidence(
            request_id_digest=cast(str, wire["request_id_digest"]),
            receipt_id_digest=cast(str, wire["receipt_id_digest"]),
            receipt_hash=cast(str, wire["receipt_hash"]),
            tenant_digest=cast(str, wire["tenant_digest"]),
            execution_boundary_digest=cast(str, wire["execution_boundary_digest"]),
            adapter_id_digest=cast(str, wire["adapter_id_digest"]),
            authorization_audit_digest=cast(str, wire["authorization_audit_digest"]),
            binding_hash=cast(str, wire["binding_hash"]),
            argument_hash=cast(str, wire["argument_hash"]),
            reason_code=ExecutionReasonCode(wire["reason_code"]),
            phase=ExecutionRefusalPhase(wire["phase"]),
            audited=bool(wire["audited"]),
            adapter_invoked=bool(wire.get("adapter_invoked", False)),
            attempt_id_digest=cast(str, wire.get("attempt_id_digest", "")),
            audit_event_id=cast(str, wire.get("audit_event_id", "")),
            audit_event_hash=cast(str, wire.get("audit_event_hash", "")),
            audit_checkpoint_hash=cast(str, wire.get("audit_checkpoint_hash", "")),
            audit_checkpoint_parent_hash=cast(str, wire.get("audit_checkpoint_parent_hash", "")),
            signed=bool(wire.get("signed", False)),
            signing_key_id=cast(str, wire.get("signing_key_id", "")),
            signature_algorithm=cast(str, wire.get("signature_algorithm", "")),
            signature=cast(str, wire.get("signature", "")),
            payload_hash=cast(str, wire.get("payload_hash", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseProofError("refusal evidence wire is malformed") from exc


def verify_release_denial_evidence(
    bundle_directory: str | Path,
    *,
    refusal_evidence: Mapping[str, Any],
    checkpoint_public_key: str | Path,
    lifecycle_public_key: str | Path,
) -> dict[str, Any]:
    """Independently re-verify one denial's refusal evidence.

    Reuses only the repository's own trust facilities — no parallel crypto:

    * the audit chain and its head checkpoint are re-verified inside a fresh
      strict :class:`ChainHashAuditStore` that trusts *only* the separately
      loaded external checkpoint public key;
    * the reconstructed :class:`ExecutionRefusalEvidence` signature is verified
      under the separately loaded external lifecycle public key; and
    * its audited inclusion is proved by
      :meth:`ExecutionRefusalEvidence.verify_integrity` against that chain.

    ``valid`` is True only when all three hold. A tampered chain, checkpoint
    signature, or refusal signature makes it fail closed rather than raise.
    """

    root = Path(bundle_directory)
    audit_bytes = _secure_read_file(root / "audit.jsonl", "denial audit log")
    checkpoint_bytes = _secure_read_file(root / "audit-checkpoint.json", "denial checkpoint")
    # The refusal evidence is the response's own claims; a structurally malformed
    # wire is a caller contract error and raises. Everything integrity-bearing
    # below (checkpoint parse, key load, chain, signatures) fails *closed* to
    # ``valid: False`` — a tampered chain, checkpoint, or signature is a negative
    # verdict, never an exception.
    evidence = _execution_refusal_evidence_from_wire(refusal_evidence)
    if not evidence.audited or not evidence.audit_event_id:
        raise ReleaseProofError("denial refusal evidence is not independently checkable")

    chain_valid = False
    signature_valid = False
    audit_inclusion_valid = False
    checkpoint_key_id = ""
    try:
        checkpoint_raw = json.loads(checkpoint_bytes.decode("utf-8"))
        if type(checkpoint_raw) is not dict or set(checkpoint_raw) != _CHECKPOINT_KEYS:
            raise ReleaseProofError("denial checkpoint has an incompatible shape")
        checkpoint = _checkpoint(cast(dict[str, Any], checkpoint_raw))
        checkpoint_key_id = checkpoint.key_id
        checkpoint_verifier = _public_key(checkpoint_public_key, checkpoint.key_id)
        lifecycle_verifier = _public_key(lifecycle_public_key, evidence.signing_key_id)
        with tempfile.TemporaryDirectory(prefix="gove-zone-denial-verify-") as temp:
            audit_path = Path(temp) / "audit.jsonl"
            _write_new(audit_path, audit_bytes)
            audit_store = ChainHashAuditStore(
                audit_path,
                checkpoint_anchor=_ReadOnlyAuditAnchor(checkpoint),
                checkpoint_namespace=checkpoint.namespace,
                checkpoint_verifier={checkpoint_verifier.key_id: checkpoint_verifier},
                require_trusted_checkpoint=True,
            )
            chain = audit_store.verify_checkpointed_chain()
            chain_valid = bool(chain.get("valid")) and bool(chain.get("strict"))
            # The two proofs are checked INDEPENDENTLY and both must hold; the
            # refusal's lifecycle signature never short-circuits the audit path.
            #  * signature_valid: the refusal is signed by the separately loaded
            #    lifecycle public key.
            #  * audit_inclusion_valid: the exact EXECUTION_REFUSAL record is
            #    committed in the strict externally-checkpointed chain and every
            #    checkpoint/event/hash binding in the SIGNED evidence matches the
            #    independently re-verified chain. ``verify_integrity`` is called
            #    with ``audit`` only (no ``verifier``) so a valid signature can
            #    NOT stand in for inclusion: an attacker who rewrites an earlier
            #    audit event, rechains, and re-signs a replacement checkpoint —
            #    with a new key id or the same key id — leaves the uncompromised
            #    signed refusal still binding the ORIGINAL checkpoint/event hash,
            #    which no longer matches the rechained chain, so inclusion fails.
            signature_valid = bool(evidence.verify_signature(lifecycle_verifier))
            audit_inclusion_valid = bool(evidence.verify_integrity(audit=audit_store))
    except Exception:
        # A tampered chain, checkpoint signature, or refusal signature makes
        # independent verification fail closed rather than raise.
        pass
    valid = bool(chain_valid and signature_valid and audit_inclusion_valid)
    return {
        "valid": valid,
        "refusal_event_id": evidence.audit_event_id,
        "reason_code": evidence.reason_code.value,
        "phase": evidence.phase.value,
        "chain_valid": chain_valid,
        "signature_valid": signature_valid,
        "audit_inclusion_valid": audit_inclusion_valid,
        "checkpoint_key_id": checkpoint_key_id,
        "lifecycle_key_id": evidence.signing_key_id,
        "verification_mode": "external-ed25519-keys-and-strict-checkpointed-chain",
    }


def generate_release_reference_demo(
    output: Path,
    *,
    pre_capture_tamper: bool = False,
) -> dict[str, Any]:
    """Run the P0 reference against a fixed local fixture (CLI-friendly).

    With ``pre_capture_tamper`` the on-disk artifact is replaced, after the
    receipted digest is fixed to the approved bytes, with bytes that do not
    match it. The kernel's post-authorization capture then recomputes a
    different digest and refuses at the last controllable boundary, producing
    the structured FAILED_CLOSED denial whose refusal evidence is independently
    re-verified in-process.
    """

    output = Path(output)
    fd, identity = _open_or_create_empty_directory(output)
    os.close(fd)
    _assert_path_identity(output, identity)
    artifact_dir = output / "artifact"
    artifact_fd, _ = _open_or_create_empty_directory(artifact_dir)
    os.close(artifact_fd)
    artifact_path = artifact_dir / "release.whl"
    good_bytes = b"fixture-gove-zone-reference-wheel-v1\n"
    _write_new(artifact_path, good_bytes)
    binding = ReleaseReferenceBinding(
        repository="fixture/acgs-reference",
        ref="refs/heads/main",
        branch="main",
        commit_sha="1" * 40,
        workflow_identity=(
            "github-actions:fixture/acgs-reference/.github/workflows/"
            "p0-release-gate-reference.yml@refs/heads/main"
        ),
        artifact_digest=hashlib.sha256(good_bytes).hexdigest(),
        environment="production",
        deployment_target="fixture://github-actions/p0-release",
        approval_identity="fixture-reference-approver",
        approval_evidence_digest="3" * 64,
        security_evidence_digest="4" * 64,
        tests_evidence_digest="5" * 64,
    )
    reference = ReleaseReferenceInput(
        approved=binding,
        requested=binding,
        artifact_path=artifact_path,
        request_id="p0-reference-demo-request-1",
        tenant_id="fixture-github-tenant",
        actor_id="fixture-release-agent",
        actor_role="release-agent",
        authority="release.deploy",
        evidence_issuer="fixture-github-actions-reference",
        evidence_verifier_id="fixture-reference-verifier",
        validator_role="approver",
        requested_at="2026-07-14T17:59:59Z",
        observed_at="2026-07-14T18:00:00Z",
        principal_verified_at="2026-07-14T17:00:00Z",
        principal_expires_at="2026-07-14T19:00:00Z",
        evidence_issued_at="2026-07-14T17:55:00Z",
        evidence_expires_at="2026-07-14T19:00:00Z",
        nonce="reference-demo-nonce-must-not-export",
        idempotency_key="reference-demo-idempotency-must-not-export",
    )
    if pre_capture_tamper:
        artifact_path.write_bytes(b"pre-capture-reference-tamper\n")
    return generate_release_reference(output / "reference-run", reference)


def _reference_claim(
    binding: ReleaseReferenceBinding,
    *,
    evidence_type: str,
    digest: str,
    issuer: str,
    verifier_id: str,
    issued_at: str,
    expires_at: str,
) -> ReleaseEvidenceClaim:
    evidence = EvidenceRef(
        evidence_id=f"p0-reference-{evidence_type}-{digest[:16]}",
        evidence_type=evidence_type,
        digest=digest,
        issuer=issuer,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return ReleaseEvidenceClaim(
        evidence=evidence,
        repository=binding.repository,
        ref=binding.ref,
        commit_sha=binding.commit_sha,
        artifact_digest=binding.artifact_digest,
        workflow_identity=binding.workflow_identity,
        verifier_id=verifier_id,
        signature=f"fixture-only:{evidence_type}:{digest}",
    )


def _reference_deployment(
    binding: ReleaseReferenceBinding,
    *,
    issuer: str,
    verifier_id: str,
    issued_at: str,
    expires_at: str,
) -> ReleaseDeployment:
    evidence = tuple(
        _reference_claim(
            binding,
            evidence_type=evidence_type,
            digest=digest,
            issuer=issuer,
            verifier_id=verifier_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        for evidence_type, digest in (
            ("approval", binding.approval_evidence_digest),
            ("security-scan", binding.security_evidence_digest),
            ("tests", binding.tests_evidence_digest),
        )
    )
    return ReleaseDeployment(
        repository=binding.repository,
        ref=binding.ref,
        branch=binding.branch,
        commit_sha=binding.commit_sha,
        workflow_identity=binding.workflow_identity,
        artifact_digest=binding.artifact_digest,
        environment=binding.environment,
        deployment_target=binding.deployment_target,
        approval_identity=binding.approval_identity,
        evidence=evidence,
    )


def generate_release_reference(
    output: Path,
    reference: ReleaseReferenceInput,
) -> dict[str, Any]:
    """Run the P0 GitHub/local reference against one gated fixture adapter.

    This is intentionally not a deploy command.  It creates the existing
    release policy, shared authorization kernel, schema-v4 executor,
    consumption ledger, audit/replay stores and proof exporter, then invokes
    the mock adapter *only* through :meth:`ReleaseGate.deploy`.
    """

    from gove_zone.authorization import (
        ExecutionReasonCode,
        ExecutionRefusalPhase,
        PolicyArtifactAttestation,
        ResolvedPolicy,
        ResolvedPolicyRef,
        SideEffectExecutionError,
        VerifiedPrincipal,
    )
    from gove_zone.receipt import Validator
    from gove_zone.side_effect_kernel import (
        AdapterOutcome,
        AdapterOutcomeStatus,
        ReceiptGatedSideEffectExecutor,
        SideEffectAuthorizationKernel,
    )

    if not isinstance(reference, ReleaseReferenceInput):
        raise TypeError("reference must be ReleaseReferenceInput")
    output = Path(output)
    output_fd, output_identity = _open_or_create_empty_directory(output)
    os.close(output_fd)
    _assert_path_identity(output, output_identity)
    runtime = output / "runtime"
    keys = output / "external-keys"
    runtime_fd, _ = _open_or_create_empty_directory(runtime)
    os.close(runtime_fd)
    keys_fd, _ = _open_or_create_empty_directory(keys)
    os.close(keys_fd)
    pack_dir = output / "proof-pack"

    # Deterministic fixture keys keep this reference reproducible.  No private
    # key is written to disk and the report is explicitly fixture-only.
    receipt_signer = Ed25519Signer.from_private_bytes(b"\x31" * 32, "p0-reference-release-key")
    lifecycle_signer = Ed25519Signer.from_private_bytes(b"\x33" * 32, "p0-reference-lifecycle-key")
    consumption_signer = Ed25519Signer.from_private_bytes(
        b"\x32" * 32, "p0-reference-consumption-key"
    )
    receipt_key = keys / "receipt-ed25519.pub"
    checkpoint_key = keys / "checkpoint-ed25519.pub"
    consumption_key = keys / "consumption-ed25519.pub"
    lifecycle_key = keys / "lifecycle-ed25519.pub"
    _write_new(receipt_key, receipt_signer.public_bytes())
    _write_new(checkpoint_key, receipt_signer.public_bytes())
    _write_new(consumption_key, consumption_signer.public_bytes())
    _write_new(lifecycle_key, lifecycle_signer.public_bytes())

    approved = _reference_deployment(
        reference.approved,
        issuer=reference.evidence_issuer,
        verifier_id=reference.evidence_verifier_id,
        issued_at=reference.evidence_issued_at,
        expires_at=reference.evidence_expires_at,
    )
    requested = _reference_deployment(
        reference.requested,
        issuer=reference.evidence_issuer,
        verifier_id=reference.evidence_verifier_id,
        issued_at=reference.evidence_issued_at,
        expires_at=reference.evidence_expires_at,
    )
    requirements = ReleaseGateRequirements(
        required_evidence_claims=tuple(
            ReleaseEvidenceRequirement.from_claim(item) for item in approved.evidence
        ),
        environment_targets={approved.environment: (approved.deployment_target,)},
        production_branches=(approved.branch,),
        production_environment=approved.environment,
        allowed_repositories=(approved.repository,),
        allowed_workflow_identities=(approved.workflow_identity,),
        require_separation_of_duties=True,
    )
    policy = ReleaseGatePolicy(requirements)
    snapshot = policy.authorization_snapshot()
    policy_ref = ResolvedPolicyRef(
        tenant_id=reference.tenant_id,
        bundle_id="acgs-p0-release-reference-policy",
        version=snapshot.policy_version,
        digest=snapshot.digest,
    )
    principal = VerifiedPrincipal(
        tenant_id=reference.tenant_id,
        actor_id=reference.actor_id,
        role=reference.actor_role,
        authority=reference.authority,
        authentication_context={
            "method": "fixture-github-context",
            "workflow_identity": reference.requested.workflow_identity,
        },
        verified_at=reference.principal_verified_at,
        expires_at=reference.principal_expires_at,
    )
    resolved = ResolvedPolicy(
        ref=policy_ref,
        policy=policy,
        attestation=PolicyArtifactAttestation(
            tenant_id=policy_ref.tenant_id,
            artifact_id=policy_ref.bundle_id,
            policy_version=policy_ref.version,
            digest=policy_ref.digest,
            resolver_id="p0-reference-policy-resolver",
        ),
        validator=Validator(reference.approved.approval_identity, reference.validator_role),
        authority=reference.authority,
    )
    principal_resolver = _StaticPrincipalResolver(principal)
    policy_resolver = _StaticPolicyResolver(resolved)
    namespace_suffix = strict_json_hash(
        {"tenant_id": reference.tenant_id, "request_id": reference.request_id}
    )[:24]
    audit_anchor = _MemoryAuditAnchor()
    audit_namespace = f"p0-reference:release-audit:{namespace_suffix}"
    audit = ChainHashAuditStore(
        runtime / "audit.jsonl",
        checkpoint_anchor=audit_anchor,
        checkpoint_namespace=audit_namespace,
        checkpoint_signer=receipt_signer,
        checkpoint_verifier={receipt_signer.key_id: receipt_signer},
        require_trusted_checkpoint=True,
    )
    replay_store = ReplaySideStore(runtime / "replay.jsonl")
    consumption_anchor = _MemoryConsumptionAnchor()
    consumption_namespace = f"p0-reference:release-consumption:{namespace_suffix}"
    consumption = ReceiptConsumptionStore(
        runtime / "consumption.sqlite3",
        hmac_key=b"p0-reference-consumption-hmac-key-v1",
        state_anchor=consumption_anchor,
        anchor_namespace=consumption_namespace,
        require_trusted_anchor=True,
    )
    observed = _timestamp(reference.observed_at, "observed_at")
    authorizer = SideEffectAuthorizationKernel(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        signer=receipt_signer,
        binding_hmac_key=b"p0-reference-binding-hmac-key-v1!!",
        allowed_validator_roles=(reference.validator_role,),
        side_store=replay_store,
        clock=lambda: observed,
    )
    executor = ReceiptGatedSideEffectExecutor(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        consumption_store=consumption,
        verifier={receipt_signer.key_id: receipt_signer},
        lifecycle_signer=lifecycle_signer,
        lifecycle_authority_id=_LIFECYCLE_AUTHORITY_ID,
        binding_hmac_key=b"p0-reference-binding-hmac-key-v1!!",
        allowed_validator_roles=(reference.validator_role,),
        clock=lambda: observed,
    )
    exporter = ReleaseProofPackExporter(
        ReleaseProofSources(
            output_directory=pack_dir,
            policy_snapshot=snapshot,
            audit_store=audit,
            audit_anchor=audit_anchor,
            audit_namespace=audit_namespace,
            replay_store=replay_store,
            consumption_store=consumption,
            consumption_anchor=consumption_anchor,
            consumption_namespace=consumption_namespace,
            consumption_signer=consumption_signer,
        )
    )
    adapter_calls: list[dict[str, Any]] = []
    deployments: list[dict[str, Any]] = []

    def fixture_adapter(*, artifact_snapshot: Any, **arguments: Any) -> AdapterOutcome:
        # No rehash of the mutable source path happens here. The kernel already
        # proved, at the last controllable boundary and before the adapter latch,
        # that this exact snapshot's content digest equals the receipted
        # ``artifact_digest``. The simulated deployment consumes the captured
        # bytes and never reopens the original path, so a source mutation after
        # capture cannot change what is deployed.
        deployed = artifact_snapshot.bytes()
        adapter_calls.append(arguments)
        deployments.append(
            {
                "artifact_sha256": hashlib.sha256(deployed).hexdigest(),
                "artifact_bytes": len(deployed),
            }
        )
        return AdapterOutcome(
            AdapterOutcomeStatus.CONFIRMED_SUCCEEDED,
            {
                "deployment_id": "fixture-p0-release-reference",
                "status": "succeeded",
                "target": requested.deployment_target,
                "artifact_sha256": hashlib.sha256(deployed).hexdigest(),
                "artifact_bytes_deployed": len(deployed),
            },
        )

    gate = ReleaseGate(
        authorizer=authorizer,
        executor=executor,
        deployment_adapter=fixture_adapter,
        proof_sink=exporter,
    )
    # The artifact is never captured here. ReleaseGate forwards the source path
    # into the executor, which performs the fixed kernel-owned secure capture at
    # the last controllable boundary — after reservation and receipt
    # re-verification, before the adapter latch. A missing, symlinked,
    # hardlinked, oversize, unreadable, or post-approval-mutated source
    # therefore fails closed inside the executor with verifiable, pre-adapter
    # refusal evidence rather than an evidence-free product-level DENY.
    try:
        result = gate.deploy(
            requested,
            artifact_source=reference.artifact_path,
            request_id=reference.request_id,
            tenant_id=reference.tenant_id,
            actor_id=reference.actor_id,
            actor_role=reference.actor_role,
            authority=reference.authority,
            policy_ref=policy_ref,
            requested_at=reference.requested_at,
            observed_at=reference.observed_at,
            nonce=reference.nonce,
            idempotency_key=reference.idempotency_key,
            authentication_context=principal.authentication_context,
        )
    except ReleaseProofSinkError:
        return {
            "valid": False,
            "decision": "ALLOW",
            "status": "POST_EXECUTION_EVIDENCE_FAILED",
            "claim_boundary": "local-fixture-only-no-real-deployment",
            "reason_codes": ["P0_REFERENCE_PROOF_SINK_FAILED"],
            "adapter_calls": len(adapter_calls),
            "deployment_count": len(deployments),
            "side_effect_confirmed": True,
            "retry_safe": False,
            "do_not_retry": True,
            "policy_digest": snapshot.digest,
            "proof_pack": None,
        }
    except SideEffectExecutionError as exc:
        # An ambiguous outcome and a proven refusal are different claims and are
        # never merged. Once the adapter has been entered the executor sanitizes
        # its reason to OUTCOME_UNKNOWN/TIMEOUT and proves nothing.
        outcome_unknown = exc.reason_code in {
            ExecutionReasonCode.OUTCOME_UNKNOWN,
            ExecutionReasonCode.TIMEOUT,
        }
        adapter_attempted = bool(adapter_calls) or bool(deployments)
        if adapter_attempted and not outcome_unknown:
            # A provable pre-adapter refusal can never coexist with recorded
            # adapter side effects: that is a real invariant violation, not the
            # sanitized ambiguous outcome. An adapter that records or partially
            # attempts and *then* raises is sanitized to OUTCOME_UNKNOWN above
            # and reported structurally below, never as this hard error.
            raise ReleaseProofError("denied reference release reached the fixture adapter") from exc
        events = list(audit.iter_events())
        # The policy rules that denied the release live on the POLICY_DECISION
        # record. A refused attempt now also commits an EXECUTION_REFUSAL record
        # after it, whose matched_rules restate the execution reason code, so
        # reading the chain's tail reported "execution.not_executable" in place
        # of the rule that actually denied. Select the decision by kind, and keep
        # the authorization's own policy reason codes separate from the
        # execution reason code.
        policy_decision_event = next(
            (
                event
                for event in reversed(events)
                if event.get("record_kind", RecordKind.POLICY_DECISION.value)
                == RecordKind.POLICY_DECISION.value
            ),
            {},
        )
        matched = policy_decision_event.get("matched_rules", [])
        policy_reason_codes = list(matched) if type(matched) is list else []
        # The executor's own proof is reported verbatim; status fields report
        # only what the evidence actually carries. A refusal the executor could
        # not prove stays explicitly unproven; an UNKNOWN carries no evidence.
        refusal = None if outcome_unknown else exc.evidence
        # Two distinct POST_RESERVATION artifact refusals exist on this route:
        # a content mismatch (BINDING_MISMATCH) after a successful capture, and a
        # capture failure (INVALID_CONTEXT) for a missing/unsafe/oversize source.
        # The approval-identity check raises before execute and carries no
        # evidence, so a POST_RESERVATION phase disambiguates the artifact ones.
        artifact_digest_denied = (
            exc.reason_code is ExecutionReasonCode.BINDING_MISMATCH
            and refusal is not None
            and refusal.phase is ExecutionRefusalPhase.POST_RESERVATION
        )
        # A missing/unsafe/oversize source or a legacy call that supplied neither
        # a source nor a snapshot both surface as INVALID_CONTEXT with audited
        # refusal evidence, but at *different* phases: the kernel's post-reservation
        # capture (POST_RESERVATION) versus the pre-reservation shape precheck
        # (AUTHORIZATION_GATE). Both are the same product fact — no verifiable
        # release artifact snapshot was available — so both map to the exact
        # RELEASE_ARTIFACT_SNAPSHOT_UNAVAILABLE reason regardless of phase. The
        # reference runs on fixed valid fixtures, so an INVALID_CONTEXT refusal here
        # is always an absent/unusable artifact input; the authorization's own
        # policy reason codes stay separate on ``policy_reason_codes`` and the raw
        # execution.invalid_context stays on ``execution_reason_code``.
        artifact_source_denied = (
            exc.reason_code is ExecutionReasonCode.INVALID_CONTEXT
            and refusal is not None
            and refusal.phase
            in (
                ExecutionRefusalPhase.POST_RESERVATION,
                ExecutionRefusalPhase.AUTHORIZATION_GATE,
            )
        )
        if artifact_digest_denied:
            reason_codes = ["RELEASE_ARTIFACT_DIGEST_MISMATCH"]
        elif artifact_source_denied:
            reason_codes = ["RELEASE_ARTIFACT_SNAPSHOT_UNAVAILABLE"]
        elif outcome_unknown:
            reason_codes = [exc.reason_code.value]
        else:
            reason_codes = list(matched) if type(matched) is list else [exc.reason_code.value]
        # Independent denial verification: when the executor produced audited,
        # signed refusal evidence, export a compatible audit bundle and re-verify
        # the refusal here against separately loaded public keys and the existing
        # strict checkpointed audit chain + ExecutionRefusalEvidence facility —
        # never a parallel crypto path. The bundle + keys are exposed on the
        # response so the identical check reruns in a fresh process; the response
        # does not claim self-contained verification, it points at trust roots.
        independent: dict[str, Any] | None = None
        denial_bundle_dir: Path | None = None
        refusal_evidence_path: Path | None = None
        verify_denial_command: str | None = None
        if refusal is not None and refusal.audited and refusal.audit_event_id:
            denial_bundle_dir = output / "denial-evidence"
            try:
                _export_release_denial_bundle(
                    denial_bundle_dir,
                    audit=audit,
                    audit_anchor=audit_anchor,
                    audit_namespace=audit_namespace,
                )
                # Persist the exact refusal-evidence claims next to the bundle so a
                # fresh process re-runs the identical check from files alone. The
                # trust roots (checkpoint + lifecycle public keys) live in the
                # separate external-keys directory and are supplied to verify-denial
                # explicitly; they are never read from this untrusted bundle.
                refusal_evidence_path = output / "refusal-evidence.json"
                _write_new(refusal_evidence_path, _json_bytes(refusal.to_dict()))
                # Every path/token is shell-quoted so the emitted command is
                # executable verbatim even when the output directory contains
                # spaces or other shell metacharacters; a tampered input path
                # therefore cannot silently split into extra arguments.
                verify_denial_command = shlex.join(
                    (
                        "gove-zone",
                        "release",
                        "verify-denial",
                        "--bundle",
                        str(denial_bundle_dir),
                        "--refusal-evidence",
                        str(refusal_evidence_path),
                        "--checkpoint-public-key",
                        str(checkpoint_key),
                        "--lifecycle-public-key",
                        str(lifecycle_key),
                    )
                )
                independent = verify_release_denial_evidence(
                    denial_bundle_dir,
                    refusal_evidence=refusal.to_dict(),
                    checkpoint_public_key=checkpoint_key,
                    lifecycle_public_key=lifecycle_key,
                )
            except (ReleaseProofError, PathCapabilityError, OSError, ValueError) as verify_exc:
                independent = {
                    "valid": False,
                    "reason": "denial-bundle-export-or-verify-failed",
                    "error": str(verify_exc),
                }
        # ``authorization_decision`` reports whether authorization issued an
        # executable receipt, derived from the *authorization* outcome and never
        # from the execution status. Only a refusal whose reason proves the
        # authorization itself was not executable — a policy denial (NOT_EXECUTABLE)
        # or no authorization reaching the gate (MISSING_AUTHORIZATION) — is a DENY.
        # Every post-authorization outcome kept an executable receipt: a reserved
        # attempt refused at the artifact boundary (digest mismatch, capture, or
        # aggregate-budget failure) and an ambiguous adapter outcome all report
        # ALLOW. ``decision`` is the product's final side-effect verdict and never
        # claims a proven DENY for an ambiguous post-latch outcome: an UNKNOWN
        # execution is reported as UNKNOWN, a proven pre-side-effect refusal as
        # DENY. ``execution_status`` stays distinct (OUTCOME_UNKNOWN vs
        # FAILED_CLOSED).
        authorization_refused = exc.reason_code in {
            ExecutionReasonCode.NOT_EXECUTABLE,
            ExecutionReasonCode.MISSING_AUTHORIZATION,
        }
        authorization_decision = "DENY" if authorization_refused else "ALLOW"
        if outcome_unknown:
            decision = "UNKNOWN"
            execution_status = "OUTCOME_UNKNOWN"
        else:
            decision = "DENY"
            execution_status = "FAILED_CLOSED"
        response: dict[str, Any] = {
            "valid": False,
            "decision": decision,
            "authorization_decision": authorization_decision,
            "status": execution_status,
            "execution_status": execution_status,
            "claim_boundary": "local-fixture-only-no-real-deployment",
            "reason_codes": reason_codes,
            "policy_reason_codes": policy_reason_codes,
            "execution_reason_code": exc.reason_code.value,
            "outcome_unknown": outcome_unknown,
            "execution_refusal_evidence": None if refusal is None else refusal.to_dict(),
            "execution_refusal_audit_event_id": (
                None if refusal is None or not refusal.audit_event_id else refusal.audit_event_id
            ),
            "execution_refusal_audited": False if refusal is None else refusal.audited,
            "execution_refusal_signed": False if refusal is None else refusal.signed,
            "adapter_attempted": adapter_attempted,
            "adapter_calls": len(adapter_calls),
            "deployment_count": len(deployments),
            "denied_before_adapter": not outcome_unknown,
            "denied_before_side_effect": not outcome_unknown,
            "side_effect_confirmed": False,
            "retry_safe": False,
            "do_not_retry": True,
            "policy_digest": snapshot.digest,
            "independent_denial_verification": independent,
            "denial_evidence_bundle": (
                None if denial_bundle_dir is None else str(denial_bundle_dir)
            ),
            "refusal_evidence_path": (
                None if refusal_evidence_path is None else str(refusal_evidence_path)
            ),
            "verify_denial_command": verify_denial_command,
            "checkpoint_public_key": str(checkpoint_key),
            "lifecycle_public_key": str(lifecycle_key),
            "proof_pack": None,
        }
        # Persist the exact denial response so the demo's evidence is complete on
        # disk: the bundle (audit + checkpoint), the refusal-evidence claims, and
        # the full structured response. This is evidence, not authorization; the
        # response alone is never self-contained proof — verify-denial re-derives
        # the verdict from the bundle and the separately supplied trust roots.
        if denial_bundle_dir is not None:
            denial_response_path = output / "denial-response.json"
            response["denial_response_path"] = str(denial_response_path)
            with contextlib.suppress(OSError, ValueError, ReleaseProofError):
                _write_new(denial_response_path, _json_bytes(response))
        return response

    if exporter.last_pack is None:
        raise ReleaseProofError("reference proof sink did not produce a pack")
    if len(adapter_calls) != 1:
        raise ReleaseProofError("reference release did not execute exactly once")
    verification = verify_release_proof_pack(
        pack_dir,
        receipt_public_key=receipt_key,
        checkpoint_public_key=checkpoint_key,
        consumption_public_key=consumption_key,
        lifecycle_public_key=lifecycle_key,
        expected_pack_digest=exporter.last_pack.pack_digest,
    )
    return {
        "valid": verification.valid,
        "decision": "ALLOW",
        "claim_boundary": "local-fixture-only-no-real-deployment",
        "adapter_result": result,
        "adapter_calls": len(adapter_calls),
        "deployment_count": len(deployments),
        "adapter_gated_by_receipt": True,
        # Proven by the kernel before the adapter latch, against the immutable
        # snapshot the adapter then deployed — not rehashed from a mutable path.
        "artifact_digest_verified_before_adapter": True,
        "deployed_artifact_sha256": deployments[0]["artifact_sha256"],
        # The kernel proved, before the adapter latch, that the captured
        # snapshot's recomputed content digest equalled the receipted
        # ``artifact_digest``; the deployed digest below is therefore the
        # approved digest. No mutable path is rehashed here.
        "approved_artifact_sha256": deployments[0]["artifact_sha256"],
        "adapter_arguments_hash": strict_json_hash(adapter_calls[0]),
        "policy_digest": snapshot.digest,
        "consumption_evidence_mode": verification.consumption_evidence_mode,
        "proof_pack": str(pack_dir),
        "pack_digest": exporter.last_pack.pack_digest,
        "receipt_public_key": str(receipt_key),
        "checkpoint_public_key": str(checkpoint_key),
        "consumption_public_key": str(consumption_key),
        "lifecycle_public_key": str(lifecycle_key),
        "verify_command": (
            f"gove-zone release verify-proof-pack --pack {pack_dir} "
            f"--receipt-public-key {receipt_key} --checkpoint-public-key {checkpoint_key} "
            f"--consumption-public-key {consumption_key} "
            f"--lifecycle-public-key {lifecycle_key} "
            f"--expected-pack-digest {exporter.last_pack.pack_digest}"
        ),
        "replay_command": (
            f"gove-zone release replay-proof-pack --pack {pack_dir} "
            f"--receipt-public-key {receipt_key} --checkpoint-public-key {checkpoint_key} "
            f"--consumption-public-key {consumption_key} "
            f"--lifecycle-public-key {lifecycle_key} "
            f"--expected-pack-digest {exporter.last_pack.pack_digest}"
        ),
    }


def generate_release_demo(
    output: Path,
    *,
    _artifact_tamper_scenario: bool = False,
    commit_guard: Callable[[str], None] | None = None,
    open_directory: sealed_pack.OpenDirectory | None = None,
    expected_output_parent: str | Path | None = None,
    expected_parent_identity: sealed_pack.DirectoryIdentity | None = None,
    path_capability: AttestedDirectory | None = None,
) -> dict[str, Any]:
    """Generate a network-free fixture pack; never invokes a real deployer."""

    if path_capability is not None:
        require_attested_directory(path_capability, error_type=ReleaseProofError)

    from gove_zone.authorization import (
        PolicyArtifactAttestation,
        ResolvedPolicy,
        ResolvedPolicyRef,
        SideEffectAuthorization,
        SideEffectExecutionError,
        SideEffectRequest,
        VerifiedPrincipal,
    )
    from gove_zone.receipt import Validator
    from gove_zone.release_gate import (
        ReleaseDeployment,
        ReleaseEvidenceClaim,
        ReleaseEvidenceRequirement,
        ReleaseGate,
    )
    from gove_zone.side_effect_kernel import (
        AdapterOutcome,
        AdapterOutcomeStatus,
        ReceiptGatedSideEffectExecutor,
        SideEffectAuthorizationKernel,
    )

    if path_capability is not None and any(
        value is not None
        for value in (open_directory, expected_output_parent, expected_parent_identity)
    ):
        raise ReleaseProofError("path capability cannot be mixed with legacy path hooks")
    directory_opener = (
        path_capability.open_directory_path
        if path_capability is not None
        else open_directory or _open_directory
    )
    if (expected_output_parent is None) != (expected_parent_identity is None):
        raise ReleaseProofError("expected output parent and identity must be supplied together")
    if expected_output_parent is not None and expected_parent_identity is not None:
        parent_fd, actual_parent = directory_opener(Path(expected_output_parent))
        try:
            if actual_parent != expected_parent_identity:
                raise ReleaseProofError("expected output parent identity changed")
        finally:
            os.close(parent_fd)
    if commit_guard is not None:
        commit_guard("before-output")
    output = Path(output)
    if path_capability is not None:
        path_capability.checkpoint()
        if output != path_capability.display_path:
            raise ReleaseProofError("output does not match the attested directory")
        output_fd, output_identity = path_capability.open_directory()
        try:
            if os.listdir(output_fd):
                raise ReleaseProofError("attested release output must be empty")
        finally:
            os.close(output_fd)
    else:
        output_fd, output_identity = _open_or_create_empty_directory(output)
        os.close(output_fd)
        _assert_path_identity(output, output_identity)
    runtime = output / "runtime"
    keys = output / "external-keys"
    if path_capability is not None:
        runtime_capability = path_capability.subdirectory("runtime", create=True)
        path_capability.subdirectory("external-keys", create=True)
    else:
        runtime_capability = None
        runtime_fd, _ = _open_or_create_empty_directory(runtime)
        os.close(runtime_fd)
        keys_fd, _ = _open_or_create_empty_directory(keys)
        os.close(keys_fd)
    pack_dir = output / "proof-pack"
    base_pack_dir = runtime / "base-proof-pack" if _artifact_tamper_scenario else pack_dir

    receipt_signer = Ed25519Signer.from_private_bytes(b"\x11" * 32, "demo-release-key")
    lifecycle_signer = Ed25519Signer.from_private_bytes(b"\x33" * 32, "demo-lifecycle-key")
    consumption_signer = Ed25519Signer.from_private_bytes(b"\x22" * 32, "demo-consumption-key")
    receipt_key = keys / "receipt-ed25519.pub"
    checkpoint_key = keys / "checkpoint-ed25519.pub"
    consumption_key = keys / "consumption-ed25519.pub"
    lifecycle_key = keys / "lifecycle-ed25519.pub"
    if path_capability is not None:
        path_capability.write_new(
            "external-keys/receipt-ed25519.pub", receipt_signer.public_bytes()
        )
        path_capability.write_new(
            "external-keys/checkpoint-ed25519.pub", receipt_signer.public_bytes()
        )
        path_capability.write_new(
            "external-keys/consumption-ed25519.pub", consumption_signer.public_bytes()
        )
        path_capability.write_new(
            "external-keys/lifecycle-ed25519.pub", lifecycle_signer.public_bytes()
        )
    else:
        _write_new(receipt_key, receipt_signer.public_bytes())
        _write_new(checkpoint_key, receipt_signer.public_bytes())
        _write_new(consumption_key, consumption_signer.public_bytes())
        _write_new(lifecycle_key, lifecycle_signer.public_bytes())
    if commit_guard is not None:
        commit_guard("keys-committed")

    now = datetime(2026, 7, 14, 18, 0, tzinfo=UTC)

    def iso(value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    # The deployment route requires an immutable snapshot proof, so the fixture
    # needs a real artifact and its real digest rather than a synthetic one.
    demo_artifact = runtime / "demo-artifact.whl"
    demo_artifact_bytes = b"fixture-local-release-demo-artifact-v1\n"
    if runtime_capability is not None:
        runtime_capability.write_new("demo-artifact.whl", demo_artifact_bytes)
    else:
        _write_new(demo_artifact, demo_artifact_bytes)
    demo_artifact_digest = hashlib.sha256(demo_artifact_bytes).hexdigest()

    evidence: list[ReleaseEvidenceClaim] = []
    for index, evidence_type in enumerate(("approval", "security-scan", "tests"), start=3):
        ref = EvidenceRef(
            evidence_id=f"demo-{evidence_type}",
            evidence_type=evidence_type,
            digest=str(index) * 64,
            issuer="demo-trusted-ci",
            issued_at=iso(now - timedelta(minutes=10)),
            expires_at=iso(now + timedelta(hours=1)),
        )
        evidence.append(
            ReleaseEvidenceClaim(
                evidence=ref,
                repository="demo/acgs-release",
                ref="refs/heads/main",
                commit_sha="1" * 40,
                artifact_digest=demo_artifact_digest,
                workflow_identity="fixture:local-release-demo",
                verifier_id="demo-ci-verifier",
                signature=f"fixture-only:{evidence_type}",
            )
        )
    deployment = ReleaseDeployment(
        repository="demo/acgs-release",
        ref="refs/heads/main",
        branch="main",
        commit_sha="1" * 40,
        workflow_identity="fixture:local-release-demo",
        artifact_digest=demo_artifact_digest,
        environment="production",
        deployment_target="fixture://local/production",
        approval_identity="demo-approver",
        evidence=tuple(evidence),
    )
    requirements = ReleaseGateRequirements(
        required_evidence_claims=tuple(
            ReleaseEvidenceRequirement.from_claim(item) for item in evidence
        ),
        environment_targets={"production": ("fixture://local/production",)},
        production_branches=("main",),
        allowed_repositories=("demo/acgs-release",),
        allowed_workflow_identities=("fixture:local-release-demo",),
    )
    policy = ReleaseGatePolicy(requirements)
    snapshot = policy.authorization_snapshot()
    policy_ref = ResolvedPolicyRef(
        tenant_id="demo-tenant",
        bundle_id="acgs-release-gate-policy",
        version=snapshot.policy_version,
        digest=snapshot.digest,
    )
    principal = VerifiedPrincipal(
        tenant_id="demo-tenant",
        actor_id="demo-release-agent",
        role="release-agent",
        authority="release.deploy",
        authentication_context={"method": "fixture-workload-identity"},
        verified_at=iso(now - timedelta(hours=1)),
        expires_at=iso(now + timedelta(hours=1)),
    )
    resolved = ResolvedPolicy(
        ref=policy_ref,
        policy=policy,
        attestation=PolicyArtifactAttestation(
            tenant_id=policy_ref.tenant_id,
            artifact_id=policy_ref.bundle_id,
            policy_version=policy_ref.version,
            digest=policy_ref.digest,
            resolver_id="demo-policy-resolver",
        ),
        validator=Validator("demo-approver", "approver"),
        authority=principal.authority,
    )
    principal_resolver = _StaticPrincipalResolver(principal)
    policy_resolver = _StaticPolicyResolver(resolved)
    audit_anchor = _MemoryAuditAnchor()
    audit_namespace = "demo:release-audit:dedicated"
    audit = (
        ChainHashAuditStore.from_attested(
            runtime_capability,
            "audit.jsonl",
            checkpoint_anchor=audit_anchor,
            checkpoint_namespace=audit_namespace,
            checkpoint_signer=receipt_signer,
            checkpoint_verifier={receipt_signer.key_id: receipt_signer},
            require_trusted_checkpoint=True,
        )
        if runtime_capability is not None
        else ChainHashAuditStore(
            runtime / "audit.jsonl",
            checkpoint_anchor=audit_anchor,
            checkpoint_namespace=audit_namespace,
            checkpoint_signer=receipt_signer,
            checkpoint_verifier={receipt_signer.key_id: receipt_signer},
            require_trusted_checkpoint=True,
        )
    )
    replay_store = (
        ReplaySideStore.from_attested(runtime_capability, "replay.jsonl")
        if runtime_capability is not None
        else ReplaySideStore(runtime / "replay.jsonl")
    )
    consumption_anchor = _MemoryConsumptionAnchor()
    consumption_namespace = "demo:release-consumption"
    consumption = (
        ReceiptConsumptionStore.from_attested(
            runtime_capability,
            "consumption.sqlite3",
            hmac_key=b"demo-consumption-hmac-key-32-bytes",
            state_anchor=consumption_anchor,
            anchor_namespace=consumption_namespace,
            require_trusted_anchor=True,
        )
        if runtime_capability is not None
        else ReceiptConsumptionStore(
            runtime / "consumption.sqlite3",
            hmac_key=b"demo-consumption-hmac-key-32-bytes",
            state_anchor=consumption_anchor,
            anchor_namespace=consumption_namespace,
            require_trusted_anchor=True,
        )
    )

    class _CapturingAuthorizationKernel(SideEffectAuthorizationKernel):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.history: list[SideEffectAuthorization] = []

        def authorize(self, request: SideEffectRequest) -> SideEffectAuthorization:
            authorization = super().authorize(request)
            self.history.append(authorization)
            return authorization

    kernel_type = (
        _CapturingAuthorizationKernel
        if _artifact_tamper_scenario
        else SideEffectAuthorizationKernel
    )
    authorizer = kernel_type(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        signer=receipt_signer,
        binding_hmac_key=b"demo-binding-hmac-key-exactly-32!!",
        allowed_validator_roles=("approver",),
        side_store=replay_store,
        clock=lambda: now,
    )
    executor = ReceiptGatedSideEffectExecutor(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        consumption_store=consumption,
        verifier={receipt_signer.key_id: receipt_signer},
        lifecycle_signer=lifecycle_signer,
        lifecycle_authority_id=_LIFECYCLE_AUTHORITY_ID,
        binding_hmac_key=b"demo-binding-hmac-key-exactly-32!!",
        allowed_validator_roles=("approver",),
        clock=lambda: now,
    )
    exporter = ReleaseProofPackExporter(
        ReleaseProofSources(
            output_directory=base_pack_dir,
            policy_snapshot=snapshot,
            audit_store=audit,
            audit_anchor=audit_anchor,
            audit_namespace=audit_namespace,
            replay_store=replay_store,
            consumption_store=consumption,
            consumption_anchor=consumption_anchor,
            consumption_namespace=consumption_namespace,
            consumption_signer=consumption_signer,
        ),
        path_capability=path_capability,
        commit_guard=commit_guard,
    )
    adapter_calls: list[dict[str, Any]] = []

    def fixture_adapter(*, artifact_snapshot: Any, **arguments: Any) -> AdapterOutcome:
        # Consumes the kernel-proven snapshot; never reopens the source path.
        deployed = artifact_snapshot.bytes()
        adapter_calls.append(arguments)
        return AdapterOutcome(
            AdapterOutcomeStatus.CONFIRMED_SUCCEEDED,
            {
                "deployment_id": "fixture-deployment-1",
                "status": "succeeded",
                "artifact_sha256": hashlib.sha256(deployed).hexdigest(),
            },
        )

    gate = ReleaseGate(
        authorizer=authorizer,
        executor=executor,
        deployment_adapter=fixture_adapter,
        proof_sink=exporter,
    )
    approved_authorization: SideEffectAuthorization | None = None
    baseline_calls = 0
    if _artifact_tamper_scenario:
        approval_request = SideEffectRequest(
            request_id="demo-release-approved-a",
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            actor_role=principal.role,
            authority=principal.authority,
            server_id=RELEASE_GATE_SERVER_ID,
            tool=RELEASE_GATE_TOOL,
            operation=RELEASE_GATE_OPERATION,
            resource=deployment.repository,
            environment=deployment.environment,
            execution_boundary=RELEASE_GATE_EXECUTION_BOUNDARY,
            policy_ref=policy_ref,
            requested_at=iso(now - timedelta(seconds=3)),
            nonce="demo-approved-a-nonce",
            idempotency_key="demo-approved-a-idempotency",
            args=deployment.canonical_arguments(),
            evidence=tuple(item.evidence for item in deployment.evidence),
            side_effect_class=RELEASE_GATE_SIDE_EFFECT_CLASS,
            goal="approve immutable artifact A before the tamper attempt",
        )
        approved_authorization = authorizer.authorize(approval_request)
        if not approved_authorization.executable or approved_authorization.receipt is None:
            raise ReleaseProofError("fixture artifact A did not receive an executable receipt")
        denied = dataclasses.replace(deployment, artifact_digest="9" * 64)
        baseline_calls = _unsafe_release_fixture_baseline(denied.canonical_arguments())
    else:
        denied = dataclasses.replace(deployment, evidence=(deployment.evidence[0],))
    try:
        gate.deploy(
            denied,
            artifact_source=demo_artifact,
            request_id="demo-release-denied-1",
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            actor_role=principal.role,
            authority=principal.authority,
            policy_ref=policy_ref,
            requested_at=iso(now - timedelta(seconds=2)),
            observed_at=iso(now),
            nonce="demo-denied-nonce",
            idempotency_key="demo-denied-idempotency",
            authentication_context=principal.authentication_context,
        )
    except SideEffectExecutionError:
        pass
    else:
        raise ReleaseProofError("fixture denied release unexpectedly executed")
    if adapter_calls:
        raise ReleaseProofError("fixture denied release reached the deployment adapter")
    denied_authorization: SideEffectAuthorization | None = None
    if _artifact_tamper_scenario:
        captured = cast(_CapturingAuthorizationKernel, authorizer).history
        denied_authorization = captured[-1]
        if denied_authorization.executable or denied_authorization.receipt is None:
            raise ReleaseProofError("fixture artifact B did not produce a signed refusal")
    result = gate.deploy(
        deployment,
        artifact_source=demo_artifact,
        request_id="demo-release-request-1",
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        actor_role=principal.role,
        authority=principal.authority,
        policy_ref=policy_ref,
        requested_at=iso(now - timedelta(seconds=1)),
        observed_at=iso(now),
        nonce="demo-release-nonce",
        idempotency_key="demo-release-idempotency",
        authentication_context=principal.authentication_context,
    )
    if exporter.last_pack is None:
        raise ReleaseProofError("demo proof sink did not produce a pack")
    if len(adapter_calls) != 1:
        raise ReleaseProofError("fixture valid release did not execute exactly once")
    verification = verify_release_proof_pack(
        base_pack_dir,
        receipt_public_key=receipt_key,
        checkpoint_public_key=checkpoint_key,
        consumption_public_key=consumption_key,
        lifecycle_public_key=lifecycle_key,
        expected_pack_digest=exporter.last_pack.pack_digest,
        path_capability=path_capability,
    )
    if _artifact_tamper_scenario:
        if approved_authorization is None or denied_authorization is None:
            raise ReleaseProofError("artifact-tamper authorizations are unavailable")
        disaster_pack, disaster_digest = _export_release_disaster_pack(
            base_pack_dir=base_pack_dir,
            output=pack_dir,
            approved_arguments=deployment.canonical_arguments(),
            attempted_arguments=denied.canonical_arguments(),
            approved_authorization=approved_authorization,
            denied_authorization=denied_authorization,
            companion_authorization=cast(_CapturingAuthorizationKernel, authorizer).history[-1],
            baseline_calls=baseline_calls,
            governed_calls=0,
            open_directory=directory_opener,
            commit_guard=commit_guard,
        )
        disaster_verification = verify_release_proof_pack(
            disaster_pack,
            receipt_public_key=receipt_key,
            checkpoint_public_key=checkpoint_key,
            consumption_public_key=consumption_key,
            lifecycle_public_key=lifecycle_key,
            expected_pack_digest=disaster_digest,
            path_capability=path_capability,
        )
        return {
            "valid": disaster_verification.valid,
            "decision": "DENY",
            "claim_boundary": "local-fixture-only-no-real-deployment",
            "baseline_side_effect_calls": baseline_calls,
            "governed_side_effect_calls": 0,
            "companion_allow_side_effect_calls": len(adapter_calls),
            "reason_codes": _authorization_reason_values(denied_authorization),
            "approved_receipt_id": cast(DecisionReceipt, approved_authorization.receipt).receipt_id,
            "refusal_id": cast(DecisionReceipt, denied_authorization.receipt).receipt_id,
            "audit_event_ids": [
                item.audit_event_id
                for item in cast(_CapturingAuthorizationKernel, authorizer).history
            ],
            "proof_pack": str(disaster_pack),
            "pack_digest": disaster_digest,
            "receipt_public_key": str(receipt_key),
            "checkpoint_public_key": str(checkpoint_key),
            "consumption_public_key": str(consumption_key),
            "lifecycle_public_key": str(lifecycle_key),
            "verify_command": (
                f"gove-zone release verify-proof-pack --pack {disaster_pack} "
                f"--receipt-public-key {receipt_key} --checkpoint-public-key {checkpoint_key} "
                f"--consumption-public-key {consumption_key} "
                f"--lifecycle-public-key {lifecycle_key} "
                f"--expected-pack-digest {disaster_digest}"
            ),
            "replay_command": (
                f"gove-zone release replay-proof-pack --pack {disaster_pack} "
                f"--receipt-public-key {receipt_key} --checkpoint-public-key {checkpoint_key} "
                f"--consumption-public-key {consumption_key} "
                f"--lifecycle-public-key {lifecycle_key} "
                f"--expected-pack-digest {disaster_digest}"
            ),
        }
    receipt_tamper_blocked, receipt_tamper_reason = _demo_receipt_tamper(
        pack_dir=pack_dir,
        receipt_key=receipt_key,
        checkpoint_key=checkpoint_key,
        consumption_key=consumption_key,
        lifecycle_key=lifecycle_key,
    )
    if not receipt_tamper_blocked:
        raise ReleaseProofError("fixture receipt tamper was not rejected")
    return {
        "valid": verification.valid,
        "claim_boundary": "local-fixture-only-no-real-deployment",
        "adapter_result": result,
        "denied_before_adapter": True,
        "adapter_calls": len(adapter_calls),
        "consumption_evidence_mode": verification.consumption_evidence_mode,
        "receipt_tamper_blocked": receipt_tamper_blocked,
        "receipt_tamper_reason_code": receipt_tamper_reason,
        "proof_pack": str(pack_dir),
        "pack_digest": exporter.last_pack.pack_digest,
        "receipt_public_key": str(receipt_key),
        "checkpoint_public_key": str(checkpoint_key),
        "consumption_public_key": str(consumption_key),
        "lifecycle_public_key": str(lifecycle_key),
        "verify_command": (
            f"gove-zone release verify-proof-pack --pack {pack_dir} "
            f"--receipt-public-key {receipt_key} --checkpoint-public-key {checkpoint_key} "
            f"--consumption-public-key {consumption_key} "
            f"--lifecycle-public-key {lifecycle_key} "
            f"--expected-pack-digest {exporter.last_pack.pack_digest}"
        ),
        "replay_command": (
            f"gove-zone release replay-proof-pack --pack {pack_dir} "
            f"--receipt-public-key {receipt_key} --checkpoint-public-key {checkpoint_key} "
            f"--consumption-public-key {consumption_key} "
            f"--lifecycle-public-key {lifecycle_key} "
            f"--expected-pack-digest {exporter.last_pack.pack_digest}"
        ),
    }


def generate_release_artifact_tamper_demo(
    output: Path,
    *,
    commit_guard: Callable[[str], None] | None = None,
    open_directory: sealed_pack.OpenDirectory | None = None,
    expected_output_parent: str | Path | None = None,
    expected_parent_identity: sealed_pack.DirectoryIdentity | None = None,
    path_capability: AttestedDirectory | None = None,
) -> dict[str, Any]:
    """Emit a v2 pack proving artifact A approval and artifact B refusal."""

    if path_capability is not None:
        require_attested_directory(path_capability, error_type=ReleaseProofError)
    return generate_release_demo(
        output,
        _artifact_tamper_scenario=True,
        commit_guard=commit_guard,
        open_directory=open_directory,
        expected_output_parent=expected_output_parent,
        expected_parent_identity=expected_parent_identity,
        path_capability=path_capability,
    )


def _unsafe_release_fixture_baseline(arguments: Mapping[str, Any]) -> int:
    """Model the ungoverned disaster locally; never a fallback execution path."""

    if type(arguments.get("artifact_digest")) is not str:
        raise ReleaseProofError("unsafe fixture baseline requires an artifact digest")
    return 1


def _export_release_disaster_pack(
    *,
    base_pack_dir: Path,
    output: Path,
    approved_arguments: Mapping[str, Any],
    attempted_arguments: Mapping[str, Any],
    approved_authorization: Any,
    denied_authorization: Any,
    companion_authorization: Any,
    baseline_calls: int,
    governed_calls: int,
    open_directory: sealed_pack.OpenDirectory | None = None,
    commit_guard: Callable[[str], None] | None = None,
) -> tuple[Path, str]:
    directory_opener = open_directory or _open_directory

    def assert_identity(path: Path, expected: sealed_pack.DirectoryIdentity) -> None:
        sealed_pack.assert_path_identity(
            path,
            expected,
            open_directory=directory_opener,
            error_type=ReleaseProofError,
        )

    raw = _read_exact_pack(
        base_pack_dir,
        open_directory=directory_opener,
        assert_path_identity=assert_identity,
    )
    approved_receipt = approved_authorization.receipt
    refusal_receipt = denied_authorization.receipt
    companion_receipt = companion_authorization.receipt
    if approved_receipt is None or refusal_receipt is None or companion_receipt is None:
        raise ReleaseProofError("disaster proof requires three signed receipts")
    reason_codes = _authorization_reason_values(denied_authorization)
    digest_input = {
        "approved_arguments_hash": strict_json_hash(approved_arguments),
        "attempted_arguments_hash": strict_json_hash(attempted_arguments),
        "baseline_side_effect_calls": baseline_calls,
        "governed_side_effect_calls": governed_calls,
        "decision": "DENY",
        "reason_codes": reason_codes,
    }
    scenario = {
        "schema": DISASTER_SCENARIO_SCHEMA,
        "scenario": "release-artifact-tamper",
        "claim_boundary": "local-fixture-only-no-real-deployment",
        "approved_arguments": _plain(approved_arguments),
        "attempted_arguments": _plain(attempted_arguments),
        "approved_receipt": approved_receipt.to_dict(),
        "baseline_side_effect_calls": baseline_calls,
        "governed_side_effect_calls": governed_calls,
        "companion_allow_side_effect_calls": 1,
        "decision": "DENY",
        "reason_codes": reason_codes,
        "scenario_digest": strict_json_hash(digest_input),
    }
    protocol = [
        {
            "record_id": "approved-artifact-a",
            "event_id": approved_authorization.audit_event_id,
            "phase": "approved",
            "decision": approved_receipt.decision,
            "arguments": _plain(approved_arguments),
            "argument_hash": strict_json_hash(approved_arguments),
            "receipt_id": approved_receipt.receipt_id,
            "side_effect_calls": 0,
            "reason_codes": _authorization_reason_values(approved_authorization),
        },
        {
            "record_id": "attempted-artifact-b",
            "event_id": denied_authorization.audit_event_id,
            "phase": "attempted",
            "decision": refusal_receipt.decision,
            "arguments": _plain(attempted_arguments),
            "argument_hash": strict_json_hash(attempted_arguments),
            "receipt_id": refusal_receipt.receipt_id,
            "side_effect_calls": governed_calls,
            "reason_codes": reason_codes,
        },
        {
            "record_id": "companion-artifact-a-execution",
            "event_id": companion_authorization.audit_event_id,
            "phase": "companion-executed",
            "decision": companion_receipt.decision,
            "arguments": _plain(approved_arguments),
            "argument_hash": strict_json_hash(approved_arguments),
            "receipt_id": companion_receipt.receipt_id,
            "side_effect_calls": 1,
            "reason_codes": _authorization_reason_values(companion_authorization),
        },
    ]
    refusals = [
        {
            "record_id": "artifact-b-refusal",
            "event_id": denied_authorization.audit_event_id,
            "reason_codes": reason_codes,
            "receipt": refusal_receipt.to_dict(),
        }
    ]
    payloads = {name: raw[name] for name in _PAYLOAD_FILES}
    payloads.update(
        {
            "protocol-results.jsonl": _jsonl_bytes(protocol),
            "refusals.jsonl": _jsonl_bytes(refusals),
            "scenario.json": _json_bytes(scenario),
        }
    )
    _, digest = _RELEASE_DISASTER_PACK_CODEC.export_new_pack(
        output,
        payloads,
        open_directory=directory_opener,
        read_file_at=_read_file_at,
        write_new_at=_write_new_at,
        assert_membership=_assert_exact_membership,
        assert_path_identity=assert_identity,
    )
    if commit_guard is not None:
        commit_guard("disaster-pack-committed")
    return output, digest


def _verify_release_disaster_pack(
    root: Path,
    raw: Mapping[str, bytes],
    *,
    receipt_public_key: str | Path,
    checkpoint_public_key: str | Path,
    consumption_public_key: str | Path,
    lifecycle_public_key: str | Path,
    expected_pack_digest: str,
    path_capability: AttestedDirectory | None = None,
) -> ReleaseProofVerification:
    if path_capability is not None:
        require_attested_directory(path_capability, error_type=ReleaseProofError)
    manifest = _RELEASE_DISASTER_PACK_CODEC.strict_json(raw["manifest.json"], "manifest.json")
    if type(manifest) is not dict or manifest.get("schema") != DISASTER_PROOF_PACK_SCHEMA:
        raise ReleaseProofError("disaster manifest schema is incompatible")
    manifest_payload = {key: manifest.get(key) for key in ("schema", "files", "verification")}
    if (
        manifest.get("pack_digest") != expected_pack_digest
        or _RELEASE_DISASTER_PACK_CODEC.pack_digest(manifest_payload) != expected_pack_digest
    ):
        raise ReleaseProofError("disaster manifest digest does not match its external pin")
    scenario = _RELEASE_DISASTER_PACK_CODEC.strict_json(raw["scenario.json"], "scenario.json")
    protocol = _RELEASE_DISASTER_PACK_CODEC.strict_jsonl(
        raw["protocol-results.jsonl"], "protocol-results.jsonl"
    )
    refusals = _RELEASE_DISASTER_PACK_CODEC.strict_jsonl(raw["refusals.jsonl"], "refusals.jsonl")
    if type(scenario) is not dict or set(scenario) != set(_DISASTER_SCENARIO_KEYS):
        raise ReleaseProofError("release disaster scenario is incompatible")
    if len(protocol) != 3 or len(refusals) != 1:
        raise ReleaseProofError("release disaster evidence cardinality is incompatible")
    if (
        scenario.get("schema") != DISASTER_SCENARIO_SCHEMA
        or scenario.get("scenario") != "release-artifact-tamper"
        or scenario.get("claim_boundary") != "local-fixture-only-no-real-deployment"
        or type(scenario.get("approved_arguments")) is not dict
        or type(scenario.get("attempted_arguments")) is not dict
        or type(scenario.get("approved_receipt")) is not dict
        or type(scenario.get("baseline_side_effect_calls")) is not int
        or type(scenario.get("governed_side_effect_calls")) is not int
        or type(scenario.get("companion_allow_side_effect_calls")) is not int
        or type(scenario.get("decision")) is not str
        or type(scenario.get("scenario_digest")) is not str
        or type(scenario.get("reason_codes")) is not list
        or any(type(item) is not str for item in scenario["reason_codes"])
    ):
        raise ReleaseProofError("release disaster scenario is incompatible")
    for index, item in enumerate(protocol):
        if (
            type(item) is not dict
            or set(item) != set(_DISASTER_PROTOCOL_KEYS)
            or any(
                type(item.get(key)) is not str
                for key in (
                    "argument_hash",
                    "decision",
                    "event_id",
                    "phase",
                    "receipt_id",
                    "record_id",
                )
            )
            or type(item.get("arguments")) is not dict
            or type(item.get("side_effect_calls")) is not int
            or type(item.get("reason_codes")) is not list
            or any(type(reason) is not str for reason in item["reason_codes"])
        ):
            raise ReleaseProofError(f"release disaster protocol row {index} is incompatible")
    for index, item in enumerate(refusals):
        if (
            type(item) is not dict
            or set(item) != set(_DISASTER_REFUSAL_KEYS)
            or type(item.get("record_id")) is not str
            or type(item.get("event_id")) is not str
            or type(item.get("receipt")) is not dict
            or type(item.get("reason_codes")) is not list
            or any(type(reason) is not str for reason in item["reason_codes"])
        ):
            raise ReleaseProofError(f"release disaster refusal row {index} is incompatible")
    phases = {item.get("phase"): item for item in protocol}
    if set(phases) != {"approved", "attempted", "companion-executed"}:
        raise ReleaseProofError("release disaster protocol phases are incompatible")
    approved = phases["approved"]
    attempted = phases["attempted"]
    companion = phases["companion-executed"]
    approved_args = scenario.get("approved_arguments")
    attempted_args = scenario.get("attempted_arguments")
    if type(approved_args) is not dict or type(attempted_args) is not dict:
        raise ReleaseProofError("release disaster arguments are incompatible")
    approved_without_artifact = dict(approved_args)
    attempted_without_artifact = dict(attempted_args)
    approved_artifact = approved_without_artifact.pop("artifact_digest", None)
    attempted_artifact = attempted_without_artifact.pop("artifact_digest", None)
    if (
        approved_without_artifact != attempted_without_artifact
        or approved_artifact == attempted_artifact
        or not _sha256(approved_artifact)
        or not _sha256(attempted_artifact)
    ):
        raise ReleaseProofError("artifact digest must be the only changed release argument")
    if (
        scenario.get("baseline_side_effect_calls") != 1
        or scenario.get("governed_side_effect_calls") != 0
        or scenario.get("companion_allow_side_effect_calls") != 1
        or scenario.get("decision") != "DENY"
        or approved.get("arguments") != approved_args
        or attempted.get("arguments") != attempted_args
        or companion.get("arguments") != approved_args
        or attempted.get("side_effect_calls") != 0
    ):
        raise ReleaseProofError("release disaster counts or exact arguments diverge")
    events = _strict_jsonl(raw["audit.jsonl"], "audit.jsonl")
    replay = _strict_jsonl(raw["replay.jsonl"], "replay.jsonl")
    event_by_id = {item.get("event_id"): item for item in events}
    replay_by_id = {item.get("event_id"): item for item in replay}
    protocol_ids = [item.get("event_id") for item in protocol]
    authorization_event_ids = {
        item.get("event_id") for item in events if "execution_evidence" not in item
    }
    if (
        len(event_by_id) != len(events)
        or len(replay_by_id) != len(replay)
        or len(set(protocol_ids)) != len(protocol_ids)
        or set(protocol_ids) != authorization_event_ids
        or set(protocol_ids) != set(replay_by_id)
    ):
        raise ReleaseProofError("release disaster has duplicate or unreferenced events")
    refusal = refusals[0]
    refusal_data = refusal.get("receipt")
    approved_data = scenario.get("approved_receipt")
    if type(refusal_data) is not dict or type(approved_data) is not dict:
        raise ReleaseProofError("release disaster signed evidence is missing")
    refusal_receipt = DecisionReceipt.from_dict(cast(dict[str, Any], refusal_data))
    approved_receipt = DecisionReceipt.from_dict(cast(dict[str, Any], approved_data))
    verifier = _public_key(
        receipt_public_key,
        refusal_receipt.signing_key_id,
        path_capability=path_capability,
    )
    for receipt in (approved_receipt, refusal_receipt):
        if (
            receipt.compute_hash() != receipt.receipt_hash
            or verifier.verify(receipt.receipt_hash.encode("utf-8"), receipt.signature) is not True
        ):
            raise ReleaseProofError("release disaster receipt signature is invalid")
    attempted_event = event_by_id.get(attempted.get("event_id"), {})
    attempted_replay = replay_by_id.get(attempted.get("event_id"), {})
    if (
        approved_receipt.decision != "allow"
        or refusal_receipt.decision != "deny"
        or approved_receipt.argument_hash != strict_json_hash(approved_args)
        or refusal_receipt.argument_hash != strict_json_hash(attempted_args)
        or refusal.get("event_id") != refusal_receipt.receipt_id
        or attempted.get("receipt_id") != refusal_receipt.receipt_id
        or attempted_event.get("event_hash") != refusal_receipt.audit_event_hash
        or attempted_event.get("decision") != "deny"
        or attempted_event.get("argument_hash") != refusal_receipt.argument_hash
        or attempted_replay.get("args") != attempted_args
        or attempted_replay.get("decision") != "deny"
        or attempted_replay.get("policy_version") != refusal_receipt.policy_version
        or attempted_event.get("actor") != refusal_receipt.actor
        or attempted_event.get("tool") != RELEASE_GATE_OPERATION
        or refusal_receipt.execution_boundary != RELEASE_GATE_EXECUTION_BOUNDARY
        or refusal_receipt.policy_hash != approved_receipt.policy_hash
        or refusal_receipt.tenant_id != approved_receipt.tenant_id
        or refusal_receipt.actor != approved_receipt.actor
        or refusal_receipt.validator_id != approved_receipt.validator_id
        or scenario.get("reason_codes") != attempted.get("reason_codes")
        or scenario.get("reason_codes") != refusal.get("reason_codes")
    ):
        raise ReleaseProofError("release disaster refusal cross-links diverge")
    digest_input = {
        "approved_arguments_hash": strict_json_hash(approved_args),
        "attempted_arguments_hash": strict_json_hash(attempted_args),
        "baseline_side_effect_calls": 1,
        "governed_side_effect_calls": 0,
        "decision": "DENY",
        "reason_codes": scenario.get("reason_codes"),
    }
    if scenario.get("scenario_digest") != strict_json_hash(digest_input):
        raise ReleaseProofError("release disaster scenario digest is invalid")
    with tempfile.TemporaryDirectory(prefix="gove-zone-release-v2-base-") as temp:
        base = Path(temp) / "proof-pack"
        base_payloads = {name: raw[name] for name in _PAYLOAD_FILES}
        _, base_digest = _RELEASE_PACK_CODEC.export_new_pack(base, base_payloads)
        base_verification = verify_release_proof_pack(
            base,
            receipt_public_key=receipt_public_key,
            checkpoint_public_key=checkpoint_public_key,
            consumption_public_key=consumption_public_key,
            lifecycle_public_key=lifecycle_public_key,
            expected_pack_digest=base_digest,
        )
    return ReleaseProofVerification(
        base_verification.valid,
        expected_pack_digest,
        base_verification.receipt_id,
        base_verification.replay,
        base_verification.consumption_evidence_mode,
    )


def _authorization_reason_values(authorization: Any) -> list[str]:
    values = authorization.reason_codes
    if type(values) is not tuple or any(
        not isinstance(item, AuthorizationReasonCode) for item in values
    ):
        raise ReleaseProofError("authorization reason codes are not canonical enums")
    return [item.value for item in values]


def _demo_receipt_tamper(
    *,
    pack_dir: Path,
    receipt_key: Path,
    checkpoint_key: Path,
    consumption_key: Path,
    lifecycle_key: Path,
) -> tuple[bool, str]:
    """Prove a manifest-rehashed receipt mutation cannot pass strong verification."""

    with tempfile.TemporaryDirectory(prefix="gove-zone-release-receipt-tamper-") as temp:
        attack_pack = Path(temp) / "proof-pack"
        original = _read_exact_pack(pack_dir)
        receipt = _strict_json(original["receipt.json"], "receipt.json")
        if type(receipt) is not dict:
            raise ReleaseProofError("fixture receipt is not an object")
        receipt["actor"] = "tampered-release-agent"
        payloads = {name: original[name] for name in _PAYLOAD_FILES}
        payloads["receipt.json"] = _json_bytes(receipt)
        manifest_payload = _manifest_payload(_manifest_entries(payloads))
        attack_digest = _pack_digest(manifest_payload)
        directory_fd, identity = _open_or_create_empty_directory(attack_pack)
        try:
            for name, data in payloads.items():
                _write_new_at(directory_fd, name, data)
            _write_new_at(
                directory_fd,
                "manifest.json",
                _json_bytes({**manifest_payload, "pack_digest": attack_digest}),
            )
            _assert_exact_membership(directory_fd, _PACK_FILES, "tamper proof output")
            os.fsync(directory_fd)
            _assert_path_identity(attack_pack, identity)
        finally:
            os.close(directory_fd)
        try:
            verify_release_proof_pack(
                attack_pack,
                receipt_public_key=receipt_key,
                checkpoint_public_key=checkpoint_key,
                consumption_public_key=consumption_key,
                lifecycle_public_key=lifecycle_key,
                expected_pack_digest=attack_digest,
            )
        except ReleaseProofError:
            return True, "RELEASE_RECEIPT_TAMPER_REJECTED"
    return False, "RELEASE_RECEIPT_TAMPER_ACCEPTED"


class _StaticPrincipalResolver:
    def __init__(self, principal: Any) -> None:
        self.principal = principal

    def resolve(self) -> Any:
        return self.principal


class _StaticPolicyResolver:
    def __init__(self, policy: Any) -> None:
        self.policy = policy

    def resolve(self, _principal: Any) -> Any:
        return self.policy


class _MemoryAuditAnchor:
    def __init__(self) -> None:
        self.value: AuditCheckpoint | None = None

    def read(self, _namespace: str) -> AuditCheckpoint | None:
        return self.value

    def compare_and_swap(
        self,
        _namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool:
        if self.value != expected:
            return False
        self.value = replacement
        return True


class _MemoryConsumptionAnchor:
    def __init__(self) -> None:
        self.value: Any = None

    def read(self, _namespace: str) -> Any:
        return self.value

    def compare_and_swap(self, _namespace: str, expected: Any, replacement: Any) -> bool:
        if self.value != expected:
            return False
        self.value = replacement
        return True


class _ReadOnlyAuditAnchor:
    def __init__(self, checkpoint: AuditCheckpoint) -> None:
        self.checkpoint = checkpoint

    def read(self, namespace: str) -> AuditCheckpoint | None:
        return self.checkpoint if namespace == self.checkpoint.namespace else None

    def compare_and_swap(
        self,
        namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool:
        return False


def _policy(value: dict[str, Any]) -> ReleaseGatePolicy:
    if value.get("kind") != "acgs.release-gate-policy":
        raise ReleaseProofError("policy kind is not the release gate policy")
    version = _required_text(value.get("version"), "policy.version")
    requirements = value.get("requirements")
    if type(requirements) is not dict:
        raise ReleaseProofError("policy requirements must be an object")
    try:
        return ReleaseGatePolicy(ReleaseGateRequirements.from_dict(requirements), version=version)
    except (TypeError, ValueError) as exc:
        raise ReleaseProofError(f"release policy cannot be rebuilt exactly: {exc}") from exc


def _checkpoint(value: dict[str, Any]) -> AuditCheckpoint:
    try:
        return AuditCheckpoint(
            namespace=_required_text(value["namespace"], "checkpoint.namespace"),
            generation=_positive_int(value["generation"], "checkpoint.generation"),
            head_hash=_required_sha256(value["head_hash"], "checkpoint.head_hash"),
            previous_checkpoint_hash=_required_sha256(
                value["previous_checkpoint_hash"], "checkpoint.previous_checkpoint_hash"
            ),
            key_id=_required_text(value["key_id"], "checkpoint.key_id"),
            algorithm=_required_text(value["algorithm"], "checkpoint.algorithm"),
            signature=_required_text(value["signature"], "checkpoint.signature"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseProofError(f"audit checkpoint is invalid: {exc}") from exc


def _verify_summary(
    value: dict[str, Any], receipt: DecisionReceipt, verifier: Ed25519Signer
) -> None:
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    if (
        value.get("schema") != CONSUMPTION_SUMMARY_SCHEMA
        or value.get("evidence_mode") != CONSUMPTION_EVIDENCE_MODE
        or value.get("state") != ConsumptionState.SUCCEEDED.value
        or value.get("tenant_id") != receipt.tenant_id
        or value.get("receipt_id") != receipt.receipt_id
        or value.get("algorithm") != "ed25519"
        or value.get("key_id") != verifier.key_id
        or not _sha256(value.get("adapter_result_digest"))
        or not _sha256(value.get("chain_head"))
        or not _sha256(value.get("state_root"))
        or type(value.get("generation")) is not int
        or cast(int, value.get("generation")) <= 0
        or not verifier.verify(
            _summary_payload(unsigned), _required_text(value.get("signature"), "summary.signature")
        )
    ):
        raise ReleaseProofError("consumption summary signature or redacted state is invalid")


def _validated_constraints(
    *,
    receipt: DecisionReceipt,
    request: dict[str, Any],
    policy_ref: dict[str, Any],
    checkpoint: AuditCheckpoint,
    args: dict[str, Any],
) -> dict[str, Any]:
    constraints = receipt.constraints
    if type(constraints) is not dict or set(constraints) != {SIDE_EFFECT_BINDING_KEY}:
        raise ReleaseProofError("receipt side-effect constraints are missing")
    binding = constraints[SIDE_EFFECT_BINDING_KEY]
    if type(binding) is not dict or set(binding) != RESERVED_BINDING_REQUIRED_KEYS:
        raise ReleaseProofError("receipt side-effect binding shape is incompatible")
    value = cast(dict[str, Any], binding)
    evidence_raw = request.get("evidence")
    if type(evidence_raw) is not list:
        raise ReleaseProofError("request evidence is missing")
    try:
        evidence = tuple(EvidenceRef(**cast(dict[str, Any], item)) for item in evidence_raw)
    except (TypeError, ValueError) as exc:
        raise ReleaseProofError(f"request evidence cannot be rebuilt: {exc}") from exc
    policy_attestation = value.get("policy_attestation")
    audit_checkpoint = value.get("audit_checkpoint")
    policy = value.get("policy")
    if type(policy_attestation) is not dict or type(audit_checkpoint) is not dict:
        raise ReleaseProofError("receipt policy attestation or audit checkpoint is missing")
    if type(policy) is not dict:
        raise ReleaseProofError("receipt policy binding is missing")
    checkpoint_binding = {**checkpoint.to_dict(), "checkpoint_hash": checkpoint.checkpoint_hash}
    goal_claim = request.get("goal_claim")
    goal_hash = goal_claim.removeprefix("sha256:") if type(goal_claim) is str else None
    comparisons = {
        "schema": SIDE_EFFECT_BINDING_KEY,
        "argument_canonicalization_profile": ARGUMENT_CANONICALIZATION_PROFILE,
        "secret_digest_profile": SECRET_DIGEST_PROFILE,
        "request_id": request.get("request_id"),
        "tenant_id": request.get("tenant_id"),
        "actor_id": request.get("actor_id"),
        "actor_role": request.get("actor_role"),
        "authority": request.get("authority"),
        "server_id": request.get("server_id"),
        "tool": request.get("tool"),
        "operation": request.get("operation"),
        "resource": request.get("resource"),
        "environment": request.get("environment"),
        "execution_boundary": request.get("execution_boundary"),
        "side_effect_class": request.get("side_effect_class"),
        "goal_hash": goal_hash,
        "authorized_at": receipt.timestamp,
        "policy": policy_ref,
        "audit_checkpoint": checkpoint_binding,
        "requested_at": request.get("requested_at"),
        "expires_at": receipt.expires_at,
        "evidence_identifiers": [item.identifier_dict() for item in evidence],
        "evidence_digest": compute_evidence_digest(evidence),
        "original_arguments_hash": strict_json_hash(args),
        "approved_arguments_hash": strict_json_hash(args),
        "validator_id": receipt.validator_id,
        "validator_role": receipt.validator_role,
        "decision": "allow",
    }
    if any(value.get(name) != expected for name, expected in comparisons.items()):
        raise ReleaseProofError("receipt constraints diverge from request, policy, or checkpoint")
    if (
        policy_attestation.get("tenant_id") != policy_ref.get("tenant_id")
        or policy_attestation.get("artifact_id") != policy_ref.get("bundle_id")
        or policy_attestation.get("policy_version") != policy_ref.get("version")
        or policy_attestation.get("digest") != policy_ref.get("digest")
        or type(policy_attestation.get("resolver_id")) is not str
        or not cast(str, policy_attestation.get("resolver_id")).strip()
    ):
        raise ReleaseProofError("receipt policy attestation diverges from the policy artifact")
    for name in ("authentication_context_hash", "nonce_digest", "idempotency_digest"):
        _required_sha256(value.get(name), f"binding.{name}")
    for name in ("principal_verified_at", "principal_expires_at"):
        _timestamp(value.get(name), f"binding.{name}")
    if not (
        _timestamp(value["principal_verified_at"], "binding.principal_verified_at")
        <= _timestamp(value["requested_at"], "binding.requested_at")
        <= _timestamp(value["authorized_at"], "binding.authorized_at")
        < _timestamp(value["expires_at"], "binding.expires_at")
        <= _timestamp(value["principal_expires_at"], "binding.principal_expires_at")
    ):
        raise ReleaseProofError("receipt principal and authorization time ordering is invalid")
    return {SIDE_EFFECT_BINDING_KEY: cast(dict[str, Any], json.loads(canonical_json(value)))}


def _verify_historical_times(request: dict[str, Any], receipt: DecisionReceipt) -> None:
    try:
        requested = _timestamp(request.get("requested_at"), "request.requested_at")
        issued = _timestamp(receipt.timestamp, "receipt.timestamp")
        expires = _timestamp(receipt.expires_at, "receipt.expires_at")
        if not requested <= issued < expires:
            raise ReleaseProofError("receipt was not valid at its historical issuance time")
        evidence = request.get("evidence")
        if type(evidence) is not list or not evidence:
            raise ReleaseProofError("request evidence is missing")
        ids: set[str] = set()
        for item in evidence:
            if type(item) is not dict or set(item) != {
                "evidence_id",
                "evidence_type",
                "digest",
                "issuer",
                "issued_at",
                "expires_at",
            }:
                raise ReleaseProofError("request evidence shape is incompatible")
            evidence_id = _required_text(item["evidence_id"], "evidence_id")
            if evidence_id in ids:
                raise ReleaseProofError("duplicate request evidence identifier")
            ids.add(evidence_id)
            if not (
                _timestamp(item["issued_at"], "evidence.issued_at")
                <= requested
                < _timestamp(item["expires_at"], "evidence.expires_at")
            ):
                raise ReleaseProofError("evidence was not valid at request time")
    except (TypeError, ValueError) as exc:
        raise ReleaseProofError(f"historical time verification failed: {exc}") from exc


def _timestamp(value: object, name: str) -> datetime:
    text = _required_text(value, name)
    if not text.endswith("Z"):
        raise ReleaseProofError(f"{name} must use canonical UTC Z form")
    result = datetime.fromisoformat(text[:-1] + "+00:00")
    if result.isoformat().replace("+00:00", "Z") != text:
        raise ReleaseProofError(f"{name} is not canonical")
    return result


def _summary_payload(value: Mapping[str, Any]) -> bytes:
    return _CONSUMPTION_DOMAIN + canonical_json(dict(value)).encode("utf-8")


def _manifest_entries(payloads: Mapping[str, bytes]) -> list[dict[str, Any]]:
    return _RELEASE_PACK_CODEC.manifest_entries(payloads)


def _verification_metadata() -> dict[str, Any]:
    value = _RELEASE_PACK_CODEC.manifest_payload([])["verification"]
    return cast(dict[str, Any], value)


def _manifest_payload(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return _RELEASE_PACK_CODEC.manifest_payload(entries)


def _pack_digest(payload: Mapping[str, Any]) -> str:
    return _RELEASE_PACK_CODEC.pack_digest(payload)


def _read_exact_pack(
    root: Path,
    *,
    open_directory: sealed_pack.OpenDirectory | None = None,
    assert_path_identity: sealed_pack.AssertPathIdentity | None = None,
) -> dict[str, bytes]:
    directory_opener = open_directory or _open_directory
    identity_assertion = assert_path_identity or _assert_path_identity
    return _RELEASE_PACK_CODEC.read_exact_pack(
        root,
        open_directory=directory_opener,
        read_file_at=_read_file_at,
        assert_membership=_assert_exact_membership,
        assert_path_identity=identity_assertion,
    )


def _strict_json(data: bytes, name: str) -> Any:
    return _RELEASE_PACK_CODEC.strict_json(data, name)


def _strict_jsonl(data: bytes, name: str) -> list[dict[str, Any]]:
    return _RELEASE_PACK_CODEC.strict_jsonl(data, name)


def _json_bytes(value: Any) -> bytes:
    return _RELEASE_PACK_CODEC.json_bytes(value)


def _jsonl_bytes(values: list[dict[str, Any]]) -> bytes:
    return _RELEASE_PACK_CODEC.jsonl_bytes(values)


def _write_new(path: Path, data: bytes) -> None:
    sealed_pack.write_new(
        path,
        data,
        open_directory=_open_directory,
        write_new_at=_write_new_at,
        assert_path_identity=_assert_path_identity,
    )


def _public_key(
    path: str | Path,
    key_id: str,
    *,
    path_capability: AttestedDirectory | None = None,
) -> Ed25519Signer:
    if path_capability is not None:
        require_attested_directory(path_capability, error_type=ReleaseProofError)
    raw = (
        path_capability.read_bytes(
            path_capability.relative_from_display(path),
            max_size=32,
        )
        if path_capability is not None
        else _secure_read_file(Path(path), "external public key")
    )
    if len(raw) != 32:
        raise ReleaseProofError("external public key must be a 32-byte regular file")
    return Ed25519Signer.from_public_bytes(raw, key_id=key_id)


def _open_directory(path: Path, *, create: bool = False) -> tuple[int, tuple[int, int]]:
    return sealed_pack.open_directory(path, create=create, error_type=ReleaseProofError)


def _assert_path_identity(path: Path, expected: tuple[int, int]) -> None:
    sealed_pack.assert_path_identity(
        path,
        expected,
        open_directory=_open_directory,
        error_type=ReleaseProofError,
    )


def _open_or_create_empty_directory(path: Path) -> tuple[int, tuple[int, int]]:
    return sealed_pack.open_or_create_empty_directory(
        path,
        open_directory=_open_directory,
        error_type=ReleaseProofError,
    )


def _assert_exact_membership(parent_fd: int, expected: frozenset[str], label: str) -> None:
    sealed_pack.assert_exact_membership(
        parent_fd,
        expected,
        label,
        error_type=ReleaseProofError,
    )


def _read_fd_exact(descriptor: int, size: int, label: str) -> bytes:
    return sealed_pack.read_fd_exact(
        descriptor,
        size,
        label,
        error_type=ReleaseProofError,
    )


def _read_file_at(parent_fd: int, name: str, label: str) -> bytes:
    return sealed_pack.read_file_at(
        parent_fd,
        name,
        label,
        max_file_size=_MAX_FILE_SIZE,
        read_exact=_read_fd_exact,
        error_type=ReleaseProofError,
    )


def _secure_read_file(path: Path, label: str) -> bytes:
    return sealed_pack.secure_read_file(
        path,
        label,
        open_directory=_open_directory,
        read_file_at=_read_file_at,
        assert_path_identity=_assert_path_identity,
    )


def _secure_sha256_file(path: Path, label: str) -> str:
    return sealed_pack.secure_sha256_file(
        path,
        label,
        max_size=_MAX_REFERENCE_ARTIFACT_SIZE,
        open_directory=_open_directory,
        assert_path_identity=_assert_path_identity,
        error_type=ReleaseProofError,
    )


def _write_new_at(parent_fd: int, name: str, data: bytes) -> None:
    sealed_pack.write_new_at(
        parent_fd,
        name,
        data,
        max_file_size=_MAX_FILE_SIZE,
        read_exact=_read_fd_exact,
        error_type=ReleaseProofError,
    )


def _plain(value: Mapping[str, Any]) -> dict[str, Any]:
    thawed = deep_thaw_json(value)
    if type(thawed) is not dict:
        raise ReleaseProofError("expected a JSON object")
    return cast(dict[str, Any], thawed)


def _text(value: object, name: str) -> str:
    return _required_text(value, name)


def _required_text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ReleaseProofError(f"{name} must be a non-empty string")
    return value


def _sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA256


def _required_sha256(value: object, name: str) -> str:
    return _RELEASE_PACK_CODEC.require_sha256(value, name)


def _positive_int(value: object, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReleaseProofError(f"{name} must be a positive integer")
    return value
