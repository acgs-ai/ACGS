"""Externally pinned proof packs for the local fixture-only Spend Guard.

Verification consumes only sealed public evidence, an external public-key trust
bundle, and an out-of-band pack digest. It never opens the live spend or
consumption stores and never invokes the fixture provider.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from gove_zone.audit import AuditCheckpoint, AuditCheckpointAnchor, ChainHashAuditStore
from gove_zone.authorization import (
    EXECUTION_REFUSAL_EVIDENCE_SCHEMA,
    AuthorizationReasonCode,
    ExecutionReasonCode,
    ExecutionRefusalEvidence,
    PolicyArtifactAttestation,
    SideEffectAuthorization,
    strict_json_hash,
)
from gove_zone.decision import Decision, RecordKind, canonical_json
from gove_zone.executor import _evidence_digest
from gove_zone.proof_pack import (
    AssertPathIdentity,
    OpenDirectory,
    SealedPackCodec,
    SealedPackSchema,
)
from gove_zone.receipt import DecisionReceipt
from gove_zone.replay import (
    execution_refusal_error,
    replay_checkpointed_bundle,
    replay_from_side_store,
)
from gove_zone.replay_store import ReplaySideStore
from gove_zone.signing import (
    Ed25519Signer,
    LifecycleAttestation,
    LifecycleVerifierRegistry,
    ReceiptSigner,
)
from gove_zone.spend_adapter import (
    SPEND_EXECUTION_BOUNDARY,
    SPEND_SERVER_ID,
    SPEND_TOOL_ID,
    SpendKernelPolicy,
)
from gove_zone.spend_guard import SPEND_OPERATION

SPEND_PROOF_SCHEMA = "gove-zone.spend-proof-pack/v1"
SPEND_TRUST_SCHEMA = "gove-zone.spend-proof-trust-bundle/v1"
SPEND_SCENARIO_SCHEMA = "gove-zone.spend-proof-scenario/v1"
SPEND_LOOP_TRUST_SCHEMA = "gove-zone.spend-proof-trust-bundle/v2"
SPEND_LOOP_SCENARIO_SCHEMA = "gove-zone.spend-proof-scenario/v2"
SPEND_LOOP_RUNTIME_SCHEMA = "gove-zone.spend-proof-runtime-bindings/v2"
SPEND_LOOP_POLICY_EVIDENCE_SCHEMA = "gove-zone.spend-proof-policy-evidence/v2"
SPEND_LOOP_CHECKPOINT_SCHEMA = "gove-zone.spend-proof-audit-checkpoint/v2"
SPEND_LOOP_CONSUMPTION_SUMMARY_SCHEMA = "gove-zone.spend-proof-consumption-summary/v2"
SPEND_LOOP_STORE_SUMMARY_SCHEMA = "gove-zone.spend-proof-store-summary/v2"
SPEND_RUNTIME_SCHEMA = "gove-zone.spend-proof-runtime-bindings/v1"
SPEND_POLICY_EVIDENCE_SCHEMA = "gove-zone.spend-proof-policy-evidence/v1"
SPEND_CHECKPOINT_SCHEMA = "gove-zone.spend-proof-audit-checkpoint/v1"
SPEND_CONSUMPTION_SUMMARY_SCHEMA = "gove-zone.spend-proof-consumption-summary/v1"
SPEND_STORE_SUMMARY_SCHEMA = "gove-zone.spend-proof-store-summary/v1"
_SPEND_EVENT_PAYLOAD_SCHEMA = "gove-zone.spend-integrity-event-payload/v1"
SPEND_PROOF_LANES = ("allow", "deny", "tamper")
SPEND_PROOF_PAYLOAD_FILES = (
    "audit-checkpoint.json",
    "audit.jsonl",
    "authorizations.jsonl",
    "consumption-summary.json",
    "fixture-journal.jsonl",
    "policy.json",
    "protocol-results.jsonl",
    "receipts.jsonl",
    "refusals.jsonl",
    "replay.jsonl",
    "requests.jsonl",
    "runtime-bindings.json",
    "scenario.json",
    "spend-store-summary.json",
)
_JSONL_FILES = frozenset(name for name in SPEND_PROOF_PAYLOAD_FILES if name.endswith(".jsonl"))
_MEDIA_TYPES = {
    name: "application/x-ndjson" if name in _JSONL_FILES else "application/json"
    for name in SPEND_PROOF_PAYLOAD_FILES
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_SUMMARY_DOMAIN = b"gove-zone:spend-proof-summary:v1\0"
_SPEND_EVENT_DOMAIN = b"gove-zone:spend-integrity-event:v1\0"
_FORBIDDEN_KEYS = {
    "nonce",
    "idempotency_key",
    "authentication_context",
    "binding_hmac_key",
    "hmac_key",
    "private_key",
    "token",
    "secret",
}
_PIN_KEYS = frozenset(
    {"tenant_id", "policy_version", "policy_digest", "policy_attestation", "target"}
)
_REQUEST_KEYS = frozenset(
    {
        "actor_id",
        "actor_role",
        "approval_digest",
        "argument_hash",
        "arguments",
        "authority",
        "environment",
        "execution_boundary",
        "expected_stop_generation",
        "idempotency_digest",
        "lane",
        "operation",
        "payment_hash",
        "policy",
        "record_id",
        "request_id",
        "requested_at",
        "resource",
        "server_id",
        "side_effect_class",
        "tenant_id",
        "tool",
    }
)
_ARGUMENT_KEYS = frozenset(
    {
        "approval",
        "approval_digest",
        "budget_probe",
        "expected_stop_generation",
        "identity",
        "payment",
        "policy",
        "rules",
        "schema",
    }
)
_IDENTITY_KEYS = frozenset(
    {
        "actor_id",
        "actor_role",
        "authority",
        "environment",
        "request_id",
        "requested_at",
        "resource",
        "tenant_id",
    }
)
_PAYMENT_KEYS = frozenset(
    {"amount", "amount_minor", "currency", "provider", "recipient", "reference"}
)
_POLICY_REF_KEYS = frozenset({"bundle_id", "digest", "version"})
_BUDGET_PROBE_KEYS = frozenset(
    {
        "base_generation",
        "budget_snapshot_digest",
        "reason_code",
        "request_digest",
        "rules_digest",
        "snapshot_digest",
        "stop_generation",
    }
)
_RULE_KEYS = frozenset(
    {
        "anomaly_floor_minor",
        "anomaly_growth_basis_points",
        "anomaly_window_seconds",
        "currency",
        "daily_limit_minor",
        "digest",
        "hourly_limit_minor",
        "loop_limit_count",
        "loop_window_seconds",
        "monthly_limit_minor",
        "rate_limit_count",
        "rate_window_seconds",
        "single_limit_minor",
        "vendor_monthly_limits",
    }
)
_AUTHORIZATION_KEYS = frozenset(
    {
        "approved_arguments_hash",
        "audit_event_hash",
        "audit_event_id",
        "binding_hash",
        "decision",
        "lane",
        "original_arguments_hash",
        "previous_audit_hash",
        "reason_codes",
        "receipt_hash",
        "receipt_id",
        "record_id",
        "request_id",
        "reserved_binding",
    }
)
_PROTOCOL_KEYS = frozenset(
    {
        "argument_hash",
        "audit_event_hash",
        "audit_event_id",
        "decision",
        "executed",
        "lane",
        "provider_delta",
        "reason_code",
        "receipt_hash",
        "receipt_id",
        "record_id",
        "request_id",
        "result_digest",
        "status",
    }
)
_AUDIT_WRAPPER_KEYS = frozenset({"event", "event_id", "lane", "lifecycle_events", "record_id"})
_AUDIT_EVENT_KEYS = frozenset(
    {
        "_audit_checkpoint_parent_hash",
        "action_tier",
        "actor",
        "argument_hash",
        "decision",
        "decision_request_hash",
        "declared_action_tier",
        "event_hash",
        "event_id",
        "goal",
        "matched_rules",
        "path",
        "policy_version",
        "previous_hash",
        "reason",
        "record_kind",
        "state_hash",
        "timestamp_iso",
        "tool",
        "transformed_args",
    }
)
_EXECUTION_AUDIT_EVENT_KEYS = frozenset(
    {*_AUDIT_EVENT_KEYS, "execution_evidence", "lifecycle_attestation"}
)
# A refusal record carries evidence but no lifecycle attestation: it attests that
# nothing ran, so there is no execution to attest to. The shared refusal contract
# rejects an attestation outright, and this key set keeps one from being smuggled
# in ahead of that check.
_REFUSAL_AUDIT_EVENT_KEYS = frozenset({*_AUDIT_EVENT_KEYS, "execution_evidence"})
# The only refusal this scenario's tamper lane can legitimately prove: the
# executor rejecting a substituted actor against the reserved binding. Pinning
# it here rather than at each use keeps the evidence claim and the public
# protocol result from drifting into disagreeing about what was refused.
_LANE_REFUSAL_REASON_CODE = ExecutionReasonCode.BINDING_MISMATCH.value
# What a refusal record must repeat verbatim from the decision it refused. The
# rest of the record's fields are legitimately its own (it is a later, denying
# event with its own identity, hashes and evidence), so binding them would
# reject genuine packs. These are the claims that identify *which* attempt was
# refused: a record that verifies perfectly but names another actor, tool,
# payload, policy or goal proves nothing about this one.
_REFUSAL_AUTHORIZATION_BOUND_KEYS = frozenset(
    {
        "action_tier",
        "actor",
        "argument_hash",
        "declared_action_tier",
        "goal",
        "path",
        "policy_version",
        "tool",
    }
)
_EXECUTION_EVIDENCE_KEYS = frozenset(
    {
        "adapter_artifact_digest",
        "adapter_id_digest",
        "argument_hash",
        "attempt_id_digest",
        "authorization_audit_digest",
        "binding_hash",
        "consumption_state",
        "execution_boundary_digest",
        "idempotency_digest",
        "nonce_digest",
        "phase",
        "reason_code",
        "receipt_hash",
        "receipt_id_digest",
        "request_id_digest",
        "tenant_digest",
    }
)
_REPLAY_WRAPPER_KEYS = frozenset({"event_id", "lane", "record_id", "side_record"})
_REPLAY_SIDE_KEYS = frozenset(
    {
        "actor",
        "args",
        "argument_hash",
        "decision",
        "event_id",
        "goal",
        "path",
        "policy_version",
        "state",
        "tool",
    }
)
_REPLAY_STATE_KEYS = frozenset(
    {
        "actor_role",
        "authentication_context_hash",
        "authority",
        "environment",
        "evidence_digest",
        "execution_boundary",
        "operation",
        "policy_attestation_artifact_id",
        "policy_attestation_digest",
        "policy_attestation_resolver_id",
        "policy_attestation_tenant_id",
        "policy_attestation_version",
        "policy_bundle_id",
        "policy_digest",
        "policy_version",
        "request_id",
        "resource",
        "server_id",
        "side_effect_class",
        "tenant_id",
        "tool",
    }
)
_RECEIPT_WRAPPER_KEYS = frozenset({"lane", "receipt", "record_id"})
_REFUSAL_KEYS = frozenset({"lane", "reason_codes", "receipt", "record_id"})
_RECEIPT_KEYS = frozenset(
    {
        "action_tier",
        "actor",
        "approval_chain_summary",
        "argument_hash",
        "audit_event_hash",
        "authority",
        "constraints",
        "decision",
        "declared_goal",
        "execution_boundary",
        "expires_at",
        "matched_rules",
        "policy_bundle_id",
        "policy_hash",
        "policy_version",
        "previous_audit_hash",
        "proposed_action",
        "receipt_hash",
        "receipt_id",
        "request_id",
        "signature",
        "signature_algorithm",
        "signing_key_id",
        "subject",
        "tenant_id",
        "timestamp",
        "transformations",
        "validator_id",
        "validator_role",
    }
)
_APPROVAL_CHAIN_KEYS = frozenset({"authority", "proposer", "validator_id", "validator_role"})
_CHECKPOINT_WRAPPER_KEYS = frozenset({"event_id", "event_ids", "checkpoint"})
_SUMMARY_WRAPPER_KEYS = frozenset(
    {"purpose", "key_id", "algorithm", "payload_hash", "payload", "signature"}
)
_CONSUMPTION_PAYLOAD_KEYS = frozenset(
    {
        "audit_event_hash",
        "audit_event_id",
        "lane",
        "receipt_hash",
        "receipt_id",
        "record",
        "result_digest",
        "schema",
    }
)
_CONSUMPTION_RECORD_KEYS = frozenset(
    {
        "attempt_id",
        "binding_hash",
        "idempotency_digest",
        "nonce_hash",
        "receipt_hash",
        "receipt_id",
        "recovery_authority",
        "recovery_evidence_digest",
        "recovery_reason_code",
        "reserved_at",
        "revoked_at",
        "state",
        "tenant_id",
        "updated_at",
    }
)
_SPEND_PAYLOAD_KEYS = frozenset(
    {"anchor", "controls", "events", "intents", "lane", "outcomes", "schema"}
)
_SPEND_ANCHOR_KEYS = frozenset(
    {"event_count", "generation", "head_hash", "key_id", "namespace", "store_id"}
)
_SPEND_EVENT_KEYS = frozenset(
    {
        "entity_id",
        "event_hash",
        "event_id",
        "event_type",
        "generation",
        "occurred_at_us",
        "payload_digest",
        "payload_json",
        "previous_hash",
    }
)
_SPEND_INTENT_KEYS = frozenset(
    {
        "amount_minor",
        "approval_digest",
        "argument_digest",
        "attempt_digest",
        "budget_rules_digest",
        "budget_snapshot_digest",
        "budget_snapshot_json",
        "currency",
        "idempotency_digest",
        "loop_fingerprint_digest",
        "policy_digest",
        "provider",
        "receipt_digest",
        "recipient",
        "reference_digest",
        "reserved_at_us",
        "semantic_digest",
        "spend_id",
        "state_generation",
        "stop_generation",
        "tenant_id",
    }
)
_SPEND_OUTCOME_KEYS = frozenset(
    {
        "provider_reference_digest",
        "result_digest",
        "spend_id",
        "state",
        "transitioned_at_us",
        "uncertainty_digest",
    }
)
_SPEND_CONTROL_KEYS = frozenset(
    {
        "authority_digest",
        "changed_at_us",
        "enabled",
        "reason_digest",
        "stop_generation",
        "tenant_id",
    }
)
_JOURNAL_WRAPPER_KEYS = frozenset({"event", "lane", "record_id"})
_JOURNAL_EVENT_KEYS = frozenset(
    {
        "envelope_digest",
        "event_hash",
        "idempotency_digest",
        "previous_hash",
        "provider_reference",
        "result_digest",
        "schema",
        "sequence",
        "status",
        "uncertainty_digest",
    }
)


class SpendProofError(RuntimeError):
    """The spend proof pack or its external trust material is invalid."""


SPEND_PROOF_CODEC = SealedPackCodec(
    SealedPackSchema(
        schema=SPEND_PROOF_SCHEMA,
        digest_domain=b"gove-zone:spend-proof-pack:v1\0",
        media_types=_MEDIA_TYPES,
        verification={
            "mode": "external-pins-and-offline-replay",
            "lanes": list(SPEND_PROOF_LANES),
        },
        jsonl_identity_key="record_id",
        error_type=SpendProofError,
    ),
    error_type=SpendProofError,
)


def _exact_dict(value: object, keys: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(keys):
        raise SpendProofError(f"{label} has an incompatible shape")
    return cast(dict[str, Any], value)


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise SpendProofError(f"{label} must be canonical nonempty text")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise SpendProofError(f"{label} must be lowercase SHA-256")
    return value


def _assert_public(value: Any, *, label: str, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str or key in _FORBIDDEN_KEYS:
                raise SpendProofError(f"{label} contains a forbidden field")
            _assert_public(item, label=label, path=(*path, key))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_public(item, label=label, path=(*path, str(index)))
        return
    if value is None or type(value) in {bool, int, float}:
        return
    if type(value) is not str:
        raise SpendProofError(f"{label} contains a non-JSON value")
    if value.startswith("/") or _WINDOWS_PATH_RE.match(value):
        raise SpendProofError(f"{label} contains an absolute path")
    if "PRIVATE KEY" in value or "fixture-idempotency" in value or "fixture-nonce" in value:
        raise SpendProofError(f"{label} contains secret fixture material")


@dataclass(frozen=True, slots=True)
class SpendProofPayloads:
    files: dict[str, bytes]

    @classmethod
    def from_values(cls, values: dict[str, Any]) -> SpendProofPayloads:
        if set(values) != set(SPEND_PROOF_PAYLOAD_FILES):
            raise SpendProofError("spend proof values do not match the fixed member set")
        files: dict[str, bytes] = {}
        for name in SPEND_PROOF_PAYLOAD_FILES:
            value = values[name]
            _assert_public(value, label=name)
            if name in _JSONL_FILES:
                if type(value) is not list:
                    raise SpendProofError(f"{name} must be a record list")
                files[name] = SPEND_PROOF_CODEC.jsonl_bytes(cast(list[dict[str, Any]], value))
            else:
                files[name] = SPEND_PROOF_CODEC.json_bytes(value)
        return cls(files)


@dataclass(frozen=True, slots=True)
class SpendProofPack:
    directory: Path
    pack_digest: str


@dataclass(frozen=True, slots=True)
class _TrustKey:
    purpose: str
    key_id: str
    algorithm: str
    public_bytes_hex: str

    @classmethod
    def parse(cls, value: object, label: str) -> _TrustKey:
        row = _exact_dict(
            value,
            {"purpose", "key_id", "algorithm", "public_bytes_hex"},
            label,
        )
        purpose = _text(row["purpose"], f"{label}.purpose")
        key_id = _text(row["key_id"], f"{label}.key_id")
        if row["algorithm"] != "ed25519":
            raise SpendProofError(f"{label}.algorithm is unsupported")
        raw_hex = _text(row["public_bytes_hex"], f"{label}.public_bytes_hex")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            raise SpendProofError(f"{label}.public_bytes_hex is invalid") from None
        if len(raw) != 32:
            raise SpendProofError(f"{label}.public_bytes_hex must encode 32 bytes")
        return cls(purpose, key_id, "ed25519", raw_hex)

    def verifier(self) -> Ed25519Signer:
        return Ed25519Signer.from_public_bytes(bytes.fromhex(self.public_bytes_hex), self.key_id)


@dataclass(frozen=True, slots=True)
class _TrustLane:
    tenant_id: str
    policy_version: str
    policy_digest: str
    policy_attestation: dict[str, Any]
    target: dict[str, Any]
    checkpoint_authority_id: str
    lifecycle_authority_id: str
    keys: dict[str, _TrustKey]

    @classmethod
    def parse(cls, value: object, lane: str) -> _TrustLane:
        row = _exact_dict(
            value,
            {
                "tenant_id",
                "policy_version",
                "policy_digest",
                "policy_attestation",
                "target",
                "checkpoint_authority_id",
                "lifecycle_authority_id",
                "keys",
            },
            f"trust.{lane}",
        )
        target = _exact_dict(
            row["target"],
            {"server_id", "tool", "operation", "execution_boundary", "provider", "rules_digest"},
            f"trust.{lane}.target",
        )
        if target != {
            "server_id": SPEND_SERVER_ID,
            "tool": SPEND_TOOL_ID,
            "operation": SPEND_OPERATION,
            "execution_boundary": SPEND_EXECUTION_BOUNDARY,
            "provider": "stripe-test",
            "rules_digest": _digest(target["rules_digest"], "rules_digest"),
        }:
            raise SpendProofError(f"trust.{lane}.target is unsupported")
        raw_keys = _exact_dict(
            row["keys"],
            {
                "receipt",
                "refusal",
                "audit-checkpoint",
                "consumption-summary",
                "spend-summary",
                "lifecycle-attestation",
            },
            f"trust.{lane}.keys",
        )
        keys = {
            name: _TrustKey.parse(raw_keys[name], f"trust.{lane}.keys.{name}") for name in raw_keys
        }
        if any(key.purpose != name for name, key in keys.items()):
            raise SpendProofError(f"trust.{lane} key purpose mismatch")
        checkpoint_authority_id = _text(
            row["checkpoint_authority_id"], f"trust.{lane}.checkpoint_authority_id"
        )
        lifecycle_authority_id = _text(
            row["lifecycle_authority_id"], f"trust.{lane}.lifecycle_authority_id"
        )
        if checkpoint_authority_id != f"audit-checkpoint:spend-proof:{lane}":
            raise SpendProofError(f"trust.{lane} checkpoint authority mismatch")
        if lifecycle_authority_id in {"audit-checkpoint", checkpoint_authority_id}:
            raise SpendProofError(f"trust.{lane} lifecycle authority is not separated")
        if keys["lifecycle-attestation"].key_id == keys["audit-checkpoint"].key_id:
            raise SpendProofError(f"trust.{lane} lifecycle key is not separated")
        attestation = _exact_dict(
            row["policy_attestation"],
            {"tenant_id", "artifact_id", "policy_version", "digest", "resolver_id"},
            f"trust.{lane}.policy_attestation",
        )
        return cls(
            _text(row["tenant_id"], f"trust.{lane}.tenant_id"),
            _text(row["policy_version"], f"trust.{lane}.policy_version"),
            _digest(row["policy_digest"], f"trust.{lane}.policy_digest"),
            attestation,
            target,
            checkpoint_authority_id,
            lifecycle_authority_id,
            keys,
        )

    def pin(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "policy_attestation": self.policy_attestation,
            "target": self.target,
        }


@dataclass(slots=True)
class _StaticAuditAnchor(AuditCheckpointAnchor):
    namespace: str
    checkpoint: AuditCheckpoint

    def read(self, namespace: str) -> AuditCheckpoint | None:
        return self.checkpoint if namespace == self.namespace else None

    def compare_and_swap(
        self,
        namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool:
        del namespace, expected, replacement
        return False


def _parse_trust(value: object) -> dict[str, _TrustLane]:
    root = _exact_dict(value, {"schema", "lanes"}, "trust bundle")
    lane_names: tuple[str, ...]
    if root["schema"] == SPEND_TRUST_SCHEMA:
        lane_names = SPEND_PROOF_LANES
    elif root["schema"] == SPEND_LOOP_TRUST_SCHEMA:
        lane_names = ("loop",)
    else:
        raise SpendProofError("trust bundle schema is unsupported")
    lanes = _exact_dict(root["lanes"], set(lane_names), "trust lanes")
    parsed = {lane: _TrustLane.parse(lanes[lane], lane) for lane in lane_names}
    _lifecycle_verifiers(parsed)
    return parsed


def _lifecycle_verifiers(trust: dict[str, _TrustLane]) -> LifecycleVerifierRegistry:
    try:
        return LifecycleVerifierRegistry(
            (
                lane.lifecycle_authority_id,
                lane.keys["lifecycle-attestation"].verifier(),
            )
            for lane in trust.values()
        )
    except (TypeError, ValueError) as exc:
        raise SpendProofError(f"lifecycle trust registry is invalid: {exc}") from exc


def _records(values: Any, label: str) -> list[dict[str, Any]]:
    if type(values) is not list:
        raise SpendProofError(f"{label} must be JSONL records")
    rows = cast(list[dict[str, Any]], values)
    if any(type(row) is not dict or type(row.get("record_id")) is not str for row in rows):
        raise SpendProofError(f"{label} records are invalid")
    return rows


def _verify_execution_refusal_event(
    event: dict[str, Any],
    authorization_event: dict[str, Any],
    *,
    label: str,
) -> ExecutionRefusalEvidence:
    """Semantically verify a refused lane's EXECUTION_REFUSAL record.

    The single shared refusal contract decides what a refusal record may say —
    the same one bundle replay and the release proof pack use — so a refusal
    cannot mean one thing here and another there. On top of that contract this
    binds the record to the authorization it refused: a record that verifies
    perfectly but describes a different attempt proves nothing about this one.
    """

    if event.get("record_kind") != RecordKind.EXECUTION_REFUSAL.value:
        raise SpendProofError(f"{label} execution refusal record kind mismatch")
    refusal_error = execution_refusal_error(event)
    if refusal_error is not None:
        raise SpendProofError(f"{label} execution refusal is invalid: {refusal_error}")
    evidence = ExecutionRefusalEvidence.from_audit_evidence(
        cast(dict[str, Any], event["execution_evidence"])
    )
    if any(
        event.get(name) != authorization_event.get(name)
        for name in _REFUSAL_AUTHORIZATION_BOUND_KEYS
    ):
        raise SpendProofError(f"{label} execution refusal authorization binding mismatch")
    return evidence


def _audit_lifecycle_events(
    wrapper: dict[str, Any],
    *,
    label: str,
    successful: bool,
    trust: _TrustLane,
    refused: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if successful and refused:
        raise SpendProofError(f"{label} cannot be both successful and refused")
    authorization_event = _exact_dict(wrapper.get("event"), _AUDIT_EVENT_KEYS, f"{label}.event")
    raw_events = wrapper.get("lifecycle_events")
    if type(raw_events) is not list:
        raise SpendProofError(f"{label}.lifecycle_events must be a list")
    # An allow lane commits the decision plus the reserved/succeeded pair; a
    # refused lane commits the decision plus exactly one refusal record. The
    # exact count and position are what reject a missing, duplicated, reordered
    # or interleaved record before any of it is trusted.
    if successful:
        expected_count = 3
    elif refused:
        expected_count = 2
    else:
        expected_count = 1
    if len(raw_events) != expected_count:
        raise SpendProofError(f"{label} lifecycle coverage mismatch")
    events: list[dict[str, Any]] = []
    for index, raw_event in enumerate(raw_events):
        if index == 0:
            keys = _AUDIT_EVENT_KEYS
        elif refused:
            keys = _REFUSAL_AUDIT_EVENT_KEYS
        else:
            keys = _EXECUTION_AUDIT_EVENT_KEYS
        events.append(_exact_dict(raw_event, keys, f"{label}.lifecycle_events[{index}]"))
    if events[0] != authorization_event:
        raise SpendProofError(f"{label} authorization/lifecycle event mismatch")
    if authorization_event.get("record_kind") != RecordKind.POLICY_DECISION.value:
        raise SpendProofError(f"{label} authorization record kind mismatch")
    if refused:
        _verify_execution_refusal_event(events[1], authorization_event, label=label)
        return authorization_event, events
    if not successful:
        return authorization_event, events

    expected_lifecycle = (
        ("receipt.execution.reserved", "claim_committed", "RESERVED"),
        ("receipt.execution.succeeded", "terminal", "SUCCEEDED"),
    )
    common_evidence: dict[str, Any] | None = None
    for event, (reason_code, phase, state) in zip(events[1:], expected_lifecycle, strict=True):
        evidence = _exact_dict(
            event.get("execution_evidence"),
            _EXECUTION_EVIDENCE_KEYS,
            f"{label}.{phase}.execution_evidence",
        )
        attestation_value = _exact_dict(
            event.get("lifecycle_attestation"),
            {"authority_id", "key_id", "algorithm", "payload_hash", "signature"},
            f"{label}.{phase}.lifecycle_attestation",
        )
        try:
            attestation = LifecycleAttestation.from_dict(attestation_value)
        except (TypeError, ValueError) as exc:
            raise SpendProofError(f"{label} lifecycle attestation is malformed: {exc}") from exc
        lifecycle_key = trust.keys["lifecycle-attestation"]
        if (
            attestation.authority_id != trust.lifecycle_authority_id
            or attestation.key_id != lifecycle_key.key_id
            or attestation.algorithm != lifecycle_key.algorithm
        ):
            raise SpendProofError(f"{label} lifecycle attestation trust binding mismatch")
        if event.get("record_kind") != RecordKind.EXECUTION_LIFECYCLE.value:
            raise SpendProofError(f"{label} execution lifecycle record kind mismatch")
        if (
            event.get("decision") != "allow"
            or event.get("tool") != authorization_event.get("tool")
            or event.get("actor") != authorization_event.get("actor")
            or event.get("argument_hash") != authorization_event.get("argument_hash")
            or event.get("policy_version") != authorization_event.get("policy_version")
            or event.get("matched_rules") != [reason_code]
            or event.get("reason") != reason_code
            or evidence.get("reason_code") != reason_code
            or evidence.get("phase") != phase
            or evidence.get("consumption_state") != state
            or evidence.get("argument_hash") != authorization_event.get("argument_hash")
        ):
            raise SpendProofError(f"{label} execution lifecycle mismatch")
        stable = {
            key: value
            for key, value in evidence.items()
            if key not in {"reason_code", "phase", "consumption_state"}
        }
        if common_evidence is None:
            common_evidence = stable
        elif stable != common_evidence:
            raise SpendProofError(f"{label} execution lifecycle binding mismatch")
    return authorization_event, events


def _verify_execution_lifecycle_bindings(
    events: list[dict[str, Any]],
    *,
    receipt: DecisionReceipt,
    binding_hash: str,
    idempotency_digest: str,
    label: str,
) -> None:
    for event in events[1:]:
        evidence = cast(dict[str, Any], event["execution_evidence"])
        if (
            evidence.get("receipt_hash") != receipt.receipt_hash
            or evidence.get("binding_hash") != binding_hash
            or evidence.get("idempotency_digest") != idempotency_digest
        ):
            raise SpendProofError(f"{label} execution lifecycle receipt binding mismatch")


def _expected_refusal_evidence(
    *,
    receipt: DecisionReceipt,
    binding: dict[str, Any],
    binding_hash: str,
    authorization_audit_hash: str,
    phase: str,
    reason_code: str,
    attempt_id_digest: str,
    label: str,
) -> dict[str, str]:
    """Recompute the complete refusal evidence a genuine refusal must carry.

    Every claim is re-derived from the lane's receipt and its authenticated
    reserved binding — the same inputs the kernel builds the evidence from
    (``_build_refusal_evidence``) — so this is the whole cross-binding contract
    in one place rather than a hand-picked subset that silently omits fields.
    The route digest is rebuilt from ``server_id:tool:operation`` exactly as the
    kernel joins it, and the reserved binding is itself pinned to the public
    request elsewhere in this lane, so none of it can be self-asserted.

    ``attempt_id_digest`` is the one claim a pack cannot re-derive: the attempt
    id is runtime-random and a refused attempt exports no consumption record to
    carry it. The shared refusal contract couples it to the phase (empty unless
    post-reservation, a valid digest when it is), so it is threaded through from
    the contract-validated record rather than trusted independently.
    """

    route = ":".join(
        _text(binding[name], f"{label} reserved_binding.{name}")
        for name in ("server_id", "tool", "operation")
    )
    return {
        "schema": EXECUTION_REFUSAL_EVIDENCE_SCHEMA,
        "request_id_digest": _evidence_digest("request_id", receipt.request_id),
        "receipt_id_digest": _evidence_digest("receipt_id", receipt.receipt_id),
        "receipt_hash": receipt.receipt_hash,
        "tenant_digest": _evidence_digest(
            "tenant", _text(binding["tenant_id"], f"{label} reserved_binding.tenant_id")
        ),
        "execution_boundary_digest": _evidence_digest(
            "execution_boundary",
            _text(binding["execution_boundary"], f"{label} reserved_binding.execution_boundary"),
        ),
        "adapter_id_digest": _evidence_digest("adapter_id", route),
        "authorization_audit_digest": _evidence_digest(
            "authorization_audit",
            authorization_audit_hash,
        ),
        "binding_hash": binding_hash,
        "argument_hash": receipt.argument_hash,
        "attempt_id_digest": attempt_id_digest,
        "reason_code": reason_code,
        "phase": phase,
        "adapter_invoked": "false",
    }


def _verify_execution_refusal_bindings(
    event: dict[str, Any],
    *,
    receipt: DecisionReceipt,
    binding: dict[str, Any],
    binding_hash: str,
    authorization_audit_hash: str,
    expected_reason_code: str,
    label: str,
) -> None:
    """Bind the refusal to this exact receipt, tenant, route and audit event.

    The shared contract proves the record is a well-formed, self-consistent
    refusal of *some* attempt; this proves it is the refusal of *this* one.
    Checking a subset of the evidence is what let an attacker rewrite an
    unchecked claim — the tenant it refused — recompute the record's own
    ``state_hash``, rechain the audit and reseal the checkpoint under a key the
    mutated trust bundle trusts, and still be accepted: every check the pack ran
    was on values the attacker also controlled. So the comparison is exact and
    whole-dict: an omitted, added or altered claim is all one failure.
    """

    evidence = cast(dict[str, str], event["execution_evidence"])
    expected = _expected_refusal_evidence(
        receipt=receipt,
        binding=binding,
        binding_hash=binding_hash,
        authorization_audit_hash=authorization_audit_hash,
        # Phase and attempt coupling are the shared contract's to enforce; the
        # reason code is pinned against the lane's public protocol result below.
        phase=evidence.get("phase", ""),
        reason_code=expected_reason_code,
        attempt_id_digest=evidence.get("attempt_id_digest", ""),
        label=label,
    )
    if evidence != expected:
        raise SpendProofError(f"{label} execution refusal binding mismatch")


def _verify_checkpointed_audit(
    events: list[dict[str, Any]],
    checkpoint: AuditCheckpoint,
    checkpoint_key: _TrustKey,
    path: Path,
    *,
    label: str,
) -> ChainHashAuditStore:
    audit_path = _private_write(path, f"{label}-audit.jsonl", SPEND_PROOF_CODEC.jsonl_bytes(events))
    audit_store = ChainHashAuditStore(
        audit_path,
        checkpoint_anchor=_StaticAuditAnchor(checkpoint.namespace, checkpoint),
        checkpoint_namespace=checkpoint.namespace,
        checkpoint_verifier={checkpoint_key.key_id: checkpoint_key.verifier()},
        require_trusted_checkpoint=True,
    )
    report = audit_store.verify_checkpointed_chain()
    if not (
        report.get("valid") is True
        and report.get("strict") is True
        and report.get("checked") == len(events)
        and report.get("failures") == []
    ):
        raise SpendProofError(f"{label} checkpointed audit verification is incomplete")
    return audit_store


def _request_arguments(value: object, label: str) -> dict[str, Any]:
    arguments = _exact_dict(value, _ARGUMENT_KEYS, label)
    _exact_dict(arguments["identity"], _IDENTITY_KEYS, f"{label}.identity")
    _exact_dict(arguments["payment"], _PAYMENT_KEYS, f"{label}.payment")
    _exact_dict(arguments["policy"], _POLICY_REF_KEYS, f"{label}.policy")
    _exact_dict(arguments["budget_probe"], _BUDGET_PROBE_KEYS, f"{label}.budget_probe")
    _exact_dict(arguments["rules"], _RULE_KEYS, f"{label}.rules")
    return arguments


def _verify_request_derived_bindings(
    lane: str,
    request: dict[str, Any],
    arguments: dict[str, Any],
    authorization: SideEffectAuthorization,
) -> None:
    """Recompute public request summaries from receipt-bound evidence."""

    # The exporter summarizes the approved envelope.  A non-executable
    # decision approves no arguments, so its public summaries intentionally
    # describe the empty approval rather than implying an executable payment.
    approved = arguments if authorization.executable else {}
    approval = approved.get("approval")
    if approval is None:
        approval_digest = None
    elif type(approval) is dict:
        approval_digest = strict_json_hash(approval)
    else:
        raise SpendProofError(f"{lane} approved spend approval is invalid")
    if approved.get("approval_digest") != approval_digest:
        raise SpendProofError(f"{lane} approved spend approval digest mismatch")

    payment = approved.get("payment", {})
    if type(payment) is not dict:
        raise SpendProofError(f"{lane} approved spend payment is invalid")
    expected_stop_generation = approved.get("expected_stop_generation", 0)
    if type(expected_stop_generation) is not int or expected_stop_generation < 0:
        raise SpendProofError(f"{lane} approved spend stop generation is invalid")
    if authorization.executable:
        probe = cast(dict[str, Any], arguments["budget_probe"])
        if probe.get("stop_generation") != expected_stop_generation:
            raise SpendProofError(f"{lane} approved spend stop generation mismatch")

    binding_idempotency = authorization.reserved_binding.get("idempotency_digest")
    request_stop_generation = request.get("expected_stop_generation")
    if type(request_stop_generation) is not int:
        raise SpendProofError(f"{lane} request stop generation is invalid")
    if (
        request.get("approval_digest") != approval_digest
        or request.get("payment_hash") != strict_json_hash(payment)
        or request.get("idempotency_digest") != binding_idempotency
        or request_stop_generation != expected_stop_generation
    ):
        raise SpendProofError(f"{lane} request derived binding mismatch")


def _loop_probe_request_digest(
    request: dict[str, Any],
    arguments: dict[str, Any],
    idempotency_digest: str,
) -> str:
    payment = cast(dict[str, Any], arguments["payment"])
    approval = arguments["approval"]
    approval_digest = strict_json_hash(approval) if type(approval) is dict else None
    argument_digest = strict_json_hash(payment)
    semantic_digest = strict_json_hash(
        {
            "provider": payment["provider"],
            "recipient": payment["recipient"],
            "amount_minor": payment["amount_minor"],
            "currency": payment["currency"],
        }
    )
    return strict_json_hash(
        {
            "schema": "acgs.spend-budget-probe-request/v1",
            "tenant_id": request["tenant_id"],
            "provider": payment["provider"],
            "recipient": payment["recipient"],
            "currency": payment["currency"],
            "amount_minor": payment["amount_minor"],
            "attempt_digest": strict_json_hash(
                {"request_id": request["request_id"], "argument_digest": argument_digest}
            ),
            "reference_digest": strict_json_hash({"reference": payment["reference"]}),
            "argument_digest": argument_digest,
            "semantic_digest": semantic_digest,
            "loop_fingerprint_digest": strict_json_hash(
                {"semantic_digest": semantic_digest, "reference": payment["reference"]}
            ),
            "policy_digest": request["policy"]["digest"],
            "approval_digest": approval_digest,
            "idempotency_digest": idempotency_digest,
            "expected_stop_generation": arguments["expected_stop_generation"],
        }
    )


def _verify_loop_request_derived_bindings(
    lane: str,
    request: dict[str, Any],
    canonical_arguments: dict[str, Any],
) -> None:
    payment = cast(dict[str, Any], canonical_arguments["payment"])
    probe = cast(dict[str, Any], canonical_arguments["budget_probe"])
    approval = canonical_arguments["approval"]
    if approval is not None and type(approval) is not dict:
        raise SpendProofError(f"{lane} loop approval is invalid")
    approval_digest = strict_json_hash(approval) if type(approval) is dict else None
    expected_stop_generation = canonical_arguments["expected_stop_generation"]
    if (
        type(expected_stop_generation) is not int
        or isinstance(expected_stop_generation, bool)
        or expected_stop_generation < 0
    ):
        raise SpendProofError(f"{lane} loop stop generation is invalid")
    idempotency_digest = _digest(
        request.get("idempotency_digest"), f"{lane}.request.idempotency_digest"
    )
    request_stop_generation = request.get("expected_stop_generation")
    if type(request_stop_generation) is not int or request_stop_generation < 0:
        raise SpendProofError(f"{lane} request stop generation is invalid")
    if (
        canonical_arguments.get("approval_digest") != approval_digest
        or probe.get("stop_generation") != expected_stop_generation
        or request.get("approval_digest") != approval_digest
        or request.get("payment_hash") != strict_json_hash(payment)
        or request_stop_generation != expected_stop_generation
        or probe.get("request_digest")
        != _loop_probe_request_digest(request, canonical_arguments, idempotency_digest)
    ):
        raise SpendProofError(f"{lane} loop derived request binding mismatch")


def _receipt_wire(value: object, label: str) -> dict[str, Any]:
    receipt = _exact_dict(value, _RECEIPT_KEYS, label)
    _exact_dict(
        receipt["approval_chain_summary"],
        _APPROVAL_CHAIN_KEYS,
        f"{label}.approval_chain_summary",
    )
    transformations = receipt["transformations"]
    if type(transformations) is not list:
        raise SpendProofError(f"{label}.transformations must be a list")
    for index, item in enumerate(transformations):
        _exact_dict(item, {"field", "value"}, f"{label}.transformations[{index}]")
    return receipt


def _exact_rows(values: object, keys: frozenset[str], label: str) -> list[dict[str, Any]]:
    if type(values) is not list:
        raise SpendProofError(f"{label} must be a row list")
    return [_exact_dict(row, keys, f"{label}[{index}]") for index, row in enumerate(values)]


def _by_lane(values: Any, label: str, *, exactly_one: bool = True) -> dict[str, dict[str, Any]]:
    rows = _records(values, label)
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        lane = row.get("lane")
        if lane not in SPEND_PROOF_LANES or lane in result:
            raise SpendProofError(f"{label} lane coverage is invalid")
        result[cast(str, lane)] = row
    if exactly_one and set(result) != set(SPEND_PROOF_LANES):
        raise SpendProofError(f"{label} does not cover every lane exactly once")
    return result


def _checkpoint(value: object, label: str) -> AuditCheckpoint:
    row = _exact_dict(
        value,
        {
            "namespace",
            "generation",
            "head_hash",
            "previous_checkpoint_hash",
            "key_id",
            "algorithm",
            "signature",
        },
        label,
    )
    try:
        return AuditCheckpoint(**row)
    except (TypeError, ValueError) as exc:
        raise SpendProofError(f"{label} is invalid: {exc}") from exc


def _verify_summary(wrapper: object, key: _TrustKey, purpose: str, label: str) -> dict[str, Any]:
    row = _exact_dict(wrapper, _SUMMARY_WRAPPER_KEYS, label)
    payload = row["payload"]
    if type(payload) is not dict:
        raise SpendProofError(f"{label}.payload must be an object")
    payload_hash = _digest(row["payload_hash"], f"{label}.payload_hash")
    unsigned = {
        "purpose": purpose,
        "key_id": key.key_id,
        "algorithm": key.algorithm,
        "payload_hash": payload_hash,
    }
    if (
        row["purpose"] != purpose
        or row["key_id"] != key.key_id
        or row["algorithm"] != key.algorithm
        or strict_json_hash(payload) != payload_hash
        or type(row["signature"]) is not str
        or not key.verifier().verify(
            _SUMMARY_DOMAIN + canonical_json(unsigned).encode("utf-8"), row["signature"]
        )
    ):
        raise SpendProofError(f"{label} signature or payload binding is invalid")
    return cast(dict[str, Any], payload)


def signed_summary(payload: dict[str, Any], signer: ReceiptSigner, purpose: str) -> dict[str, Any]:
    """Create one public proof-layer summary signature."""

    payload_hash = strict_json_hash(payload)
    unsigned = {
        "purpose": purpose,
        "key_id": signer.key_id,
        "algorithm": signer.algorithm,
        "payload_hash": payload_hash,
    }
    return {
        **unsigned,
        "payload": payload,
        "signature": signer.sign(_SUMMARY_DOMAIN + canonical_json(unsigned).encode("utf-8")),
    }


def _private_write(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _verify_spend_summary(
    lane: str,
    summary: dict[str, Any],
    request: dict[str, Any],
    receipt: DecisionReceipt,
    protocol: dict[str, Any],
    trust: _TrustLane,
) -> None:
    summary = _exact_dict(summary, _SPEND_PAYLOAD_KEYS, f"spend.{lane}.payload")
    if summary.get("schema") != SPEND_STORE_SUMMARY_SCHEMA or summary.get("lane") != lane:
        raise SpendProofError("spend summary schema/lane mismatch")
    anchor = _exact_dict(summary["anchor"], _SPEND_ANCHOR_KEYS, f"spend.{lane}.anchor")
    events = _exact_rows(summary["events"], _SPEND_EVENT_KEYS, f"spend.{lane}.events")
    intents = _exact_rows(summary["intents"], _SPEND_INTENT_KEYS, f"spend.{lane}.intents")
    outcomes = _exact_rows(summary["outcomes"], _SPEND_OUTCOME_KEYS, f"spend.{lane}.outcomes")
    controls = _exact_rows(summary["controls"], _SPEND_CONTROL_KEYS, f"spend.{lane}.controls")
    previous = "0" * 64
    intent_rows: list[dict[str, Any]] = []
    outcome_rows: list[dict[str, Any]] = []
    control_rows: list[dict[str, Any]] = []
    for generation, event in enumerate(events, start=1):
        payload_json = _text(event.get("payload_json"), "spend event payload_json")
        payload_digest = hashlib.sha256(payload_json.encode()).hexdigest()
        document = {
            "generation": generation,
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "entity_id": event.get("entity_id"),
            "payload_digest": payload_digest,
            "previous_hash": previous,
            "occurred_at_us": event.get("occurred_at_us"),
        }
        expected_hash = hashlib.sha256(
            _SPEND_EVENT_DOMAIN + canonical_json(document).encode()
        ).hexdigest()
        if (
            event.get("generation") != generation
            or event.get("payload_digest") != payload_digest
            or event.get("previous_hash") != previous
            or event.get("event_hash") != expected_hash
        ):
            raise SpendProofError("spend event chain mismatch")
        payload = _exact_dict(
            json.loads(payload_json),
            {"schema", "event_type", "row"},
            "spend event payload",
        )
        event_type = event["event_type"]
        if type(event_type) is not str:
            raise SpendProofError("spend event type is invalid")
        row_keys = {
            "RESERVE": _SPEND_INTENT_KEYS,
            "OUTCOME": _SPEND_OUTCOME_KEYS,
            "CONTROL": _SPEND_CONTROL_KEYS,
        }.get(event_type)
        if row_keys is None:
            raise SpendProofError("spend event type is invalid")
        payload_row = _exact_dict(payload["row"], row_keys, "spend event row")
        if (
            payload["schema"] != _SPEND_EVENT_PAYLOAD_SCHEMA
            or canonical_json(payload) != payload_json
            or payload.get("event_type") != event_type
        ):
            raise SpendProofError("spend event payload mismatch")
        target = {
            "RESERVE": intent_rows,
            "OUTCOME": outcome_rows,
            "CONTROL": control_rows,
        }.get(event_type)
        if target is None:
            raise SpendProofError("spend event type is invalid")
        target.append(payload_row)
        previous = expected_hash
    if (
        anchor.get("generation") != len(events)
        or anchor.get("event_count") != len(events)
        or anchor.get("head_hash") != previous
        or intents != sorted(intent_rows, key=lambda row: row.get("spend_id", ""))
        or outcomes != sorted(outcome_rows, key=lambda row: row.get("spend_id", ""))
        or controls
        != sorted(
            control_rows, key=lambda row: (row.get("tenant_id", ""), row.get("stop_generation", 0))
        )
    ):
        raise SpendProofError("spend materialized state does not equal event replay")
    if lane == "allow":
        if len(intents) != 1 or len(outcomes) != 1 or len(events) != 2:
            raise SpendProofError("allow spend summary must contain one completed payment")
        intent, outcome = intents[0], outcomes[0]
        snapshot_json = _text(intent.get("budget_snapshot_json"), "budget snapshot")
        if (
            hashlib.sha256(snapshot_json.encode()).hexdigest()
            != intent.get("budget_snapshot_digest")
            or intent.get("receipt_digest") != receipt.receipt_hash
            or intent.get("policy_digest") != trust.policy_digest
            or intent.get("argument_digest") != request.get("payment_hash")
            or intent.get("budget_rules_digest") != trust.target["rules_digest"]
            or intent.get("idempotency_digest") != request.get("idempotency_digest")
            or intent.get("approval_digest") != request.get("approval_digest")
            or intent.get("stop_generation") != request.get("expected_stop_generation")
            or outcome.get("spend_id") != intent.get("spend_id")
            or outcome.get("state") != "SUCCEEDED"
            or outcome.get("result_digest") != protocol.get("result_digest")
        ):
            raise SpendProofError("allow spend cross-link mismatch")
    elif events or intents or outcomes or controls:
        raise SpendProofError(f"{lane} spend summary must prove zero mutation")


def _verify_v1_semantics(values: dict[str, Any], trust: dict[str, _TrustLane]) -> None:
    scenario = _exact_dict(values["scenario.json"], {"schema", "lanes"}, "scenario")
    runtime = _exact_dict(values["runtime-bindings.json"], {"schema", "lanes"}, "runtime")
    policy_root = _exact_dict(values["policy.json"], {"schema", "lanes"}, "policy")
    if (scenario["schema"], runtime["schema"], policy_root["schema"]) != (
        SPEND_SCENARIO_SCHEMA,
        SPEND_RUNTIME_SCHEMA,
        SPEND_POLICY_EVIDENCE_SCHEMA,
    ):
        raise SpendProofError("proof metadata schema is unsupported")
    for root, label in ((scenario, "scenario"), (runtime, "runtime"), (policy_root, "policy")):
        lanes = _exact_dict(root["lanes"], set(SPEND_PROOF_LANES), f"{label}.lanes")
        for lane in SPEND_PROOF_LANES:
            expected_keys = _PIN_KEYS if label != "policy" else frozenset({*_PIN_KEYS, "artifact"})
            row = _exact_dict(lanes[lane], expected_keys, f"{label}.{lane}")
            embedded = row if label != "policy" else {key: row[key] for key in trust[lane].pin()}
            if embedded != trust[lane].pin():
                raise SpendProofError(f"{label}.{lane} external trust mismatch")
    policies = cast(dict[str, Any], policy_root["lanes"])
    reconstructed: dict[str, SpendKernelPolicy] = {}
    for lane in SPEND_PROOF_LANES:
        row = _exact_dict(policies[lane], {*_PIN_KEYS, "artifact"}, f"policy.{lane}")
        try:
            attestation = PolicyArtifactAttestation(**trust[lane].policy_attestation)
            policy = SpendKernelPolicy.from_authorization_snapshot(row["artifact"])
        except (TypeError, ValueError) as exc:
            raise SpendProofError(f"policy.{lane} reconstruction failed: {exc}") from exc
        snapshot = policy.authorization_snapshot()
        if snapshot.digest != trust[lane].policy_digest or attestation.digest != snapshot.digest:
            raise SpendProofError(f"policy.{lane} digest/attestation mismatch")
        reconstructed[lane] = policy

    requests = _by_lane(values["requests.jsonl"], "requests")
    authorizations = _by_lane(values["authorizations.jsonl"], "authorizations")
    protocols = _by_lane(values["protocol-results.jsonl"], "protocol results")
    audits = _by_lane(values["audit.jsonl"], "audit")
    replays = _by_lane(values["replay.jsonl"], "replay")
    receipts = _by_lane(values["receipts.jsonl"], "receipts")
    refusals = _by_lane(values["refusals.jsonl"], "refusals", exactly_one=False)
    if set(refusals) != {"deny"}:
        raise SpendProofError("refusal evidence must cover only the deny lane")
    checkpoint_root = _exact_dict(
        values["audit-checkpoint.json"], {"schema", "lanes"}, "checkpoint"
    )
    if checkpoint_root["schema"] != SPEND_CHECKPOINT_SCHEMA:
        raise SpendProofError("checkpoint schema is unsupported")
    checkpoint_lanes = _exact_dict(
        checkpoint_root["lanes"], set(SPEND_PROOF_LANES), "checkpoint lanes"
    )
    consumption_root = _exact_dict(
        values["consumption-summary.json"], {"schema", "lanes"}, "consumption"
    )
    spend_root = _exact_dict(
        values["spend-store-summary.json"], {"schema", "lanes"}, "spend summary"
    )
    if (
        consumption_root["schema"] != SPEND_CONSUMPTION_SUMMARY_SCHEMA
        or spend_root["schema"] != SPEND_STORE_SUMMARY_SCHEMA
    ):
        raise SpendProofError("summary schema is unsupported")
    consumption_lanes = _exact_dict(
        consumption_root["lanes"], set(SPEND_PROOF_LANES), "consumption lanes"
    )
    spend_lanes = _exact_dict(spend_root["lanes"], set(SPEND_PROOF_LANES), "spend lanes")
    journal_rows = _records(values["fixture-journal.jsonl"], "fixture journal")

    with tempfile.TemporaryDirectory(prefix="gove-zone-spend-proof-") as temporary:
        private_root = Path(temporary)
        for lane in SPEND_PROOF_LANES:
            pin = trust[lane]
            request = _exact_dict(requests[lane], _REQUEST_KEYS, f"request.{lane}")
            authorization = _exact_dict(
                authorizations[lane], _AUTHORIZATION_KEYS, f"authorization.{lane}"
            )
            protocol = _exact_dict(protocols[lane], _PROTOCOL_KEYS, f"protocol.{lane}")
            audit_wrapper = _exact_dict(audits[lane], _AUDIT_WRAPPER_KEYS, f"audit.{lane}")
            replay_wrapper = _exact_dict(replays[lane], _REPLAY_WRAPPER_KEYS, f"replay.{lane}")
            receipt_wrapper = _exact_dict(receipts[lane], _RECEIPT_WRAPPER_KEYS, f"receipt.{lane}")
            if any(
                row.get("lane") != lane
                for row in (
                    request,
                    authorization,
                    protocol,
                    audit_wrapper,
                    replay_wrapper,
                    receipt_wrapper,
                )
            ):
                raise SpendProofError(f"{lane} lane wrapper mismatch")
            if request.get("tenant_id") != pin.tenant_id or request.get("policy") != {
                "version": pin.policy_version,
                "digest": pin.policy_digest,
            }:
                raise SpendProofError(f"{lane} request trust mismatch")
            if any(
                request.get(name) != value
                for name, value in pin.target.items()
                if name != "provider" and name != "rules_digest"
            ):
                raise SpendProofError(f"{lane} request route mismatch")
            arguments = _request_arguments(request.get("arguments"), f"request.{lane}.arguments")
            identity = cast(dict[str, Any], arguments["identity"])
            if strict_json_hash(arguments) != request.get("argument_hash") or any(
                request.get(name) != identity.get(name) for name in _IDENTITY_KEYS
            ):
                raise SpendProofError(f"{lane} request argument hash mismatch")
            receipt_value = _receipt_wire(receipt_wrapper.get("receipt"), f"receipt.{lane}.wire")
            try:
                receipt = DecisionReceipt.from_dict(receipt_value)
            except Exception as exc:
                raise SpendProofError(f"{lane} receipt is invalid: {exc}") from exc
            receipt_key = pin.keys["refusal" if lane == "deny" else "receipt"]
            verifier = receipt_key.verifier()
            if (
                receipt.compute_hash() != receipt.receipt_hash
                or receipt.signing_key_id != receipt_key.key_id
                or receipt.signature_algorithm != "ed25519"
                or not verifier.verify(receipt.receipt_hash.encode(), receipt.signature)
            ):
                raise SpendProofError(f"{lane} receipt signature is invalid")
            event, lifecycle_events = _audit_lifecycle_events(
                audit_wrapper,
                label=f"audit.{lane}",
                successful=lane == "allow",
                trust=pin,
                refused=lane == "tamper",
            )
            side = _exact_dict(
                replay_wrapper.get("side_record"),
                _REPLAY_SIDE_KEYS,
                f"replay.{lane}.side_record",
            )
            side_arguments = _request_arguments(side.get("args"), f"replay.{lane}.args")
            side_state = _exact_dict(side.get("state"), _REPLAY_STATE_KEYS, f"replay.{lane}.state")
            expected_decision = "deny" if lane == "deny" else "allow"
            raw_reasons = authorization["reason_codes"]
            if type(raw_reasons) is not list:
                raise SpendProofError(f"{lane} authorization reasons are invalid")
            try:
                decision = Decision(authorization["decision"])
                reason_codes = tuple(AuthorizationReasonCode(item) for item in raw_reasons)
                verified_authorization = SideEffectAuthorization(
                    request_id=authorization["request_id"],
                    decision=decision,
                    reason_codes=reason_codes,
                    original_arguments_hash=authorization["original_arguments_hash"],
                    approved_arguments_hash=authorization["approved_arguments_hash"],
                    binding_hash=authorization["binding_hash"],
                    audit_event_id=authorization["audit_event_id"],
                    audit_event_hash=authorization["audit_event_hash"],
                    previous_audit_hash=authorization["previous_audit_hash"],
                    approved_arguments=arguments if decision is Decision.ALLOW else {},
                    reserved_binding=authorization["reserved_binding"],
                    receipt=receipt,
                )
            except (TypeError, ValueError) as exc:
                raise SpendProofError(f"{lane} authorization binding is invalid: {exc}") from exc
            _verify_request_derived_bindings(lane, request, arguments, verified_authorization)
            binding = cast(dict[str, Any], authorization["reserved_binding"])
            if lane == "allow":
                _verify_execution_lifecycle_bindings(
                    lifecycle_events,
                    receipt=receipt,
                    binding_hash=authorization["binding_hash"],
                    idempotency_digest=binding["idempotency_digest"],
                    label=f"audit.{lane}",
                )
            elif lane == "tamper":
                _verify_execution_refusal_bindings(
                    lifecycle_events[1],
                    receipt=receipt,
                    binding=binding,
                    binding_hash=authorization["binding_hash"],
                    authorization_audit_hash=authorization["audit_event_hash"],
                    expected_reason_code=_LANE_REFUSAL_REASON_CODE,
                    label=f"audit.{lane}",
                )
            binding_pairs = {
                "actor_id": request["actor_id"],
                "actor_role": request["actor_role"],
                "authority": request["authority"],
                "environment": request["environment"],
                "request_id": request["request_id"],
                "requested_at": request["requested_at"],
                "resource": request["resource"],
                "tenant_id": request["tenant_id"],
            }
            if any(binding.get(name) != value for name, value in binding_pairs.items()):
                raise SpendProofError(f"{lane} request identity binding mismatch")
            state_pairs = {
                "actor_role": request["actor_role"],
                "authority": request["authority"],
                "environment": request["environment"],
                "request_id": request["request_id"],
                "resource": request["resource"],
                "tenant_id": request["tenant_id"],
            }
            if any(side_state.get(name) != value for name, value in state_pairs.items()):
                raise SpendProofError(f"{lane} runtime identity binding mismatch")
            common = (
                request.get("request_id"),
                request.get("argument_hash"),
                receipt.receipt_id,
                receipt.receipt_hash,
                event.get("event_id"),
                event.get("event_hash"),
            )
            if (
                common
                != (
                    authorization.get("request_id"),
                    authorization.get("original_arguments_hash"),
                    authorization.get("receipt_id"),
                    authorization.get("receipt_hash"),
                    authorization.get("audit_event_id"),
                    authorization.get("audit_event_hash"),
                )
                or verified_authorization.receipt is not receipt
                or (
                    receipt.request_id != request.get("request_id")
                    or receipt.receipt_id != event.get("event_id")
                    or receipt.audit_event_hash != event.get("event_hash")
                    or receipt.argument_hash != request.get("argument_hash")
                    or receipt.policy_hash != pin.policy_digest
                    or receipt.decision != expected_decision
                    or receipt.matched_rules != event.get("matched_rules")
                    or receipt.previous_audit_hash != event.get("previous_hash")
                    or receipt.actor != event.get("actor")
                    or receipt.proposed_action != event.get("tool")
                    or receipt.timestamp != event.get("timestamp_iso")
                    or receipt.declared_goal != event.get("goal")
                    or event.get("decision") != expected_decision
                    or event.get("argument_hash") != request.get("argument_hash")
                    or audit_wrapper.get("event_id") != event.get("event_id")
                    or replay_wrapper.get("event_id") != side.get("event_id")
                    or side.get("event_id") != event.get("event_id")
                    or side_arguments != arguments
                    or side.get("argument_hash") != request.get("argument_hash")
                    or side.get("decision") != expected_decision
                )
            ):
                raise SpendProofError(f"{lane} request/authorization/receipt/audit/replay mismatch")
            checkpoint_row = _exact_dict(
                checkpoint_lanes[lane], _CHECKPOINT_WRAPPER_KEYS, f"checkpoint.{lane}"
            )
            checkpoint = _checkpoint(checkpoint_row["checkpoint"], f"checkpoint.{lane}.wire")
            checkpoint_key = pin.keys["audit-checkpoint"]
            if (
                checkpoint_row["event_id"] != event.get("event_id")
                or checkpoint_row["event_ids"]
                != [candidate["event_id"] for candidate in lifecycle_events]
                or checkpoint.generation != len(lifecycle_events)
                or checkpoint.head_hash != lifecycle_events[-1].get("event_hash")
                or checkpoint.key_id != checkpoint_key.key_id
                or not checkpoint_key.verifier().verify(
                    checkpoint.signing_payload(), checkpoint.signature
                )
            ):
                raise SpendProofError(f"{lane} checkpoint mismatch")
            audit_store = _verify_checkpointed_audit(
                lifecycle_events,
                checkpoint,
                checkpoint_key,
                private_root,
                label=lane,
            )
            replay_path = _private_write(
                private_root,
                f"{lane}-replay.jsonl",
                SPEND_PROOF_CODEC.jsonl_bytes([side]),
            )
            replay_report = replay_checkpointed_bundle(
                audit_store,
                ReplaySideStore(replay_path),
                reconstructed[lane],
                lifecycle_verifiers=_lifecycle_verifiers(trust),
            )
            if (
                replay_report.get("valid") is not True
                or replay_report.get("strict") is not True
                or replay_report.get("events_total") != 1
                or replay_report.get("events_matched") != 1
                or replay_report.get("lifecycle_events_total") != (2 if lane == "allow" else 0)
                or replay_report.get("mismatches") != []
            ):
                raise SpendProofError(f"{lane} checkpointed replay is incomplete")
            if not replay_from_side_store(event, side, reconstructed[lane]).matches:
                raise SpendProofError(f"{lane} offline semantic replay is incomplete")
            consumption = _verify_summary(
                consumption_lanes[lane],
                pin.keys["consumption-summary"],
                "consumption-summary",
                f"consumption.{lane}",
            )
            spend = _verify_summary(
                spend_lanes[lane], pin.keys["spend-summary"], "spend-summary", f"spend.{lane}"
            )
            consumption = _exact_dict(
                consumption, _CONSUMPTION_PAYLOAD_KEYS, f"consumption.{lane}.payload"
            )
            if (
                consumption.get("schema") != SPEND_CONSUMPTION_SUMMARY_SCHEMA
                or consumption.get("lane") != lane
                or consumption.get("receipt_id") != receipt.receipt_id
                or consumption.get("receipt_hash") != receipt.receipt_hash
                or consumption.get("audit_event_id") != event.get("event_id")
                or consumption.get("audit_event_hash") != event.get("event_hash")
                or consumption.get("result_digest") != protocol.get("result_digest")
            ):
                raise SpendProofError(f"{lane} consumption cross-link mismatch")
            record = consumption.get("record")
            if lane == "allow":
                record = _exact_dict(record, _CONSUMPTION_RECORD_KEYS, "consumption.allow.record")
                if record.get("state") != "SUCCEEDED":
                    raise SpendProofError("allow consumption must be SUCCEEDED")
            elif record is not None:
                raise SpendProofError(f"{lane} consumption must be absent")
            _verify_spend_summary(lane, spend, request, receipt, protocol, pin)
            if protocol.get("provider_delta") != (1 if lane == "allow" else 0):
                raise SpendProofError(f"{lane} provider delta is invalid")
            expected_status = {"allow": "SUCCEEDED", "deny": "DENIED", "tamper": "TAMPER_BLOCKED"}[
                lane
            ]
            expected_protocol_reason = {
                "allow": "execution.succeeded",
                "deny": "authorization.denied",
                "tamper": _LANE_REFUSAL_REASON_CODE,
            }[lane]
            if protocol.get("status") != expected_status or protocol.get("executed") is not (
                lane == "allow"
            ):
                raise SpendProofError(f"{lane} protocol result is invalid")
            if (
                protocol.get("request_id") != authorization.get("request_id")
                or protocol.get("decision") != authorization.get("decision")
                or protocol.get("reason_code") != expected_protocol_reason
                or protocol.get("argument_hash") != authorization.get("original_arguments_hash")
                or protocol.get("audit_event_id") != authorization.get("audit_event_id")
                or protocol.get("audit_event_hash") != authorization.get("audit_event_hash")
                or protocol.get("receipt_id") != receipt.receipt_id
                or protocol.get("receipt_hash") != receipt.receipt_hash
            ):
                raise SpendProofError(f"{lane} protocol receipt mismatch")
            if lane == "deny":
                refusal = _exact_dict(refusals[lane], _REFUSAL_KEYS, "refusal.deny")
                refusal_receipt = _receipt_wire(refusal["receipt"], "refusal.deny.receipt")
                if (
                    refusal.get("reason_codes") != list(reason_codes)
                    or refusal_receipt != receipt_value
                ):
                    raise SpendProofError(
                        "deny refusal does not bind reasons and signed non-executable receipt"
                    )

    if len(journal_rows) != 1:
        raise SpendProofError("fixture journal must contain exactly one allow record")
    journal_wrapper = _exact_dict(journal_rows[0], _JOURNAL_WRAPPER_KEYS, "fixture journal wrapper")
    if journal_wrapper.get("lane") != "allow":
        raise SpendProofError("fixture journal must contain exactly one allow record")
    journal = _exact_dict(
        journal_wrapper.get("event"), _JOURNAL_EVENT_KEYS, "fixture journal event"
    )
    body = {key: value for key, value in journal.items() if key != "event_hash"}
    allow_protocol = protocols["allow"]
    allow_request = requests["allow"]
    allow_spend = _verify_summary(
        spend_lanes["allow"], trust["allow"].keys["spend-summary"], "spend-summary", "spend.allow"
    )
    allow_outcome = cast(list[dict[str, Any]], allow_spend["outcomes"])[0]
    if (
        hashlib.sha256(canonical_json(body).encode()).hexdigest() != journal.get("event_hash")
        or journal.get("sequence") != 1
        or journal.get("previous_hash") != "0" * 64
        or journal.get("idempotency_digest") != allow_request.get("idempotency_digest")
        or journal.get("envelope_digest") != allow_request.get("argument_hash")
        or journal.get("status") != "SUCCEEDED"
        or journal.get("result_digest") != allow_protocol.get("result_digest")
        or journal.get("result_digest") != allow_outcome.get("result_digest")
    ):
        raise SpendProofError("fixture journal/spend outcome cross-link mismatch")


_LOOP_LANES = tuple(f"loop-{index:02d}" for index in range(1, 13))
_LOOP_ALLOW_LANES = frozenset(_LOOP_LANES[:5])
_LOOP_DENY_LANES = frozenset(_LOOP_LANES[5:])
_LOOP_SUMMARY_KEYS = frozenset(
    {
        "amount_minor",
        "baseline_effect_count",
        "baseline_total_minor",
        "budget_limit_minor",
        "currency",
        "governed_denied_count",
        "governed_effect_count",
        "governed_succeeded_count",
        "governed_total_minor",
        "request_count",
        "unsafe_baseline_mode",
    }
)
_LOOP_CONSUMPTION_KEYS = frozenset({"schema", "lane", "records", "succeeded_count", "denied_count"})
_LOOP_CONSUMPTION_RECORD_KEYS = frozenset(
    {
        "audit_event_hash",
        "audit_event_id",
        "lane",
        "receipt_hash",
        "receipt_id",
        "record",
        "result_digest",
    }
)
_LOOP_REFUSAL_KEYS = frozenset(
    {
        "argument_hash",
        "audit_event_hash",
        "audit_event_id",
        "lane",
        "reason_codes",
        "record_id",
        "request_id",
    }
)


def _loop_rows(
    values: object,
    keys: frozenset[str],
    label: str,
    expected_lanes: frozenset[str],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in _exact_rows(values, keys, label):
        lane = row.get("lane")
        if type(lane) is not str or lane in result:
            raise SpendProofError(f"{label} loop lane coverage is invalid")
        result[lane] = row
    if set(result) != set(expected_lanes):
        raise SpendProofError(f"{label} loop lane coverage is invalid")
    return result


def _verify_loop_spend_summary(
    summary: dict[str, Any],
    requests: dict[str, dict[str, Any]],
    receipts: dict[str, DecisionReceipt],
    protocols: dict[str, dict[str, Any]],
    trust: _TrustLane,
) -> dict[str, dict[str, Any]]:
    summary = _exact_dict(summary, _SPEND_PAYLOAD_KEYS, "spend.loop.payload")
    if summary.get("schema") != SPEND_STORE_SUMMARY_SCHEMA or summary.get("lane") != "loop":
        raise SpendProofError("loop spend summary schema/lane mismatch")
    anchor = _exact_dict(summary["anchor"], _SPEND_ANCHOR_KEYS, "spend.loop.anchor")
    events = _exact_rows(summary["events"], _SPEND_EVENT_KEYS, "spend.loop.events")
    intents = _exact_rows(summary["intents"], _SPEND_INTENT_KEYS, "spend.loop.intents")
    outcomes = _exact_rows(summary["outcomes"], _SPEND_OUTCOME_KEYS, "spend.loop.outcomes")
    controls = _exact_rows(summary["controls"], _SPEND_CONTROL_KEYS, "spend.loop.controls")
    previous = "0" * 64
    intent_rows: list[dict[str, Any]] = []
    outcome_rows: list[dict[str, Any]] = []
    control_rows: list[dict[str, Any]] = []
    for generation, event in enumerate(events, start=1):
        payload_json = _text(event.get("payload_json"), "loop spend event payload_json")
        payload_digest = hashlib.sha256(payload_json.encode()).hexdigest()
        document = {
            "generation": generation,
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "entity_id": event.get("entity_id"),
            "payload_digest": payload_digest,
            "previous_hash": previous,
            "occurred_at_us": event.get("occurred_at_us"),
        }
        expected_hash = hashlib.sha256(
            _SPEND_EVENT_DOMAIN + canonical_json(document).encode()
        ).hexdigest()
        if (
            event.get("generation") != generation
            or event.get("payload_digest") != payload_digest
            or event.get("previous_hash") != previous
            or event.get("event_hash") != expected_hash
        ):
            raise SpendProofError("loop spend event chain mismatch")
        payload = _exact_dict(
            json.loads(payload_json), {"schema", "event_type", "row"}, "loop spend event payload"
        )
        event_type = cast(str, event.get("event_type"))
        row_keys = {
            "RESERVE": _SPEND_INTENT_KEYS,
            "OUTCOME": _SPEND_OUTCOME_KEYS,
            "CONTROL": _SPEND_CONTROL_KEYS,
        }.get(event_type)
        if row_keys is None:
            raise SpendProofError("loop spend event type is invalid")
        payload_row = _exact_dict(payload["row"], row_keys, "loop spend event row")
        if (
            payload.get("schema") != _SPEND_EVENT_PAYLOAD_SCHEMA
            or payload.get("event_type") != event_type
            or canonical_json(payload) != payload_json
        ):
            raise SpendProofError("loop spend event payload mismatch")
        {"RESERVE": intent_rows, "OUTCOME": outcome_rows, "CONTROL": control_rows}[
            event_type
        ].append(payload_row)
        previous = expected_hash
    if (
        anchor.get("generation") != 10
        or anchor.get("event_count") != 10
        or anchor.get("head_hash") != previous
        or len(events) != 10
        or len(intents) != 5
        or len(outcomes) != 5
        or controls
        or intents != sorted(intent_rows, key=lambda row: row.get("spend_id", ""))
        or outcomes != sorted(outcome_rows, key=lambda row: row.get("spend_id", ""))
        or control_rows
    ):
        raise SpendProofError("loop spend materialized state/cardinality mismatch")
    outcomes_by_id = {cast(str, row["spend_id"]): row for row in outcomes}
    if len(outcomes_by_id) != 5 or sum(cast(int, row["amount_minor"]) for row in intents) != 5000:
        raise SpendProofError("loop spend total/cardinality mismatch")
    matched: dict[str, dict[str, Any]] = {}
    for intent in intents:
        lane_matches = [
            lane
            for lane in _LOOP_ALLOW_LANES
            if intent.get("receipt_digest") == receipts[lane].receipt_hash
        ]
        if len(lane_matches) != 1:
            raise SpendProofError("loop spend intent receipt coverage mismatch")
        lane = lane_matches[0]
        request = requests[lane]
        protocol = protocols[lane]
        outcome = outcomes_by_id.get(cast(str, intent.get("spend_id")))
        snapshot_json = _text(intent.get("budget_snapshot_json"), "loop budget snapshot")
        if (
            outcome is None
            or hashlib.sha256(snapshot_json.encode()).hexdigest()
            != intent.get("budget_snapshot_digest")
            or intent.get("policy_digest") != trust.policy_digest
            or intent.get("argument_digest") != request.get("payment_hash")
            or intent.get("budget_rules_digest") != trust.target["rules_digest"]
            or intent.get("idempotency_digest") != request.get("idempotency_digest")
            or intent.get("approval_digest") != request.get("approval_digest")
            or intent.get("stop_generation") != request.get("expected_stop_generation")
            or intent.get("amount_minor") != 1000
            or intent.get("currency") != "USD"
            or intent.get("provider") != "stripe-test"
            or intent.get("recipient") != "vendor-known"
            or outcome.get("state") != "SUCCEEDED"
            or outcome.get("result_digest") != protocol.get("result_digest")
        ):
            raise SpendProofError("loop spend intent/outcome cross-link mismatch")
        matched[lane] = outcome
    if set(matched) != set(_LOOP_ALLOW_LANES):
        raise SpendProofError("loop spend successful lane coverage mismatch")
    return matched


def _verify_loop_semantics(values: dict[str, Any], trust: dict[str, _TrustLane]) -> None:
    if set(trust) != {"loop"}:
        raise SpendProofError("loop trust lane coverage is invalid")
    pin = trust["loop"]
    scenario = _exact_dict(values["scenario.json"], {"schema", "lanes", "loop"}, "scenario")
    runtime = _exact_dict(values["runtime-bindings.json"], {"schema", "lanes"}, "runtime")
    policy_root = _exact_dict(values["policy.json"], {"schema", "lanes"}, "policy")
    if (scenario["schema"], runtime["schema"], policy_root["schema"]) != (
        SPEND_LOOP_SCENARIO_SCHEMA,
        SPEND_LOOP_RUNTIME_SCHEMA,
        SPEND_LOOP_POLICY_EVIDENCE_SCHEMA,
    ):
        raise SpendProofError("loop proof metadata schema is unsupported")
    loop_summary = _exact_dict(scenario["loop"], _LOOP_SUMMARY_KEYS, "scenario.loop")
    if loop_summary != {
        "amount_minor": 1000,
        "baseline_effect_count": 12,
        "baseline_total_minor": 12000,
        "budget_limit_minor": 5000,
        "currency": "USD",
        "governed_denied_count": 7,
        "governed_effect_count": 5,
        "governed_succeeded_count": 5,
        "governed_total_minor": 5000,
        "request_count": 12,
        "unsafe_baseline_mode": "private-local-fixture-no-fallback",
    }:
        raise SpendProofError("loop scenario bounds are incompatible")
    for root, label in ((scenario, "scenario"), (runtime, "runtime"), (policy_root, "policy")):
        lanes = _exact_dict(root["lanes"], {"loop"}, f"{label}.lanes")
        expected_keys = _PIN_KEYS if label != "policy" else frozenset({*_PIN_KEYS, "artifact"})
        row = _exact_dict(lanes["loop"], expected_keys, f"{label}.loop")
        embedded = row if label != "policy" else {key: row[key] for key in pin.pin()}
        if embedded != pin.pin():
            raise SpendProofError(f"{label}.loop external trust mismatch")
    policy_row = cast(dict[str, Any], policy_root["lanes"])["loop"]
    try:
        attestation = PolicyArtifactAttestation(**pin.policy_attestation)
        policy = SpendKernelPolicy.from_authorization_snapshot(policy_row["artifact"])
    except (TypeError, ValueError) as exc:
        raise SpendProofError(f"policy.loop reconstruction failed: {exc}") from exc
    snapshot = policy.authorization_snapshot()
    if snapshot.digest != pin.policy_digest or attestation.digest != snapshot.digest:
        raise SpendProofError("policy.loop digest/attestation mismatch")

    all_lanes = frozenset(_LOOP_LANES)
    requests = _loop_rows(values["requests.jsonl"], _REQUEST_KEYS, "requests", all_lanes)
    authorizations = _loop_rows(
        values["authorizations.jsonl"],
        _AUTHORIZATION_KEYS,
        "authorizations",
        _LOOP_ALLOW_LANES,
    )
    protocols = _loop_rows(
        values["protocol-results.jsonl"], _PROTOCOL_KEYS, "protocol results", all_lanes
    )
    audits = _loop_rows(values["audit.jsonl"], _AUDIT_WRAPPER_KEYS, "audit", all_lanes)
    replays = _loop_rows(values["replay.jsonl"], _REPLAY_WRAPPER_KEYS, "replay", all_lanes)
    receipt_rows = _loop_rows(
        values["receipts.jsonl"], _RECEIPT_WRAPPER_KEYS, "receipts", _LOOP_ALLOW_LANES
    )
    refusal_rows = _loop_rows(
        values["refusals.jsonl"], _LOOP_REFUSAL_KEYS, "refusals", _LOOP_DENY_LANES
    )
    parsed_receipts: dict[str, DecisionReceipt] = {}
    events: list[dict[str, Any]] = []
    side_records: list[dict[str, Any]] = []
    for index, lane in enumerate(_LOOP_LANES, start=1):
        request = requests[lane]
        protocol = protocols[lane]
        audit_wrapper = audits[lane]
        replay_wrapper = replays[lane]
        arguments = _request_arguments(request["arguments"], f"request.{lane}.arguments")
        identity = cast(dict[str, Any], arguments["identity"])
        payment = cast(dict[str, Any], arguments["payment"])
        probe = cast(dict[str, Any], arguments["budget_probe"])
        if (
            request.get("tenant_id") != pin.tenant_id
            or request.get("policy") != {"version": pin.policy_version, "digest": pin.policy_digest}
            or any(
                request.get(name) != value
                for name, value in pin.target.items()
                if name not in {"provider", "rules_digest"}
            )
            or strict_json_hash(arguments) != request.get("argument_hash")
            or any(request.get(name) != identity.get(name) for name in _IDENTITY_KEYS)
            or payment.get("amount") != "10.00"
            or payment.get("amount_minor") != 1000
            or payment.get("currency") != "USD"
            or payment.get("provider") != "stripe-test"
            or payment.get("recipient") != "vendor-known"
            or payment.get("reference") != f"fixture-loop-order-{index:02d}"
            or probe.get("reason_code")
            != (None if lane in _LOOP_ALLOW_LANES else "SPEND_HOURLY_LIMIT_EXCEEDED")
        ):
            raise SpendProofError(f"{lane} request/amount/budget binding mismatch")
        expected_decision = "allow" if lane in _LOOP_ALLOW_LANES else "deny"
        event, lifecycle_events = _audit_lifecycle_events(
            audit_wrapper,
            label=f"audit.{lane}",
            successful=lane in _LOOP_ALLOW_LANES,
            trust=pin,
        )
        side = _exact_dict(
            replay_wrapper["side_record"], _REPLAY_SIDE_KEYS, f"replay.{lane}.side_record"
        )
        side_args = _request_arguments(side["args"], f"replay.{lane}.args")
        side_state = _exact_dict(side["state"], _REPLAY_STATE_KEYS, f"replay.{lane}.state")
        _verify_loop_request_derived_bindings(lane, request, side_args)
        if (
            event.get("decision") != expected_decision
            or event.get("argument_hash") != request.get("argument_hash")
            or audit_wrapper.get("event_id") != event.get("event_id")
            or replay_wrapper.get("event_id") != side.get("event_id")
            or side.get("event_id") != event.get("event_id")
            or side.get("decision") != expected_decision
            or side.get("argument_hash") != request.get("argument_hash")
            or side_args != arguments
            or side_state.get("policy_digest") != pin.policy_digest
            or protocol.get("request_id") != request.get("request_id")
            or protocol.get("decision") != expected_decision
            or protocol.get("status") != ("SUCCEEDED" if lane in _LOOP_ALLOW_LANES else "DENIED")
            or protocol.get("executed") is not (lane in _LOOP_ALLOW_LANES)
            or protocol.get("reason_code")
            != ("execution.succeeded" if lane in _LOOP_ALLOW_LANES else "authorization.denied")
            or protocol.get("provider_delta") != (1 if lane in _LOOP_ALLOW_LANES else 0)
            or protocol.get("audit_event_id") != event.get("event_id")
            or protocol.get("audit_event_hash") != event.get("event_hash")
            or protocol.get("argument_hash") != request.get("argument_hash")
            or any(
                side_state.get(name) != request.get(name)
                for name in {
                    "actor_role",
                    "authority",
                    "environment",
                    "request_id",
                    "resource",
                    "tenant_id",
                }
            )
        ):
            raise SpendProofError(f"{lane} authorization/audit/protocol cross-link mismatch")
        if lane in _LOOP_ALLOW_LANES:
            authorization = authorizations[lane]
            receipt_value = _receipt_wire(receipt_rows[lane]["receipt"], f"receipt.{lane}.wire")
            try:
                receipt = DecisionReceipt.from_dict(receipt_value)
                reason_codes = tuple(
                    AuthorizationReasonCode(item) for item in authorization["reason_codes"]
                )
                verified = SideEffectAuthorization(
                    request_id=authorization["request_id"],
                    decision=Decision(authorization["decision"]),
                    reason_codes=reason_codes,
                    original_arguments_hash=authorization["original_arguments_hash"],
                    approved_arguments_hash=authorization["approved_arguments_hash"],
                    binding_hash=authorization["binding_hash"],
                    audit_event_id=authorization["audit_event_id"],
                    audit_event_hash=authorization["audit_event_hash"],
                    previous_audit_hash=authorization["previous_audit_hash"],
                    approved_arguments=arguments,
                    reserved_binding=authorization["reserved_binding"],
                    receipt=receipt,
                )
            except (TypeError, ValueError) as exc:
                raise SpendProofError(f"{lane} authorization binding is invalid: {exc}") from exc
            key = pin.keys["receipt"]
            binding = cast(dict[str, Any], authorization["reserved_binding"])
            if (
                authorization["reason_codes"] != ["authorization.allowed"]
                or receipt.compute_hash() != receipt.receipt_hash
                or receipt.signing_key_id != key.key_id
                or receipt.signature_algorithm != "ed25519"
                or not key.verifier().verify(receipt.receipt_hash.encode(), receipt.signature)
                or receipt.request_id != request.get("request_id")
                or receipt.argument_hash != request.get("argument_hash")
                or receipt.policy_hash != pin.policy_digest
                or receipt.receipt_id != event.get("event_id")
                or receipt.audit_event_hash != event.get("event_hash")
                or receipt.previous_audit_hash != event.get("previous_hash")
                or authorization.get("receipt_id") != receipt.receipt_id
                or authorization.get("receipt_hash") != receipt.receipt_hash
                or authorization.get("audit_event_id") != event.get("event_id")
                or authorization.get("audit_event_hash") != event.get("event_hash")
                or protocol.get("receipt_id") != receipt.receipt_id
                or protocol.get("receipt_hash") != receipt.receipt_hash
                or any(binding.get(name) != request.get(name) for name in _IDENTITY_KEYS)
            ):
                raise SpendProofError(f"{lane} executable receipt cross-link mismatch")
            _verify_request_derived_bindings(lane, request, arguments, verified)
            _verify_execution_lifecycle_bindings(
                lifecycle_events,
                receipt=receipt,
                binding_hash=authorization["binding_hash"],
                idempotency_digest=cast(str, binding["idempotency_digest"]),
                label=f"audit.{lane}",
            )
            parsed_receipts[lane] = receipt
        else:
            refusal = refusal_rows[lane]
            if (
                refusal.get("request_id") != request.get("request_id")
                or refusal.get("argument_hash") != request.get("argument_hash")
                or refusal.get("audit_event_id") != event.get("event_id")
                or refusal.get("audit_event_hash") != event.get("event_hash")
                or refusal.get("reason_codes") != ["authorization.denied"]
                or protocol.get("receipt_id") is not None
                or protocol.get("receipt_hash") is not None
                or protocol.get("result_digest") is not None
            ):
                raise SpendProofError(f"{lane} refusal cross-link mismatch")
        events.extend(lifecycle_events)
        side_records.append(side)

    checkpoint_root = _exact_dict(
        values["audit-checkpoint.json"], {"schema", "lane", "event_ids", "checkpoint"}, "checkpoint"
    )
    if (
        checkpoint_root["schema"] != SPEND_LOOP_CHECKPOINT_SCHEMA
        or checkpoint_root["lane"] != "loop"
        or checkpoint_root["event_ids"] != [event["event_id"] for event in events]
    ):
        raise SpendProofError("loop checkpoint coverage mismatch")
    checkpoint = _checkpoint(checkpoint_root["checkpoint"], "checkpoint.loop.wire")
    checkpoint_key = pin.keys["audit-checkpoint"]
    if (
        checkpoint.generation != 22
        or checkpoint.head_hash != events[-1]["event_hash"]
        or checkpoint.key_id != checkpoint_key.key_id
        or not checkpoint_key.verifier().verify(checkpoint.signing_payload(), checkpoint.signature)
    ):
        raise SpendProofError("loop checkpoint mismatch")
    with tempfile.TemporaryDirectory(prefix="gove-zone-spend-loop-proof-") as temporary:
        private_root = Path(temporary)
        audit_store = _verify_checkpointed_audit(
            events,
            checkpoint,
            checkpoint_key,
            private_root,
            label="loop",
        )
        replay_path = _private_write(
            private_root,
            "loop-replay.jsonl",
            SPEND_PROOF_CODEC.jsonl_bytes(side_records),
        )
        replay_report = replay_checkpointed_bundle(
            audit_store,
            ReplaySideStore(replay_path),
            policy,
            lifecycle_verifiers=_lifecycle_verifiers(trust),
        )
        if (
            replay_report.get("valid") is not True
            or replay_report.get("strict") is not True
            or replay_report.get("events_total") != 12
            or replay_report.get("events_matched") != 12
            or replay_report.get("lifecycle_events_total") != 10
            or replay_report.get("mismatches") != []
        ):
            raise SpendProofError("loop checkpointed replay is incomplete")
    if any(
        not replay_from_side_store(
            cast(dict[str, Any], audits[lane]["event"]),
            side_records[index],
            policy,
        ).matches
        for index, lane in enumerate(_LOOP_LANES)
    ):
        raise SpendProofError("loop offline semantic replay is incomplete")

    consumption_root = _exact_dict(
        values["consumption-summary.json"], {"schema", "lane", "summary"}, "consumption"
    )
    spend_root = _exact_dict(
        values["spend-store-summary.json"], {"schema", "lane", "summary"}, "spend summary"
    )
    if (
        consumption_root["schema"] != SPEND_LOOP_CONSUMPTION_SUMMARY_SCHEMA
        or consumption_root["lane"] != "loop"
        or spend_root["schema"] != SPEND_LOOP_STORE_SUMMARY_SCHEMA
        or spend_root["lane"] != "loop"
    ):
        raise SpendProofError("loop summary schema/lane mismatch")
    consumption = _verify_summary(
        consumption_root["summary"],
        pin.keys["consumption-summary"],
        "consumption-summary",
        "consumption.loop",
    )
    consumption = _exact_dict(consumption, _LOOP_CONSUMPTION_KEYS, "consumption.loop.payload")
    records = _exact_rows(
        consumption["records"], _LOOP_CONSUMPTION_RECORD_KEYS, "consumption.loop.records"
    )
    if (
        consumption.get("schema") != SPEND_LOOP_CONSUMPTION_SUMMARY_SCHEMA
        or consumption.get("lane") != "loop"
        or consumption.get("succeeded_count") != 5
        or consumption.get("denied_count") != 7
        or [row["lane"] for row in records] != list(_LOOP_LANES)
    ):
        raise SpendProofError("loop consumption coverage mismatch")
    for row in records:
        lane = cast(str, row["lane"])
        protocol = protocols[lane]
        record = row["record"]
        if lane in _LOOP_ALLOW_LANES:
            receipt = parsed_receipts[lane]
            authorization = authorizations[lane]
            if (
                row.get("receipt_id") != receipt.receipt_id
                or row.get("receipt_hash") != receipt.receipt_hash
                or row.get("audit_event_id") != authorization["audit_event_id"]
                or row.get("audit_event_hash") != authorization["audit_event_hash"]
                or row.get("result_digest") != protocol["result_digest"]
            ):
                raise SpendProofError(f"{lane} consumption cross-link mismatch")
            record = _exact_dict(record, _CONSUMPTION_RECORD_KEYS, f"consumption.{lane}.record")
            if record.get("state") != "SUCCEEDED":
                raise SpendProofError(f"{lane} consumption is not SUCCEEDED")
        elif (
            record is not None
            or row.get("receipt_id") is not None
            or row.get("receipt_hash") is not None
            or row.get("audit_event_id") != audits[lane]["event_id"]
            or row.get("audit_event_hash") != audits[lane]["event"]["event_hash"]
            or row.get("result_digest") is not None
            or protocol.get("result_digest") is not None
        ):
            raise SpendProofError(f"{lane} denial must have no consumption/result")
    spend = _verify_summary(
        spend_root["summary"], pin.keys["spend-summary"], "spend-summary", "spend.loop"
    )
    outcomes = _verify_loop_spend_summary(spend, requests, parsed_receipts, protocols, pin)

    journals = _loop_rows(
        values["fixture-journal.jsonl"],
        _JOURNAL_WRAPPER_KEYS,
        "fixture journal",
        _LOOP_ALLOW_LANES,
    )
    previous = "0" * 64
    for sequence, lane in enumerate(_LOOP_LANES[:5], start=1):
        journal = _exact_dict(journals[lane]["event"], _JOURNAL_EVENT_KEYS, f"journal.{lane}")
        body = {key: value for key, value in journal.items() if key != "event_hash"}
        request = requests[lane]
        protocol = protocols[lane]
        outcome = outcomes[lane]
        if (
            hashlib.sha256(canonical_json(body).encode()).hexdigest() != journal.get("event_hash")
            or journal.get("sequence") != sequence
            or journal.get("previous_hash") != previous
            or journal.get("idempotency_digest") != request.get("idempotency_digest")
            or journal.get("envelope_digest") != request.get("argument_hash")
            or journal.get("status") != "SUCCEEDED"
            or journal.get("result_digest") != protocol.get("result_digest")
            or journal.get("result_digest") != outcome.get("result_digest")
        ):
            raise SpendProofError(f"{lane} fixture journal cross-link mismatch")
        previous = cast(str, journal["event_hash"])


def _verify_semantics(values: dict[str, Any], trust: dict[str, _TrustLane]) -> None:
    scenario = values.get("scenario.json")
    if type(scenario) is not dict:
        raise SpendProofError("scenario has an incompatible shape")
    schema = scenario.get("schema")
    if schema == SPEND_SCENARIO_SCHEMA:
        _verify_v1_semantics(values, trust)
    elif schema == SPEND_LOOP_SCENARIO_SCHEMA:
        _verify_loop_semantics(values, trust)
    else:
        raise SpendProofError("proof scenario schema is unsupported")


def export_spend_proof_pack(output: str | Path, payloads: SpendProofPayloads) -> SpendProofPack:
    if not isinstance(payloads, SpendProofPayloads):
        raise TypeError("payloads must be SpendProofPayloads")
    path = Path(output)
    _manifest, digest = SPEND_PROOF_CODEC.export_new_pack(path, payloads.files)
    return SpendProofPack(path, digest)


def _verify_with_trust_bytes(
    directory: str | Path,
    *,
    trust_bundle_bytes: bytes,
    expected_pack_digest: str,
    open_directory: OpenDirectory | None = None,
    assert_path_identity: AssertPathIdentity | None = None,
) -> str:
    if (open_directory is None) != (assert_path_identity is None):
        raise SpendProofError("open_directory and assert_path_identity must be supplied together")
    expected = _digest(expected_pack_digest, "expected_pack_digest")
    raw = SPEND_PROOF_CODEC.read_exact_pack(
        Path(directory),
        open_directory=open_directory,
        assert_path_identity=assert_path_identity,
    )
    manifest = SPEND_PROOF_CODEC.strict_json(raw["manifest.json"], "manifest.json")
    if type(manifest) is not dict:
        raise SpendProofError("manifest is invalid")
    actual = _digest(manifest.get("pack_digest"), "manifest.pack_digest")
    if not hmac.compare_digest(actual, expected):
        raise SpendProofError("external expected pack digest mismatch")
    trust_value = SPEND_PROOF_CODEC.strict_json(trust_bundle_bytes, "trust bundle")
    _assert_public(trust_value, label="trust bundle")
    trust = _parse_trust(trust_value)
    values: dict[str, Any] = {}
    for name in SPEND_PROOF_PAYLOAD_FILES:
        values[name] = (
            SPEND_PROOF_CODEC.strict_jsonl(raw[name], name)
            if name in _JSONL_FILES
            else SPEND_PROOF_CODEC.strict_json(raw[name], name)
        )
        _assert_public(values[name], label=name)
    try:
        _verify_semantics(values, trust)
    except SpendProofError:
        raise
    except Exception as exc:
        raise SpendProofError(f"semantic verification failed closed: {exc}") from exc
    return actual


def verify_spend_proof_pack(
    directory: str | Path,
    *,
    trust_bundle: str | Path,
    expected_pack_digest: str,
    open_directory: OpenDirectory | None = None,
    assert_path_identity: AssertPathIdentity | None = None,
) -> str:
    trust_raw = SPEND_PROOF_CODEC.secure_read_file(Path(trust_bundle), "trust bundle")
    return _verify_with_trust_bytes(
        directory,
        trust_bundle_bytes=trust_raw,
        expected_pack_digest=expected_pack_digest,
        open_directory=open_directory,
        assert_path_identity=assert_path_identity,
    )


def replay_spend_proof_pack(
    directory: str | Path,
    *,
    trust_bundle: str | Path,
    expected_pack_digest: str,
    open_directory: OpenDirectory | None = None,
    assert_path_identity: AssertPathIdentity | None = None,
) -> str:
    return verify_spend_proof_pack(
        directory,
        trust_bundle=trust_bundle,
        expected_pack_digest=expected_pack_digest,
        open_directory=open_directory,
        assert_path_identity=assert_path_identity,
    )


__all__ = [
    "SPEND_PROOF_CODEC",
    "SPEND_PROOF_LANES",
    "SPEND_PROOF_PAYLOAD_FILES",
    "SPEND_PROOF_SCHEMA",
    "SPEND_TRUST_SCHEMA",
    "SpendProofError",
    "SpendProofPack",
    "SpendProofPayloads",
    "export_spend_proof_pack",
    "replay_spend_proof_pack",
    "signed_summary",
    "verify_spend_proof_pack",
]
