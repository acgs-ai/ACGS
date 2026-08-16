"""Genuine two-lane MCP proof capture and atomic external trust export.

Each isolated lane is driven through one official in-process ``ClientSession``.
The exporter then resolves the opaque protocol request ID back to the exact
gateway-owned response object before exporting frozen, path-neutral evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, SupportsIndex, cast
from weakref import WeakKeyDictionary, finalize

from gove_zone.authorization import strict_json_hash
from gove_zone.mcp_gateway import MCPGatewayResponse, MCPGatewayStatus
from gove_zone.mcp_proof import (
    MCP_ACTION_PROOF_CODEC,
    MCP_ACTION_SCENARIO_SCHEMA,
    MCP_ACTION_TRUST_SCHEMA,
    MCP_AUDIT_CHECKPOINT_SCHEMA,
    MCP_FIXTURE_STATE_SCHEMA,
    MCP_POISONED_TOOL_DESCRIPTION,
    MCP_POLICY_EVIDENCE_SCHEMA,
    MCP_PROMPT_INJECTION_ATTACK_SCHEMA,
    MCP_PROMPT_INJECTION_SCENARIO_SCHEMA,
    MCP_PROMPT_INJECTION_TEXT,
    MCP_RUNTIME_BINDINGS_SCHEMA,
    MCPActionProofError,
    MCPActionProofPayloads,
    _pinned_output_parent_callbacks,
    _verify_mcp_proof_pack_with_trust_bytes,
    export_mcp_proof_pack,
)
from gove_zone.mcp_reference import MCPProofSources, MCPReferenceRuntime, create_reference_runtime
from gove_zone.mcp_runtime import (
    AUTHORIZATION_META_KEY,
    DECISION_META_KEY,
    _governance_meta,
    _in_process_client_session,
    build_mcp_server,
)
from gove_zone.path_capability import (
    AttestedDirectory,
    OwnedAttestedDirectory,
    _claim_owned_attested_directories,
    _duplicate_owned_attested_directory,
    require_attested_directory,
)
from gove_zone.proof_pack import (
    DirectoryIdentity,
    OpenDirectory,
    SealedPackCodec,
    SealedPackExportError,
    SealedPackSchema,
)
from gove_zone.receipt import safe_result_hash

MCP_PROOF_ENVELOPE_SCHEMA = "gove-zone.mcp-action-proof-envelope/v2"
MCP_EXPECTED_DIGEST_SCHEMA = "gove-zone.mcp-action-expected-pack-digest/v2"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

MCP_PROOF_ENVELOPE_CODEC = SealedPackCodec(
    SealedPackSchema(
        schema=MCP_PROOF_ENVELOPE_SCHEMA,
        digest_domain=b"gove-zone:mcp-action-proof-envelope:v2\x00",
        media_types={
            "expected-pack-digest.json": "application/json",
            "trust-bundle.json": "application/json",
        },
        verification={
            "expected_pack_digest": "external-envelope-member",
            "trust_bundle": "external-public-only-envelope-member",
        },
        error_type=MCPActionProofError,
    ),
    error_type=MCPActionProofError,
    export_error_type=SealedPackExportError,
)


@dataclass(frozen=True, slots=True)
class MCPGenuineProofExport:
    pack_directory: Path
    pack_digest: str
    envelope_directory: Path
    envelope_digest: str


@dataclass(slots=True)
class _LeaseResourceState:
    resources: tuple[OwnedAttestedDirectory, OwnedAttestedDirectory]
    lock: RLock
    closed: bool = False

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            for resource in reversed(self.resources):
                resource.close()


@dataclass(frozen=True, slots=True)
class _LeaseRecord:
    pack_digest: str
    envelope_digest: str
    summary_bytes: bytes
    resources: _LeaseResourceState
    finalizer: finalize[[_LeaseResourceState], MCPGenuineProofLease]


_LEASE_LOCK = RLock()
_LEASES: WeakKeyDictionary[MCPGenuineProofLease, _LeaseRecord]


class MCPGenuineProofLease:
    """Unforgeable identity for one privately-minted owned proof lease."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("MCPGenuineProofLease can only be minted by the proof exporter")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("MCPGenuineProofLease cannot be subclassed")

    def __enter__(self) -> MCPGenuineProofLease:
        _lease_record(self)
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __copy__(self) -> MCPGenuineProofLease:
        raise TypeError("MCP proof leases cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> MCPGenuineProofLease:
        raise TypeError("MCP proof leases cannot be deep-copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("MCP proof leases cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("MCP proof leases cannot be serialized")

    @property
    def pack_digest(self) -> str:
        return _lease_record(self).pack_digest

    @property
    def envelope_digest(self) -> str:
        return _lease_record(self).envelope_digest

    @property
    def proof_summary(self) -> dict[str, Any]:
        value = json.loads(_lease_record(self).summary_bytes)
        if type(value) is not dict:
            raise MCPActionProofError("MCP proof lease summary is invalid")
        return value

    def verify(self) -> str:
        return _verify_lease_record(self)

    def replay(self) -> str:
        return _verify_lease_record(self)

    def close(self) -> None:
        with _LEASE_LOCK:
            if type(self) is not MCPGenuineProofLease or self not in _LEASES:
                raise MCPActionProofError("an exact registered MCP proof lease is required")
            record = _LEASES[self]
        record.finalizer()


_LEASES = WeakKeyDictionary()


def _lease_record(value: object) -> _LeaseRecord:
    with _LEASE_LOCK:
        if type(value) is not MCPGenuineProofLease:
            raise MCPActionProofError("an exact registered MCP proof lease is required")
        record = _LEASES.get(value)
        if record is None or record.resources.closed:
            raise MCPActionProofError("MCP proof lease is closed or unregistered")
        return record


def _close_lease_resources(resources: _LeaseResourceState) -> None:
    resources.close()


def _owned_callbacks(
    resource: OwnedAttestedDirectory,
) -> tuple[OpenDirectory, Callable[[Path, DirectoryIdentity], None]]:
    def open_directory(_path: Path) -> tuple[int, DirectoryIdentity]:
        return _duplicate_owned_attested_directory(resource, error_type=MCPActionProofError)

    def assert_identity(_path: Path, expected: DirectoryIdentity) -> None:
        descriptor, actual = _duplicate_owned_attested_directory(
            resource, error_type=MCPActionProofError
        )
        try:
            if actual != expected:
                raise MCPActionProofError("owned proof directory identity changed")
        finally:
            os.close(descriptor)

    return open_directory, assert_identity


def _derive_owned_proof(
    pack: OwnedAttestedDirectory,
    envelope: OwnedAttestedDirectory,
) -> tuple[str, str, bytes]:
    envelope_raw = MCP_PROOF_ENVELOPE_CODEC.read_exact_pack_attested(envelope)
    envelope_manifest = MCP_PROOF_ENVELOPE_CODEC.strict_json(
        envelope_raw["manifest.json"], "manifest.json"
    )
    if type(envelope_manifest) is not dict or type(envelope_manifest.get("pack_digest")) is not str:
        raise MCPActionProofError("verification envelope manifest is incompatible")
    envelope_digest = cast(str, envelope_manifest["pack_digest"])
    expected = MCP_PROOF_ENVELOPE_CODEC.strict_json(
        envelope_raw["expected-pack-digest.json"], "expected-pack-digest.json"
    )
    if (
        type(expected) is not dict
        or set(expected) != {"schema", "pack_digest"}
        or expected.get("schema") != MCP_EXPECTED_DIGEST_SCHEMA
    ):
        raise MCPActionProofError("expected digest envelope member has an incompatible shape")
    expected_pack_digest = cast(str, expected["pack_digest"])
    open_directory, assert_identity = _owned_callbacks(pack)
    pack_digest = _verify_mcp_proof_pack_with_trust_bytes(
        Path("."),
        trust_bundle_bytes=envelope_raw["trust-bundle.json"],
        expected_pack_digest=expected_pack_digest,
        open_directory=open_directory,
        assert_path_identity=assert_identity,
    )
    pack_raw = MCP_ACTION_PROOF_CODEC.read_exact_pack_attested(pack)
    summary = {
        "scenario": MCP_ACTION_PROOF_CODEC.strict_json(pack_raw["scenario.json"], "scenario.json"),
        "protocol_results": MCP_ACTION_PROOF_CODEC.strict_jsonl(
            pack_raw["protocol-results.jsonl"], "protocol-results.jsonl"
        ),
        "refusals": MCP_ACTION_PROOF_CODEC.strict_jsonl(
            pack_raw["refusals.jsonl"], "refusals.jsonl"
        ),
    }
    summary_bytes = json.dumps(
        summary,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return pack_digest, envelope_digest, summary_bytes


def _mint_mcp_genuine_proof_lease(
    pack: OwnedAttestedDirectory,
    envelope: OwnedAttestedDirectory,
) -> MCPGenuineProofLease:
    _claim_owned_attested_directories((pack, envelope), error_type=MCPActionProofError)
    try:
        pack_digest, envelope_digest, summary_bytes = _derive_owned_proof(pack, envelope)
        lease = object.__new__(MCPGenuineProofLease)
        resources = _LeaseResourceState((pack, envelope), RLock())
        cleanup = finalize(lease, _close_lease_resources, resources)
        record = _LeaseRecord(
            pack_digest,
            envelope_digest,
            summary_bytes,
            resources,
            cleanup,
        )
        with _LEASE_LOCK:
            _LEASES[lease] = record
        return lease
    except BaseException:
        envelope.close()
        pack.close()
        raise


def _verify_lease_record(lease: MCPGenuineProofLease) -> str:
    record = _lease_record(lease)
    with record.resources.lock:
        if record.resources.closed:
            raise MCPActionProofError("MCP proof lease is closed")
        pack_digest, envelope_digest, summary_bytes = _derive_owned_proof(
            *record.resources.resources
        )
        if (
            not hmac.compare_digest(pack_digest, record.pack_digest)
            or not hmac.compare_digest(envelope_digest, record.envelope_digest)
            or not hmac.compare_digest(summary_bytes, record.summary_bytes)
        ):
            raise MCPActionProofError("MCP proof lease evidence changed")
        return pack_digest


class MCPGenuineProofExportError(MCPActionProofError):
    """A proof export failed after at least the proof pack committed."""

    def __init__(
        self,
        message: str,
        *,
        pack_digest: str,
        cause: Exception,
        phase: str,
        envelope_committed: bool | None = None,
        durability: str | None = None,
    ) -> None:
        super().__init__(message)
        self.pack_committed = True
        self.pack_digest = pack_digest
        self.cause = cause
        self.envelope_committed = (
            bool(getattr(cause, "committed", False))
            if envelope_committed is None
            else envelope_committed
        )
        self.parent_identity_preserved = getattr(cause, "parent_identity_preserved", None)
        self.pinned_final_entry_exists = getattr(cause, "pinned_final_entry_exists", None)
        self.lexical_final_path_exists = getattr(cause, "lexical_final_path_exists", None)
        self.final_path_exists = getattr(cause, "final_path_exists", None)
        self.cleanup_attempted = bool(getattr(cause, "cleanup_attempted", False))
        self.cleanup_succeeded = getattr(cause, "cleanup_succeeded", None)
        self.durability_uncertain = bool(getattr(cause, "durability_uncertain", False))
        self.envelope_retry_safe = bool(getattr(cause, "retry_safe", False))
        self.retry_safe = False
        self.phase = phase
        self.durability = durability or (
            "uncertain"
            if self.durability_uncertain
            else "pack-and-envelope-committed"
            if self.envelope_committed
            else "pack-committed"
        )
        self.final_path = getattr(cause, "final_path", None)
        self.temp_path = getattr(cause, "temp_path", None)
        self.temp_path_exists = getattr(cause, "temp_path_exists", None)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _pin(sources: MCPProofSources) -> dict[str, Any]:
    return {
        "tenant_id": sources.tenant_id,
        "policy_version": sources.policy_version,
        "policy_digest": sources.policy_digest,
        "target": {
            "server_digest": hashlib.sha256(sources.target_server_id.encode("utf-8")).hexdigest(),
            "launch_digest": sources.target_launch_digest,
            "transport_digest": sources.target_transport_binding,
            "artifact_digest": sources.target_artifact_digest,
        },
    }


def _trust_lane(sources: MCPProofSources) -> dict[str, Any]:
    return {
        **_pin(sources),
        "policy_attestation": sources.policy_attestation.to_dict(),
        "checkpoint_authority_id": f"audit-checkpoint:{sources.audit_namespace}",
        "lifecycle_authority_id": sources.lifecycle_authority_id,
        "keys": {
            "receipt": sources.receipt_key.to_dict(),
            "refusal": sources.refusal_key.to_dict(),
            "checkpoint": sources.checkpoint_key.to_dict(),
            "consumption": sources.consumption_key.to_dict(),
            "exchange": sources.exchange_key.to_dict(),
            "lifecycle": sources.lifecycle_key.to_dict(),
        },
    }


def _read_jsonl(path: Path, capability: AttestedDirectory | None = None) -> list[dict[str, Any]]:
    if capability is None:
        if not path.exists():
            return []
        payload = path.read_bytes()
    else:
        try:
            payload = capability.read_bytes(capability.relative_from_display(path))
        except FileNotFoundError:
            return []
    rows: list[dict[str, Any]] = []
    for line in payload.splitlines():
        value = json.loads(line)
        if type(value) is not dict:
            raise MCPActionProofError("fixture source is not object JSONL")
        rows.append(cast(dict[str, Any], value))
    return rows


def _authorization(lane: str) -> dict[str, Any]:
    return {
        AUTHORIZATION_META_KEY: {
            "nonce": f"proof-{lane}-nonce",
            "idempotencyKey": f"proof-{lane}-idempotency",
            "requestedAt": _timestamp(),
            "evidence": [],
            "goal": f"capture the isolated {lane} MCP proof lane",
        }
    }


def _assert_exact_reference_tools(tools: list[Any]) -> None:
    values = [tool.model_dump(mode="json", by_alias=True, exclude_none=True) for tool in tools]
    arguments_schema = {
        "type": "object",
        "properties": {"record": {"type": "string", "maxLength": 256}},
        "required": ["record"],
        "additionalProperties": False,
    }
    if values != [
        {
            "name": "fixture.write_once",
            "description": "Append one sanitized fixture record",
            "inputSchema": arguments_schema,
        },
        {
            "name": "fixture.ambiguous_write",
            "description": "Append once and delay to simulate an uncertain response",
            "inputSchema": arguments_schema,
        },
        {
            "name": "fixture.read",
            "description": "Read the local fixture ledger",
            "inputSchema": {"type": "object", "additionalProperties": False},
        },
    ]:
        raise MCPActionProofError("normal official client received an unexpected tool catalog")


def _exact_response_from_client_result(
    runtime: MCPReferenceRuntime, result: Any
) -> MCPGatewayResponse:
    meta = result.meta
    if type(meta) is not dict or set(meta) != {DECISION_META_KEY}:
        raise MCPActionProofError("official client result has incompatible governance metadata")
    decision = meta[DECISION_META_KEY]
    if type(decision) is not dict or type(decision.get("requestId")) is not str:
        raise MCPActionProofError("official client result has no canonical governance request ID")
    response = runtime.require_gateway_response(decision["requestId"])
    if meta != {DECISION_META_KEY: _governance_meta(response)}:
        raise MCPActionProofError("official client metadata does not match the gateway projection")
    return response


def _pinned(pin: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    return {**dict(pin), **dict(values)}


def _evidence_row(
    protocol: Mapping[str, Any], purpose: str, evidence: Mapping[str, Any], key: Mapping[str, str]
) -> dict[str, Any]:
    return {
        **{
            name: protocol[name]
            for name in (
                "tenant_id",
                "policy_version",
                "policy_digest",
                "target",
                "lane",
                "event_id",
                "decision_id",
                "request_id",
                "actor",
                "decision",
                "governed_operation",
                "authority",
                "downstream_tool",
                "arguments_hash",
                "evidence_id",
            )
        },
        "record_id": f"{purpose}-{protocol['lane']}",
        "key_purpose": key["purpose"],
        "key_id": key["key_id"],
        "evidence": dict(evidence),
    }


def _fixture_wrapper(
    lane: str,
    pin: Mapping[str, Any],
    protocol: Mapping[str, Any],
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    call_log: list[dict[str, Any]],
) -> dict[str, Any]:
    delta = len(after) - len(before)
    return _pinned(
        pin,
        {
            "schema": MCP_FIXTURE_STATE_SCHEMA,
            "lane": lane,
            "event_ids": [protocol["event_id"]],
            "outcome_record_ids": [protocol["record_id"]],
            "ledger_before": before,
            "ledger_after": after,
            "ledger_before_count": len(before),
            "ledger_after_count": len(after),
            "write_delta": delta,
            "call_count": len(call_log),
            "event_digest": strict_json_hash([protocol["event_id"]]),
            "outcome_digest": strict_json_hash([protocol["record_id"]]),
            "ledger_before_digest": strict_json_hash(before),
            "ledger_after_digest": strict_json_hash(after),
            "write_delta_digest": strict_json_hash(
                {"before": len(before), "after": len(after), "delta": delta}
            ),
            "call_log_digest": strict_json_hash(call_log),
            "call_log": call_log,
        },
    )


async def _capture_lane(
    root: Path,
    lane: str,
    capability: AttestedDirectory | None = None,
    phase_hook: Callable[[str], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    runtime = await create_reference_runtime(
        root,
        inbound_token="fixture-token",  # noqa: S106  # nosec B106
        session_id=f"proof-{lane}-session",
        catalog_mode="normal" if lane == "normal" else "poison-description",
        proof_lane=lane,
        state_capability=capability,
        capability_phase_hook=phase_hook,
    )
    try:
        sources = runtime.public_snapshot()
        pin = _pin(sources)
        if phase_hook is not None:
            phase_hook("before-ledger-read")
        if capability is not None:
            capability.checkpoint()
        before = _read_jsonl(sources.fixture_ledger_path, capability)
        server = build_mcp_server(
            runtime.gateway,
            stdio_token="fixture-token",  # noqa: S106  # nosec B106
            stdio_session_id=runtime.session_id,
        )
        async with _in_process_client_session(server) as session:
            if lane == "normal":
                listed = await session.list_tools()
                _assert_exact_reference_tools(listed.tools)
            result = await session.call_tool(
                "fixture.write_once",
                {"record": f"genuine-{lane}-proof"},
                meta=_authorization(lane),
            )
        response = _exact_response_from_client_result(runtime, result)
        protocol = runtime.capture_gateway_exchange(response).to_dict()
        events = [dict(event) for event in runtime.audit.iter_events()]
        expected_event_count = 3 if lane == "normal" else 1
        if len(events) != expected_event_count or events[0]["event_id"] != protocol["event_id"]:
            raise MCPActionProofError(f"{lane} lane produced an incompatible audit lifecycle")
        checkpoint = runtime.seal_current_audit_checkpoint()
        if phase_hook is not None:
            phase_hook("before-ledger-read")
        if capability is not None:
            capability.checkpoint()
        after = _read_jsonl(sources.fixture_ledger_path, capability)
        if phase_hook is not None:
            phase_hook("before-call-log-read")
        if capability is not None:
            capability.checkpoint()
        call_log = _read_jsonl(sources.fixture_call_log_path, capability)
        if lane == "normal":
            if response.status is not MCPGatewayStatus.SUCCEEDED or response.receipt is None:
                raise MCPActionProofError("normal lane did not produce an executable receipt")
            replay = runtime.replay_store.get(response.audit_event_id)
            if replay is None:
                raise MCPActionProofError("normal lane replay record is missing")
            receipt = response.receipt
            consumption_record = {
                "event_id": response.audit_event_id,
                "outcome_record_id": protocol["record_id"],
                "receipt_id": receipt.receipt_id,
                "receipt_hash": receipt.receipt_hash,
                "state": "SUCCEEDED",
                "result_digest": safe_result_hash(response.payload),
                "audit_event_hash": receipt.audit_event_hash,
                "tenant_id": receipt.tenant_id,
                "actor": receipt.actor,
                "governed_operation": protocol["governed_operation"],
                "authority": protocol["authority"],
                "downstream_tool": protocol["downstream_tool"],
                "arguments_hash": receipt.argument_hash,
            }
            consumption = runtime.capture_consumption_evidence(
                "normal",
                response=response,
                outcome_record_id=cast(str, protocol["record_id"]),
                records=[consumption_record],
            ).to_dict()
            evidence = receipt.to_dict()
            replay_rows = [
                _pinned(
                    pin,
                    {
                        "record_id": f"replay-{response.audit_event_id}",
                        "lane": lane,
                        "event_id": response.audit_event_id,
                        "side_record": dict(replay),
                    },
                )
            ]
        else:
            if (
                response.status is not MCPGatewayStatus.DENIED
                or response.refusal_evidence is None
                or response.reason_codes != ("mcp.gateway.catalog_mismatch",)
                or list(runtime.replay_store.iter_records())
            ):
                raise MCPActionProofError(
                    "poison tools/call did not fail closed at catalog pinning"
                )
            consumption = runtime.capture_consumption_evidence(
                "poison", response=None, outcome_record_id=None, records=()
            ).to_dict()
            evidence = response.refusal_evidence.to_dict()
            replay_rows = []
        values = {
            "protocol": protocol,
            "audit": [
                _pinned(
                    pin,
                    {
                        "record_id": f"audit-{event['event_id']}",
                        "lane": lane,
                        "event_id": event["event_id"],
                        "event": event,
                    },
                )
                for event in events
            ],
            "checkpoint": _pinned(
                pin,
                {
                    "schema": MCP_AUDIT_CHECKPOINT_SCHEMA,
                    "lane": lane,
                    "event_ids": [event["event_id"] for event in events],
                    "head_hash": events[-1]["event_hash"],
                    "generation": checkpoint.generation,
                    "namespace": checkpoint.namespace,
                    "key_purpose": sources.checkpoint_key.purpose,
                    "key_id": sources.checkpoint_key.key_id,
                    "checkpoint": checkpoint.to_dict(),
                },
            ),
            "replay": replay_rows,
            "consumption": consumption,
            "fixture": _fixture_wrapper(lane, pin, protocol, before, after, call_log),
            "evidence": evidence,
            "pin": pin,
            "policy": json.loads(sources.policy_artifact),
            "policy_attestation": sources.policy_attestation.to_dict(),
        }
        return values, _trust_lane(sources)
    finally:
        await runtime.aclose()


async def export_genuine_mcp_proof(
    pack_output: str | Path,
    envelope_output: str | Path,
    *,
    runtime_root: str | Path,
    commit_guard: Callable[[str], None] | None = None,
    open_directory: OpenDirectory | None = None,
    expected_output_parent: str | Path | None = None,
    expected_parent_identity: DirectoryIdentity | None = None,
    pre_codec_barrier: Callable[[str], None] | None = None,
    output_capability: AttestedDirectory | None = None,
    runtime_capability: AttestedDirectory | None = None,
    _prompt_injection_scenario: bool = False,
) -> MCPGenuineProofExport | MCPGenuineProofLease:
    """Capture, seal, and offline-verify genuine normal and poisoned lanes."""

    if commit_guard is not None and not callable(commit_guard):
        raise TypeError("commit_guard must be callable")
    if pre_codec_barrier is not None and not callable(pre_codec_barrier):
        raise TypeError("pre_codec_barrier must be callable")
    if output_capability is not None:
        require_attested_directory(output_capability, error_type=MCPActionProofError)
        if any(
            value is not None
            for value in (open_directory, expected_output_parent, expected_parent_identity)
        ):
            raise MCPActionProofError("output capability cannot be mixed with legacy callbacks")
        output_capability.checkpoint()
        open_directory = output_capability.open_directory_path
        expected_output_parent = output_capability.display_path
        expected_parent_identity = output_capability.identity
    if runtime_capability is not None:
        require_attested_directory(runtime_capability, error_type=MCPActionProofError)
        runtime_capability.checkpoint()
    pack_output_path = Path(pack_output)
    envelope_output_path = Path(envelope_output)
    _pinned_output_parent_callbacks(
        pack_output_path,
        open_directory=open_directory,
        expected_output_parent=expected_output_parent,
        expected_parent_identity=expected_parent_identity,
    )
    envelope_open, envelope_assert = _pinned_output_parent_callbacks(
        envelope_output_path,
        open_directory=open_directory,
        expected_output_parent=expected_output_parent,
        expected_parent_identity=expected_parent_identity,
    )
    root = Path(runtime_root)
    if commit_guard is not None and runtime_capability is not None:
        commit_guard("before-runtime")
    if runtime_capability is None:
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        normal_capability = poison_capability = None
    else:
        runtime_capability.checkpoint()
        if root != runtime_capability.display_path:
            raise MCPActionProofError("runtime capability does not match runtime_root")
        normal_capability = runtime_capability.subdirectory("normal", create=True)
        poison_capability = runtime_capability.subdirectory("poison", create=True)
    capability_phase_hook = commit_guard if runtime_capability is not None else None
    try:
        normal, normal_trust = await _capture_lane(
            root / "normal", "normal", normal_capability, capability_phase_hook
        )
        poison, poison_trust = await _capture_lane(
            root / "poison", "poison", poison_capability, capability_phase_hook
        )
    finally:
        # These are exporter-owned children.  Closing each parent also closes
        # the private fixture child minted by create_reference_runtime.
        for lane_capability in (poison_capability, normal_capability):
            if lane_capability is not None:
                lane_capability.close()
    scenario: dict[str, Any] = {
        "schema": MCP_ACTION_SCENARIO_SCHEMA,
        "lanes": {"normal": normal["pin"], "poison": poison["pin"]},
    }
    if _prompt_injection_scenario:
        arguments = {"record": "genuine-poison-proof"}
        baseline_calls = _unsafe_prompt_injection_fixture_baseline(
            MCP_PROMPT_INJECTION_TEXT,
            MCP_POISONED_TOOL_DESCRIPTION,
            "fixture.write_once",
            arguments,
        )
        if baseline_calls != 1 or poison["protocol"]["downstream_call_count"] != 0:
            raise MCPActionProofError("prompt injection fixture counts are incompatible")
        scenario = {
            **scenario,
            "schema": MCP_PROMPT_INJECTION_SCENARIO_SCHEMA,
            "attack": {
                "schema": MCP_PROMPT_INJECTION_ATTACK_SCHEMA,
                "untrusted_prompt": MCP_PROMPT_INJECTION_TEXT,
                "poisoned_tool_description": MCP_POISONED_TOOL_DESCRIPTION,
                "tool_name": "fixture.write_once",
                "arguments": arguments,
                "baseline_protocol_record_id": "unsafe-baseline-prompt-injection",
                "governed_protocol_record_id": poison["protocol"]["record_id"],
                "expected_refusal_reason": "mcp.gateway.catalog_mismatch",
                "baseline_side_effect_calls": baseline_calls,
                "governed_downstream_calls": poison["protocol"]["downstream_call_count"],
                "unsafe_baseline_mode": "private-local-fixture-no-fallback",
                "prompt_used_as_policy_input": False,
            },
        }
    values: dict[str, Any] = {
        "scenario.json": scenario,
        "runtime-bindings.json": {
            "schema": MCP_RUNTIME_BINDINGS_SCHEMA,
            "lanes": {"normal": normal["pin"], "poison": poison["pin"]},
        },
        "policy.json": {
            "schema": MCP_POLICY_EVIDENCE_SCHEMA,
            "lanes": {
                "normal": {
                    **normal["pin"],
                    "artifact": normal["policy"],
                    "policy_attestation": normal["policy_attestation"],
                },
                "poison": {
                    **poison["pin"],
                    "artifact": poison["policy"],
                    "policy_attestation": poison["policy_attestation"],
                },
            },
        },
        "protocol-results.jsonl": [normal["protocol"], poison["protocol"]],
        "receipts.jsonl": [
            _evidence_row(
                normal["protocol"], "receipt", normal["evidence"], normal_trust["keys"]["receipt"]
            )
        ],
        "refusals.jsonl": [
            _evidence_row(
                poison["protocol"], "refusal", poison["evidence"], poison_trust["keys"]["refusal"]
            )
        ],
        "normal-audit.jsonl": normal["audit"],
        "normal-audit-checkpoint.json": normal["checkpoint"],
        "normal-replay.jsonl": normal["replay"],
        "normal-consumption-snapshot.json": normal["consumption"],
        "normal-fixture-state.json": normal["fixture"],
        "poison-audit.jsonl": poison["audit"],
        "poison-audit-checkpoint.json": poison["checkpoint"],
        "poison-consumption-snapshot.json": poison["consumption"],
        "poison-fixture-state.json": poison["fixture"],
    }
    payloads = MCPActionProofPayloads.from_values(values)
    trust = {
        "schema": MCP_ACTION_TRUST_SCHEMA,
        "lanes": {"normal": normal_trust, "poison": poison_trust},
    }
    predicted_entries = MCP_ACTION_PROOF_CODEC.manifest_entries(payloads.files)
    predicted_digest = MCP_ACTION_PROOF_CODEC.pack_digest(
        MCP_ACTION_PROOF_CODEC.manifest_payload(predicted_entries)
    )
    envelope_payloads = {
        "trust-bundle.json": MCP_PROOF_ENVELOPE_CODEC.json_bytes(trust),
        "expected-pack-digest.json": MCP_PROOF_ENVELOPE_CODEC.json_bytes(
            {"schema": MCP_EXPECTED_DIGEST_SCHEMA, "pack_digest": predicted_digest}
        ),
    }
    if commit_guard is not None:
        commit_guard("before-pack")
    if pre_codec_barrier is not None:
        pre_codec_barrier("pack")
    pack = export_mcp_proof_pack(
        pack_output_path,
        payloads,
        open_directory=open_directory,
        expected_output_parent=expected_output_parent,
        expected_parent_identity=expected_parent_identity,
    )
    if commit_guard is not None:
        try:
            commit_guard("after-pack")
        except Exception as exc:
            raise MCPGenuineProofExportError(
                "proof pack committed but the output-root identity guard failed; "
                "preserve the pack and do not retry in place",
                pack_digest=pack.pack_digest,
                cause=exc,
                phase="output-root:after-pack",
                envelope_committed=False,
                durability="pack-committed",
            ) from exc
    if pack.pack_digest != predicted_digest:
        cause = MCPActionProofError(
            "committed pack digest differs from its frozen preflight digest"
        )
        raise MCPGenuineProofExportError(
            "proof pack committed but its returned digest failed the frozen digest guard; "
            "preserve the pack and do not retry in place",
            pack_digest=predicted_digest,
            cause=cause,
            phase="post-pack-digest-guard",
            envelope_committed=False,
            durability="pack-committed",
        ) from cause
    if commit_guard is not None:
        try:
            commit_guard("before-envelope")
        except Exception as exc:
            raise MCPGenuineProofExportError(
                "proof pack committed but the output-root identity guard failed before the "
                "envelope; preserve the pack and do not retry in place",
                pack_digest=pack.pack_digest,
                cause=exc,
                phase="output-root:before-envelope",
                envelope_committed=False,
                durability="pack-committed",
            ) from exc
    try:
        if pre_codec_barrier is not None:
            pre_codec_barrier("envelope")
        _manifest, envelope_digest = MCP_PROOF_ENVELOPE_CODEC.export_new_pack(
            envelope_output_path,
            envelope_payloads,
            open_directory=envelope_open,
            assert_path_identity=envelope_assert,
        )
    except Exception as exc:
        raise MCPGenuineProofExportError(
            "proof pack committed; external trust envelope failed; do not delete or retry the pack",
            pack_digest=pack.pack_digest,
            cause=exc,
            phase=f"envelope:{getattr(exc, 'phase', 'preflight')}",
        ) from exc
    if commit_guard is not None:
        try:
            commit_guard("after-envelope")
        except Exception as exc:
            raise MCPGenuineProofExportError(
                "proof pack and trust envelope committed but the output-root identity guard "
                "failed; preserve both artifacts and do not retry in place",
                pack_digest=pack.pack_digest,
                cause=exc,
                phase="output-root:after-envelope",
                envelope_committed=True,
                durability="pack-and-envelope-committed",
            ) from exc
    lease: MCPGenuineProofLease | None = None
    try:
        if commit_guard is not None and output_capability is not None:
            commit_guard("before-verify")
        if output_capability is None:
            verified_digest = verify_exported_mcp_proof(
                pack.directory,
                envelope_output_path,
                expected_envelope_digest=envelope_digest,
            )
        else:
            pack_owned = output_capability.detach_subdirectory(pack_output_path.name)
            try:
                envelope_owned = output_capability.detach_subdirectory(envelope_output_path.name)
            except BaseException:
                pack_owned.close()
                raise
            lease = _mint_mcp_genuine_proof_lease(pack_owned, envelope_owned)
            verified_digest = lease.verify()
            if not hmac.compare_digest(lease.envelope_digest, envelope_digest):
                raise MCPActionProofError(
                    "owned proof envelope digest does not match the committed envelope"
                )
        if not hmac.compare_digest(verified_digest, pack.pack_digest):
            raise MCPActionProofError("offline proof digest does not match the committed pack")
    except Exception as exc:
        if lease is not None:
            lease.close()
        raise MCPGenuineProofExportError(
            "proof pack and trust envelope committed but offline verification failed; "
            "preserve both artifacts and do not retry in place",
            pack_digest=pack.pack_digest,
            cause=exc,
            phase="post-envelope-offline-verify",
            envelope_committed=True,
            durability="pack-and-envelope-committed",
        ) from exc
    if commit_guard is not None and output_capability is not None:
        try:
            commit_guard("verified")
        except Exception:
            if lease is not None:
                lease.close()
            raise
    try:
        if runtime_capability is not None:
            runtime_capability.checkpoint()
        if lease is not None:
            if not hmac.compare_digest(lease.verify(), pack.pack_digest):
                raise MCPActionProofError("terminal lease verification digest mismatch")
            return lease
    except Exception:
        if lease is not None:
            lease.close()
        raise
    return MCPGenuineProofExport(
        pack_directory=pack.directory,
        pack_digest=pack.pack_digest,
        envelope_directory=envelope_output_path,
        envelope_digest=envelope_digest,
    )


async def export_prompt_injection_disaster_proof(
    pack_output: str | Path,
    envelope_output: str | Path,
    *,
    runtime_root: str | Path,
    commit_guard: Callable[[str], None] | None = None,
    open_directory: OpenDirectory | None = None,
    expected_output_parent: str | Path | None = None,
    expected_parent_identity: DirectoryIdentity | None = None,
    pre_codec_barrier: Callable[[str], None] | None = None,
    output_capability: AttestedDirectory | None = None,
    runtime_capability: AttestedDirectory | None = None,
) -> MCPGenuineProofExport | MCPGenuineProofLease:
    """Seal the exact prompt-injection fixture in the native MCP proof pack."""

    return await export_genuine_mcp_proof(
        pack_output,
        envelope_output,
        runtime_root=runtime_root,
        commit_guard=commit_guard,
        open_directory=open_directory,
        expected_output_parent=expected_output_parent,
        expected_parent_identity=expected_parent_identity,
        pre_codec_barrier=pre_codec_barrier,
        output_capability=output_capability,
        runtime_capability=runtime_capability,
        _prompt_injection_scenario=True,
    )


def _unsafe_prompt_injection_fixture_baseline(
    prompt: str,
    description: str,
    tool_name: str,
    arguments: Mapping[str, Any],
) -> int:
    """Model an ungoverned local call; never used as a gateway fallback."""

    if (
        prompt != MCP_PROMPT_INJECTION_TEXT
        or description != MCP_POISONED_TOOL_DESCRIPTION
        or tool_name != "fixture.write_once"
        or dict(arguments) != {"record": "genuine-poison-proof"}
    ):
        raise MCPActionProofError("unsafe prompt-injection baseline is not the fixed fixture")
    return 1


def verify_exported_mcp_proof(
    pack: str | Path,
    envelope: str | Path,
    *,
    expected_envelope_digest: str,
    path_capability: AttestedDirectory | None = None,
) -> str:
    """Strongly verify an export and return only its informational pack digest.

    The operation always rereads and verifies the pack and external envelope. The
    returned built-in string is not accepted by any execution path as authorization.
    Control of this trusted verifier process is outside the threat model.
    """

    if (
        type(expected_envelope_digest) is not str
        or _SHA256_RE.fullmatch(expected_envelope_digest) is None
    ):
        raise MCPActionProofError("expected envelope digest must be lowercase SHA-256")
    if path_capability is not None:
        require_attested_directory(path_capability, error_type=MCPActionProofError)
        path_capability.checkpoint()
    raw = (
        MCP_PROOF_ENVELOPE_CODEC.read_exact_pack(Path(envelope))
        if path_capability is None
        else MCP_PROOF_ENVELOPE_CODEC.read_exact_pack(
            Path(envelope),
            open_directory=path_capability.open_directory_path,
            assert_path_identity=path_capability.assert_path_identity,
        )
    )
    manifest = MCP_PROOF_ENVELOPE_CODEC.strict_json(raw["manifest.json"], "manifest.json")
    if type(manifest) is not dict or type(manifest.get("pack_digest")) is not str:
        raise MCPActionProofError("verification envelope manifest is incompatible")
    actual_envelope_digest = cast(str, manifest["pack_digest"])
    if not hmac.compare_digest(actual_envelope_digest, expected_envelope_digest):
        raise MCPActionProofError("external expected envelope digest mismatch")
    expected = MCP_PROOF_ENVELOPE_CODEC.strict_json(
        raw["expected-pack-digest.json"], "expected-pack-digest.json"
    )
    if type(expected) is not dict or set(expected) != {"schema", "pack_digest"}:
        raise MCPActionProofError("expected digest envelope member has an incompatible shape")
    if expected["schema"] != MCP_EXPECTED_DIGEST_SCHEMA:
        raise MCPActionProofError("expected digest envelope schema is unsupported")
    return _verify_mcp_proof_pack_with_trust_bytes(
        pack,
        trust_bundle_bytes=raw["trust-bundle.json"],
        expected_pack_digest=cast(str, expected["pack_digest"]),
        open_directory=(path_capability.open_directory_path if path_capability else None),
        assert_path_identity=(path_capability.assert_path_identity if path_capability else None),
    )


def _verify_exported_mcp_proof_attested(
    pack: AttestedDirectory,
    envelope: AttestedDirectory,
    *,
    expected_envelope_digest: str,
) -> str:
    if (
        type(expected_envelope_digest) is not str
        or _SHA256_RE.fullmatch(expected_envelope_digest) is None
    ):
        raise MCPActionProofError("expected envelope digest must be lowercase SHA-256")
    require_attested_directory(pack, error_type=MCPActionProofError)
    require_attested_directory(envelope, error_type=MCPActionProofError)
    raw = MCP_PROOF_ENVELOPE_CODEC.read_exact_pack_attested(envelope)
    manifest = MCP_PROOF_ENVELOPE_CODEC.strict_json(raw["manifest.json"], "manifest.json")
    if type(manifest) is not dict or type(manifest.get("pack_digest")) is not str:
        raise MCPActionProofError("verification envelope manifest is incompatible")
    actual_envelope_digest = cast(str, manifest["pack_digest"])
    if not hmac.compare_digest(actual_envelope_digest, expected_envelope_digest):
        raise MCPActionProofError("external expected envelope digest mismatch")
    expected = MCP_PROOF_ENVELOPE_CODEC.strict_json(
        raw["expected-pack-digest.json"], "expected-pack-digest.json"
    )
    if type(expected) is not dict or set(expected) != {"schema", "pack_digest"}:
        raise MCPActionProofError("expected digest envelope member has an incompatible shape")
    if expected["schema"] != MCP_EXPECTED_DIGEST_SCHEMA:
        raise MCPActionProofError("expected digest envelope schema is unsupported")
    return _verify_mcp_proof_pack_with_trust_bytes(
        pack.display_path,
        trust_bundle_bytes=raw["trust-bundle.json"],
        expected_pack_digest=cast(str, expected["pack_digest"]),
        directory_capability=pack,
    )


__all__ = [
    "MCPGenuineProofExport",
    "MCPGenuineProofLease",
    "MCPGenuineProofExportError",
    "MCP_EXPECTED_DIGEST_SCHEMA",
    "MCP_PROOF_ENVELOPE_CODEC",
    "MCP_PROOF_ENVELOPE_SCHEMA",
    "export_genuine_mcp_proof",
    "export_prompt_injection_disaster_proof",
    "verify_exported_mcp_proof",
]
