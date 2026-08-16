from __future__ import annotations

import copy
import dataclasses
import hashlib
import inspect
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

import gove_zone.mcp_proof as mcp_proof_module
import gove_zone.mcp_reference as mcp_reference_module
from gove_zone.audit import (
    GENESIS_CHECKPOINT_HASH,
    GENESIS_HASH,
    AuditCheckpoint,
    ChainHashAuditStore,
)
from gove_zone.authorization import (
    REFUSAL_EVIDENCE_SCHEMA,
    AuthorizationReasonCode,
    PolicyArtifactAttestation,
    RefusalEvidence,
    strict_json_hash,
)
from gove_zone.consumption import (
    AnchoredConsumptionState,
    ConsumptionState,
    ReceiptConsumptionStore,
)
from gove_zone.decision import Decision, DecisionRecord, RecordKind, canonical_json
from gove_zone.mcp_proof import (
    MCP_ACTION_PROOF_CODEC,
    MCP_ACTION_PROOF_PAYLOAD_FILES,
    MCP_ACTION_PROOF_SCHEMA,
    MCP_ACTION_TRUST_SCHEMA,
    MCP_AUDIT_CHECKPOINT_SCHEMA,
    MCP_CONSUMPTION_SNAPSHOT_SCHEMA,
    MCP_FIXTURE_STATE_SCHEMA,
    MCPActionProofError,
    MCPActionProofPayloads,
    export_mcp_proof_pack,
    replay_mcp_proof_pack,
    verify_mcp_proof_pack,
)
from gove_zone.mcp_reference import MCPSignedConsumptionSnapshot
from gove_zone.proof_pack import SealedPackExportError
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.replay_store import ReplaySideStore
from gove_zone.signing import Ed25519Signer, LifecycleAttestation
from gove_zone.tool import ToolCall


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


_POLICY_ARTIFACT = {"decision": "allow", "version": "mcp-reference-policy/v1"}
_CONSUMPTION_WRAPPER_DOMAIN = b"gove-zone:mcp-action-consumption-wrapper:v2\x00"
_GATEWAY_EXCHANGE_DOMAIN = b"gove-zone:mcp-gateway-exchange:v2\x00"
_PURPOSES = {
    "receipt": "receipt",
    "refusal": "refusal",
    "checkpoint": "audit-checkpoint",
    "consumption": "consumption-snapshot",
    "exchange": "gateway-exchange",
    "lifecycle": "lifecycle-attestation",
}


def _key(slot: str, signer: Ed25519Signer) -> dict[str, str]:
    return {
        "purpose": _PURPOSES[slot],
        "key_id": signer.key_id,
        "algorithm": "ed25519",
        "public_bytes_hex": signer.public_bytes().hex(),
    }


def _lane(name: str, signers: dict[str, Ed25519Signer]) -> tuple[dict[str, Any], dict[str, Any]]:
    policy_digest = strict_json_hash(_POLICY_ARTIFACT)
    target = {
        "server_digest": _digest(f"{name}-server"),
        "launch_digest": _digest(f"{name}-launch"),
        "transport_digest": _digest(f"{name}-transport"),
        "artifact_digest": _digest(f"{name}-artifact"),
    }
    pin = {
        "tenant_id": f"tenant-{name}",
        "policy_version": "mcp-reference-policy/v1",
        "policy_digest": policy_digest,
        "target": target,
    }
    trust = {
        **pin,
        "policy_attestation": PolicyArtifactAttestation(
            tenant_id=f"tenant-{name}",
            artifact_id="mcp-reference-policy",
            policy_version="mcp-reference-policy/v1",
            digest=policy_digest,
            resolver_id="mcp-reference-policy-resolver",
        ).to_dict(),
        "checkpoint_authority_id": f"audit-checkpoint:mcp-proof:{name}",
        "lifecycle_authority_id": f"mcp-execution-validator:{name}",
        "keys": {slot: _key(slot, signers[slot]) for slot in _PURPOSES},
    }
    return pin, trust


class _Anchor:
    def __init__(self) -> None:
        self.current: dict[str, AuditCheckpoint] = {}

    def read(self, namespace: str) -> AuditCheckpoint | None:
        return self.current.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool:
        if self.current.get(namespace) != expected:
            return False
        self.current[namespace] = replacement
        return True


class _ConsumptionAnchor:
    def __init__(self) -> None:
        self.current: dict[str, AnchoredConsumptionState] = {}

    def read(self, namespace: str) -> AnchoredConsumptionState | None:
        return self.current.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AnchoredConsumptionState | None,
        replacement: AnchoredConsumptionState,
    ) -> bool:
        if self.current.get(namespace) != expected:
            return False
        self.current[namespace] = replacement
        return True


def _audit_record(
    root: Path,
    lane: str,
    record: DecisionRecord,
    signer: Ed25519Signer,
) -> tuple[dict[str, Any], AuditCheckpoint]:
    anchor = _Anchor()
    namespace = f"mcp-proof:{lane}"
    store = ChainHashAuditStore(
        root / f"{lane}-audit.jsonl",
        checkpoint_anchor=anchor,
        checkpoint_namespace=namespace,
        checkpoint_signer=signer,
        checkpoint_verifier={signer.key_id: signer},
        require_trusted_checkpoint=True,
    )
    commit = store.append_committed(record)
    assert store.verify_checkpointed_chain()["valid"] is True
    return commit.event, commit.checkpoint


def _evidence_digest(label: str, value: str) -> str:
    return strict_json_hash(
        {
            "domain": "gove-zone:standalone-execution-evidence:v1",
            "field": label,
            "value": value,
        }
    )


def _normal_audit_lifecycle(
    root: Path,
    record: DecisionRecord,
    *,
    tenant_id: str,
    policy_digest: str,
    request_id: str,
    checkpoint_signer: Ed25519Signer,
    receipt_signer: Ed25519Signer,
    lifecycle_signer: Ed25519Signer,
    lifecycle_authority_id: str,
) -> tuple[list[dict[str, Any]], AuditCheckpoint, DecisionReceipt]:
    anchor = _Anchor()
    namespace = "mcp-proof:normal"
    store = ChainHashAuditStore(
        root / "normal-audit.jsonl",
        checkpoint_anchor=anchor,
        checkpoint_namespace=namespace,
        checkpoint_signer=checkpoint_signer,
        checkpoint_verifier={checkpoint_signer.key_id: checkpoint_signer},
        require_trusted_checkpoint=True,
    )
    authorization = store.append_committed(record)
    receipt = DecisionReceipt.from_record(
        record,
        audit_hash=authorization.event["event_hash"],
        previous_audit_hash=authorization.event["previous_hash"],
        tenant_id=tenant_id,
        execution_boundary="acgs-mcp-action-gateway",
        policy_bundle_id="mcp-reference-policy",
        policy_hash=policy_digest,
        request_id=request_id,
        validator=Validator("fixture-security-approver", "approver"),
        authority="mcp.tools.call",
        constraints={
            "_acgs_side_effect_v2": {
                "operation": "tools/call",
                "authority": "mcp.tools.call",
                "tool": "fixture.write_once",
            }
        },
        signer=receipt_signer,
    )
    stable = {
        "tenant_digest": _evidence_digest("tenant", tenant_id),
        "execution_boundary_digest": _evidence_digest(
            "execution_boundary", "acgs-mcp-action-gateway"
        ),
        "adapter_id_digest": _digest("normal-adapter-id"),
        "adapter_artifact_digest": _digest("normal-adapter-artifact"),
        "receipt_id_digest": _evidence_digest("receipt_id", receipt.receipt_id),
        "receipt_hash": receipt.receipt_hash,
        "request_id_digest": _evidence_digest("request_id", request_id),
        "authorization_audit_digest": _evidence_digest(
            "authorization_audit", receipt.audit_event_hash
        ),
        "nonce_digest": _digest("normal-nonce"),
        "idempotency_digest": _digest("normal-idempotency"),
        "attempt_id_digest": _digest("normal-attempt"),
        "binding_hash": _digest("normal-binding"),
        "argument_hash": record.argument_hash,
    }
    events = [authorization.event]
    checkpoint = authorization.checkpoint
    for timestamp, phase, reason, state in (
        (
            "2026-01-01T00:00:01+00:00",
            "claim_committed",
            "receipt.execution.reserved",
            "RESERVED",
        ),
        (
            "2026-01-01T00:00:02+00:00",
            "terminal",
            "receipt.execution.succeeded",
            "SUCCEEDED",
        ),
    ):
        lifecycle = DecisionRecord.lifecycle(
            decision=Decision.ALLOW,
            tool=record.tool,
            argument_hash=record.argument_hash,
            policy_version=record.policy_version,
            event_id=f"normal-{phase}-event",
            matched_rules=(reason,),
            reason=reason,
            timestamp_iso=timestamp,
            goal="",
            actor=record.actor,
            path=(),
            state_hash=None,
            decision_request_hash="",
            execution_evidence={
                **stable,
                "phase": phase,
                "reason_code": reason,
                "consumption_state": state,
            },
            signer=lifecycle_signer,
            authority_id=lifecycle_authority_id,
        )
        committed = store.append_committed(lifecycle)
        events.append(committed.event)
        checkpoint = committed.checkpoint
    assert store.verify_checkpointed_chain()["valid"] is True
    return events, checkpoint, receipt


def _fixture_values() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, dict[str, Ed25519Signer]],
]:
    signers = {
        lane: {slot: Ed25519Signer.generate(f"{lane}-{slot}-key") for slot in _PURPOSES}
        for lane in ("normal", "poison")
    }
    normal_pin, normal_trust = _lane("normal", signers["normal"])
    poison_pin, poison_trust = _lane("poison", signers["poison"])

    def pinned(pin: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
        return {**copy.deepcopy(pin), **values}

    normal_call = ToolCall(
        name="tools/call",
        args={"record": "semantic-proof"},
        goal="prove semantic verification",
        actor="fixture-agent",
        path=("mcp", "fixture"),
        state={
            "ledger": _digest("ledger-before"),
            "operation": "tools/call",
            "authority": "mcp.tools.call",
            "tool": "fixture.write_once",
        },
    )
    poison_call = ToolCall(
        name="tools/call",
        args={"record": "poison"},
        goal="prove refusal",
        actor="fixture-agent-poison",
        path=("mcp", "fixture"),
        state={
            "ledger": _digest("poison-ledger"),
            "operation": "tools/call",
            "authority": "mcp.tools.call",
            "tool": "fixture.write_once",
        },
    )
    normal_record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=normal_call.name,
        argument_hash=normal_call.argument_hash(),
        policy_version="mcp-reference-policy/v1",
        event_id="normal-event-1",
        matched_rules=("MCP_REFERENCE_ALLOW",),
        reason="fixture-only reference policy",
        timestamp_iso="2026-01-01T00:00:00+00:00",
        goal=normal_call.goal,
        actor=normal_call.actor,
        path=normal_call.path,
        state_hash=normal_call.state_hash(),
        decision_request_hash=normal_call.decision_request_hash(),
    )
    refusal_state = {
        "schema": REFUSAL_EVIDENCE_SCHEMA,
        "request_id": "request-poison",
        "reason_code": AuthorizationReasonCode.INTERNAL_FAILURE.value,
        "decision": Decision.DENY.value,
        "reason_codes": ["mcp.gateway.catalog_mismatch"],
        "claimed_tenant_id": poison_pin["tenant_id"],
        "claimed_actor_id": poison_call.actor,
        "operation": poison_call.name,
        "argument_hash": poison_call.argument_hash(),
        "policy_digest": poison_pin["policy_digest"],
        "principal_verified": True,
    }
    poison_record = DecisionRecord(
        decision=Decision.DENY,
        tool=poison_call.name,
        argument_hash=poison_call.argument_hash(),
        policy_version="mcp-reference-policy/v1",
        event_id="poison-event-1",
        matched_rules=("mcp.gateway.catalog_mismatch",),
        reason="fixture catalog pinning refusal",
        timestamp_iso="2026-01-01T00:00:01+00:00",
        goal=poison_call.goal,
        actor=poison_call.actor,
        path=poison_call.path,
        state_hash=strict_json_hash(refusal_state),
        decision_request_hash=poison_call.decision_request_hash(),
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        normal_events, normal_checkpoint, normal_receipt = _normal_audit_lifecycle(
            root,
            normal_record,
            tenant_id=normal_pin["tenant_id"],
            policy_digest=normal_pin["policy_digest"],
            request_id="request-normal",
            checkpoint_signer=signers["normal"]["checkpoint"],
            receipt_signer=signers["normal"]["receipt"],
            lifecycle_signer=signers["normal"]["lifecycle"],
            lifecycle_authority_id=normal_trust["lifecycle_authority_id"],
        )
        normal_event = normal_events[0]
        poison_event, poison_checkpoint = _audit_record(
            root, "poison", poison_record, signers["poison"]["checkpoint"]
        )
        replay_store = ReplaySideStore(root / "normal-replay.jsonl")
        normal_side = replay_store.append(normal_call, normal_record)

    refusal = RefusalEvidence(
        request_id="request-poison",
        reason_code=AuthorizationReasonCode.INTERNAL_FAILURE,
        decision=Decision.DENY,
        reason_codes=("mcp.gateway.catalog_mismatch",),
        claimed_tenant_id=poison_pin["tenant_id"],
        claimed_actor_id=poison_call.actor,
        operation=poison_call.name,
        argument_hash=poison_call.argument_hash(),
        policy_digest=poison_pin["policy_digest"],
        principal_verified=True,
        audited=True,
        audit_event_id=poison_event["event_id"],
        audit_event_hash=poison_event["event_hash"],
        audit_checkpoint_hash=poison_checkpoint.checkpoint_hash,
        signed=True,
        signing_key_id=signers["poison"]["refusal"].key_id,
        signature_algorithm="ed25519",
        signature="0" * 128,
    )
    refusal = dataclasses.replace(
        refusal,
        signature=signers["poison"]["refusal"].sign(refusal.payload_hash.encode()),
    )

    result_digest = _digest("normal-result")
    protocol = [
        pinned(
            normal_pin,
            {
                "record_id": "protocol-normal",
                "lane": "normal",
                "event_id": normal_record.event_id,
                "decision_id": normal_record.event_id,
                "request_id": normal_receipt.request_id,
                "actor": normal_call.actor,
                "decision": "ALLOW",
                "status": "succeeded",
                "executed": True,
                "retryable": False,
                "outcome_unknown": False,
                "downstream_call_count": 1,
                "side_effect_write_count": 1,
                "governed_operation": normal_call.name,
                "authority": "mcp.tools.call",
                "downstream_tool": "fixture.write_once",
                "arguments_hash": normal_call.argument_hash(),
                "attempt_digest": strict_json_hash(
                    {
                        "request_id": normal_receipt.request_id,
                        "governed_operation": normal_call.name,
                        "authority": "mcp.tools.call",
                        "downstream_tool": "fixture.write_once",
                        "arguments_hash": normal_call.argument_hash(),
                    }
                ),
                "downstream_call_digest": strict_json_hash(
                    {
                        "method": "tools/call",
                        "request_id": normal_receipt.request_id,
                        "tool_name": "fixture.write_once",
                        "arguments": normal_call.args,
                    }
                ),
                "result_digest": result_digest,
                "evidence_kind": "receipt",
                "evidence_id": normal_record.event_id,
                "signature_purpose": "gateway-exchange",
                "signature_key_id": signers["normal"]["exchange"].key_id,
                "signature_algorithm": "ed25519",
                "signature": "pending",
            },
        ),
        pinned(
            poison_pin,
            {
                "record_id": "protocol-poison",
                "lane": "poison",
                "event_id": poison_record.event_id,
                "decision_id": poison_record.event_id,
                "request_id": refusal.request_id,
                "actor": poison_call.actor,
                "decision": "DENY",
                "status": "refused",
                "executed": False,
                "retryable": False,
                "outcome_unknown": False,
                "downstream_call_count": 0,
                "side_effect_write_count": 0,
                "governed_operation": poison_call.name,
                "authority": "mcp.tools.call",
                "downstream_tool": "fixture.write_once",
                "arguments_hash": poison_call.argument_hash(),
                "attempt_digest": strict_json_hash(
                    {
                        "request_id": refusal.request_id,
                        "governed_operation": poison_call.name,
                        "authority": "mcp.tools.call",
                        "downstream_tool": "fixture.write_once",
                        "arguments_hash": poison_call.argument_hash(),
                    }
                ),
                "downstream_call_digest": "",
                "result_digest": "",
                "evidence_kind": "refusal",
                "evidence_id": poison_record.event_id,
                "signature_purpose": "gateway-exchange",
                "signature_key_id": signers["poison"]["exchange"].key_id,
                "signature_algorithm": "ed25519",
                "signature": "pending",
            },
        ),
    ]
    for lane, row in zip(("normal", "poison"), protocol, strict=True):
        unsigned = dict(row)
        unsigned.pop("signature")
        row["signature"] = signers[lane]["exchange"].sign(
            _GATEWAY_EXCHANGE_DOMAIN + canonical_json(unsigned).encode()
        )

    def evidence_row(
        row: dict[str, Any], purpose: str, trust_lane: dict[str, Any], evidence: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            **{
                name: copy.deepcopy(row[name])
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
            "record_id": f"{purpose}-row-{row['event_id']}",
            "key_purpose": trust_lane["keys"][purpose]["purpose"],
            "key_id": trust_lane["keys"][purpose]["key_id"],
            "evidence": evidence,
        }

    def audit_wrapper(lane: str, pin: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        return pinned(
            pin,
            {
                "record_id": f"audit-{event['event_id']}",
                "lane": lane,
                "event_id": event["event_id"],
                "event": event,
            },
        )

    def checkpoint_wrapper(
        lane: str, pin: dict[str, Any], trust_lane: dict[str, Any], checkpoint: AuditCheckpoint
    ) -> dict[str, Any]:
        return pinned(
            pin,
            {
                "schema": MCP_AUDIT_CHECKPOINT_SCHEMA,
                "lane": lane,
                "event_ids": [
                    event["event_id"]
                    for event in (normal_events if lane == "normal" else [poison_event])
                ],
                "head_hash": checkpoint.head_hash,
                "generation": checkpoint.generation,
                "namespace": checkpoint.namespace,
                "key_purpose": trust_lane["keys"]["checkpoint"]["purpose"],
                "key_id": trust_lane["keys"]["checkpoint"]["key_id"],
                "checkpoint": checkpoint.to_dict(),
            },
        )

    def consumption_wrapper(
        lane: str, pin: dict[str, Any], trust_lane: dict[str, Any], row: dict[str, Any]
    ) -> dict[str, Any]:
        has_effect = lane == "normal"
        key = signers[lane]["consumption"]
        anchor_namespace = f"mcp-proof-consumption:{lane}"
        anchor = _ConsumptionAnchor()
        records = []
        with tempfile.TemporaryDirectory() as temporary:
            store = ReceiptConsumptionStore(
                Path(temporary) / "consumption.db",
                hmac_key=b"fixture-consumption-hmac-key-32-bytes",
                state_anchor=anchor,
                anchor_namespace=anchor_namespace,
                require_trusted_anchor=True,
            )
            if has_effect:
                store.reserve(
                    pin["tenant_id"],
                    normal_receipt.receipt_id,
                    "fixture-reservation-value",
                    normal_receipt.receipt_hash,
                    _digest("normal-binding"),
                    "normal-attempt",
                    idempotency_digest=_digest("normal-idempotency-binding"),
                )
                terminal = store.mark_succeeded(
                    pin["tenant_id"], normal_receipt.receipt_id, "normal-attempt"
                )
                assert terminal.state is ConsumptionState.SUCCEEDED
                records = [
                    {
                        "event_id": row["event_id"],
                        "outcome_record_id": row["record_id"],
                        "receipt_id": terminal.receipt_id,
                        "receipt_hash": terminal.receipt_hash,
                        "state": terminal.state.value,
                        "result_digest": row["result_digest"],
                        "audit_event_hash": normal_event["event_hash"],
                        "tenant_id": terminal.tenant_id,
                        "actor": row["actor"],
                        "governed_operation": row["governed_operation"],
                        "authority": row["authority"],
                        "downstream_tool": row["downstream_tool"],
                        "arguments_hash": row["arguments_hash"],
                    }
                ]
            anchored = anchor.read(anchor_namespace)
            assert anchored is not None
        unsigned_snapshot = MCPSignedConsumptionSnapshot(
            tenant_id=pin["tenant_id"],
            anchor_namespace=anchor_namespace,
            store_id=anchored.store_id,
            generation=anchored.generation,
            chain_head=anchored.chain_head,
            state_root=anchored.state_root,
            key_id=key.key_id,
            algorithm="ed25519",
            signature="0" * 128,
        )
        snapshot = dataclasses.replace(
            unsigned_snapshot, signature=key.sign(unsigned_snapshot.signing_payload())
        )
        wrapper = pinned(
            pin,
            {
                "schema": MCP_CONSUMPTION_SNAPSHOT_SCHEMA,
                "lane": lane,
                "event_ids": [row["event_id"]] if has_effect else [],
                "outcome_record_ids": [row["record_id"]] if has_effect else [],
                "anchor_namespace": anchor_namespace,
                "store_id": anchored.store_id,
                "generation": anchored.generation,
                "chain_head": anchored.chain_head,
                "state_root": anchored.state_root,
                "key_purpose": trust_lane["keys"]["consumption"]["purpose"],
                "key_id": key.key_id,
                "snapshot": snapshot.to_dict(),
                "records": records,
                "outer_algorithm": "ed25519",
                "outer_signature": "pending",
            },
        )
        unsigned = dict(wrapper)
        unsigned.pop("outer_signature")
        wrapper["outer_signature"] = key.sign(
            _CONSUMPTION_WRAPPER_DOMAIN + canonical_json(unsigned).encode()
        )
        return wrapper

    def fixture(lane: str, pin: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
        normal = lane == "normal"
        ledger_before: list[dict[str, str]] = []
        ledger_after = [{"record": "semantic-proof"}] if normal else []
        call_log = [{"tool": row["downstream_tool"]}] if normal else []
        event_ids = [row["event_id"]]
        outcome_ids = [row["record_id"]]
        return pinned(
            pin,
            {
                "schema": MCP_FIXTURE_STATE_SCHEMA,
                "lane": lane,
                "event_ids": event_ids,
                "outcome_record_ids": outcome_ids,
                "ledger_before": ledger_before,
                "ledger_after": ledger_after,
                "ledger_before_count": len(ledger_before),
                "ledger_after_count": len(ledger_after),
                "write_delta": len(ledger_after) - len(ledger_before),
                "call_count": len(call_log),
                "event_digest": strict_json_hash(event_ids),
                "outcome_digest": strict_json_hash(outcome_ids),
                "ledger_before_digest": strict_json_hash(ledger_before),
                "ledger_after_digest": strict_json_hash(ledger_after),
                "write_delta_digest": strict_json_hash(
                    {
                        "before": len(ledger_before),
                        "after": len(ledger_after),
                        "delta": len(ledger_after) - len(ledger_before),
                    }
                ),
                "call_log_digest": strict_json_hash(call_log),
                "call_log": call_log,
            },
        )

    values: dict[str, Any] = {
        "scenario.json": {
            "schema": "gove-zone.mcp-action-proof-scenario/v2",
            "lanes": {"normal": normal_pin, "poison": poison_pin},
        },
        "runtime-bindings.json": {
            "schema": "gove-zone.mcp-action-runtime-bindings/v2",
            "lanes": {"normal": normal_pin, "poison": poison_pin},
        },
        "policy.json": {
            "schema": "gove-zone.mcp-action-policy-evidence/v2",
            "lanes": {
                "normal": {
                    **copy.deepcopy(normal_pin),
                    "artifact": copy.deepcopy(_POLICY_ARTIFACT),
                    "policy_attestation": copy.deepcopy(normal_trust["policy_attestation"]),
                },
                "poison": {
                    **copy.deepcopy(poison_pin),
                    "artifact": copy.deepcopy(_POLICY_ARTIFACT),
                    "policy_attestation": copy.deepcopy(poison_trust["policy_attestation"]),
                },
            },
        },
        "protocol-results.jsonl": protocol,
        "receipts.jsonl": [
            evidence_row(protocol[0], "receipt", normal_trust, normal_receipt.to_dict())
        ],
        "refusals.jsonl": [evidence_row(protocol[1], "refusal", poison_trust, refusal.to_dict())],
        "normal-audit.jsonl": [
            audit_wrapper("normal", normal_pin, event) for event in normal_events
        ],
        "normal-audit-checkpoint.json": checkpoint_wrapper(
            "normal", normal_pin, normal_trust, normal_checkpoint
        ),
        "normal-replay.jsonl": [
            pinned(
                normal_pin,
                {
                    "record_id": "replay-normal-event-1",
                    "lane": "normal",
                    "event_id": normal_record.event_id,
                    "side_record": normal_side,
                },
            )
        ],
        "normal-consumption-snapshot.json": consumption_wrapper(
            "normal", normal_pin, normal_trust, protocol[0]
        ),
        "normal-fixture-state.json": fixture("normal", normal_pin, protocol[0]),
        "poison-audit.jsonl": [audit_wrapper("poison", poison_pin, poison_event)],
        "poison-audit-checkpoint.json": checkpoint_wrapper(
            "poison", poison_pin, poison_trust, poison_checkpoint
        ),
        "poison-consumption-snapshot.json": consumption_wrapper(
            "poison", poison_pin, poison_trust, protocol[1]
        ),
        "poison-fixture-state.json": fixture("poison", poison_pin, protocol[1]),
    }
    trust = {
        "schema": MCP_ACTION_TRUST_SCHEMA,
        "lanes": {"normal": normal_trust, "poison": poison_trust},
    }
    return values, trust, signers


def _replace_poison_refusal_semantics(
    values: dict[str, Any],
    signers: dict[str, dict[str, Ed25519Signer]],
    *,
    reason_code: AuthorizationReasonCode,
    reason_codes: tuple[str, ...],
) -> None:
    """Rebuild every signed/audited poison link for a semantic mutation."""

    protocol = values["protocol-results.jsonl"][1]
    poison_call = ToolCall(
        name="tools/call",
        args={"record": "poison"},
        goal="prove refusal",
        actor=protocol["actor"],
        path=("mcp", "fixture"),
        state={
            "ledger": _digest("poison-ledger"),
            "operation": "tools/call",
            "authority": "mcp.tools.call",
            "tool": "fixture.write_once",
        },
    )
    refusal_state = {
        "schema": REFUSAL_EVIDENCE_SCHEMA,
        "request_id": protocol["request_id"],
        "reason_code": reason_code.value,
        "decision": Decision.DENY.value,
        "reason_codes": list(reason_codes),
        "claimed_tenant_id": protocol["tenant_id"],
        "claimed_actor_id": protocol["actor"],
        "operation": poison_call.name,
        "argument_hash": poison_call.argument_hash(),
        "policy_digest": protocol["policy_digest"],
        "principal_verified": True,
    }
    record = DecisionRecord(
        decision=Decision.DENY,
        tool=poison_call.name,
        argument_hash=poison_call.argument_hash(),
        policy_version="mcp-reference-policy/v1",
        event_id=protocol["event_id"],
        matched_rules=reason_codes,
        reason="fixture rebuilt poison refusal",
        timestamp_iso="2026-01-01T00:00:01+00:00",
        goal=poison_call.goal,
        actor=poison_call.actor,
        path=poison_call.path,
        state_hash=strict_json_hash(refusal_state),
        decision_request_hash=poison_call.decision_request_hash(),
    )
    with tempfile.TemporaryDirectory() as temporary:
        event, checkpoint = _audit_record(
            Path(temporary), "poison", record, signers["poison"]["checkpoint"]
        )
    audit_wrapper = values["poison-audit.jsonl"][0]
    audit_wrapper["event_id"] = event["event_id"]
    audit_wrapper["event"] = event
    checkpoint_wrapper = values["poison-audit-checkpoint.json"]
    checkpoint_wrapper["event_ids"] = [event["event_id"]]
    checkpoint_wrapper["head_hash"] = event["event_hash"]
    checkpoint_wrapper["generation"] = checkpoint.generation
    checkpoint_wrapper["namespace"] = checkpoint.namespace
    checkpoint_wrapper["checkpoint"] = checkpoint.to_dict()

    refusal = RefusalEvidence(
        request_id=protocol["request_id"],
        reason_code=reason_code,
        decision=Decision.DENY,
        reason_codes=reason_codes,
        claimed_tenant_id=protocol["tenant_id"],
        claimed_actor_id=protocol["actor"],
        operation=protocol["governed_operation"],
        argument_hash=protocol["arguments_hash"],
        policy_digest=protocol["policy_digest"],
        principal_verified=True,
        audited=True,
        audit_event_id=event["event_id"],
        audit_event_hash=event["event_hash"],
        audit_checkpoint_hash=checkpoint.checkpoint_hash,
        signed=True,
        signing_key_id=signers["poison"]["refusal"].key_id,
        signature_algorithm="ed25519",
        signature="0" * 128,
    )
    refusal = dataclasses.replace(
        refusal,
        signature=signers["poison"]["refusal"].sign(refusal.payload_hash.encode()),
    )
    values["refusals.jsonl"][0]["evidence"] = refusal.to_dict()
    unsigned_protocol = dict(protocol)
    unsigned_protocol.pop("signature")
    protocol["signature"] = signers["poison"]["exchange"].sign(
        _GATEWAY_EXCHANGE_DOMAIN + canonical_json(unsigned_protocol).encode()
    )


def _replace_normal_input_semantics(
    values: dict[str, Any],
    signers: dict[str, dict[str, Ed25519Signer]],
    args: dict[str, Any],
) -> None:
    """Rebuild all normal-lane evidence after replacing downstream input."""

    protocol = values["protocol-results.jsonl"][0]
    normal_call = ToolCall(
        name="tools/call",
        args=copy.deepcopy(args),
        goal="prove semantic verification",
        actor="fixture-agent",
        path=("mcp", "fixture"),
        state={
            "ledger": _digest("ledger-before"),
            "operation": "tools/call",
            "authority": "mcp.tools.call",
            "tool": "fixture.write_once",
        },
    )
    normal_record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=normal_call.name,
        argument_hash=normal_call.argument_hash(),
        policy_version="mcp-reference-policy/v1",
        event_id=protocol["event_id"],
        matched_rules=("MCP_REFERENCE_ALLOW",),
        reason="fixture-only reference policy",
        timestamp_iso="2026-01-01T00:00:00+00:00",
        goal=normal_call.goal,
        actor=normal_call.actor,
        path=normal_call.path,
        state_hash=normal_call.state_hash(),
        decision_request_hash=normal_call.decision_request_hash(),
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        events, checkpoint, receipt = _normal_audit_lifecycle(
            root,
            normal_record,
            tenant_id=protocol["tenant_id"],
            policy_digest=protocol["policy_digest"],
            request_id=protocol["request_id"],
            checkpoint_signer=signers["normal"]["checkpoint"],
            receipt_signer=signers["normal"]["receipt"],
            lifecycle_signer=signers["normal"]["lifecycle"],
            lifecycle_authority_id="mcp-execution-validator:normal",
        )
        event = events[0]
        replay_store = ReplaySideStore(root / "normal-replay.jsonl")
        side_record = replay_store.append(normal_call, normal_record)

    protocol["arguments_hash"] = normal_call.argument_hash()
    protocol["attempt_digest"] = strict_json_hash(
        {
            "request_id": protocol["request_id"],
            "governed_operation": protocol["governed_operation"],
            "authority": protocol["authority"],
            "downstream_tool": protocol["downstream_tool"],
            "arguments_hash": protocol["arguments_hash"],
        }
    )
    protocol["downstream_call_digest"] = strict_json_hash(
        {
            "method": protocol["governed_operation"],
            "request_id": protocol["request_id"],
            "tool_name": protocol["downstream_tool"],
            "arguments": args,
        }
    )
    unsigned_protocol = dict(protocol)
    unsigned_protocol.pop("signature")
    protocol["signature"] = signers["normal"]["exchange"].sign(
        _GATEWAY_EXCHANGE_DOMAIN + canonical_json(unsigned_protocol).encode()
    )

    audit_template = values["normal-audit.jsonl"][0]
    values["normal-audit.jsonl"] = [
        {
            **{
                name: copy.deepcopy(audit_template[name])
                for name in ("tenant_id", "policy_version", "policy_digest", "target")
            },
            "record_id": f"audit-{item['event_id']}",
            "lane": "normal",
            "event_id": item["event_id"],
            "event": item,
        }
        for item in events
    ]
    checkpoint_wrapper = values["normal-audit-checkpoint.json"]
    checkpoint_wrapper["event_ids"] = [item["event_id"] for item in events]
    checkpoint_wrapper["head_hash"] = events[-1]["event_hash"]
    checkpoint_wrapper["generation"] = checkpoint.generation
    checkpoint_wrapper["namespace"] = checkpoint.namespace
    checkpoint_wrapper["checkpoint"] = checkpoint.to_dict()
    replay_wrapper = values["normal-replay.jsonl"][0]
    replay_wrapper["event_id"] = event["event_id"]
    replay_wrapper["side_record"] = side_record

    receipt_wrapper = values["receipts.jsonl"][0]
    for name in (
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
    ):
        receipt_wrapper[name] = copy.deepcopy(protocol[name])
    receipt_wrapper["evidence"] = receipt.to_dict()

    anchor = _ConsumptionAnchor()
    anchor_namespace = "mcp-proof-consumption:normal"
    with tempfile.TemporaryDirectory() as temporary:
        store = ReceiptConsumptionStore(
            Path(temporary) / "consumption.db",
            hmac_key=b"fixture-consumption-hmac-key-32-bytes",
            state_anchor=anchor,
            anchor_namespace=anchor_namespace,
            require_trusted_anchor=True,
        )
        store.reserve(
            protocol["tenant_id"],
            receipt.receipt_id,
            "fixture-reservation-value",
            receipt.receipt_hash,
            _digest("normal-binding"),
            "normal-attempt",
            idempotency_digest=_digest("normal-idempotency-binding"),
        )
        terminal = store.mark_succeeded(protocol["tenant_id"], receipt.receipt_id, "normal-attempt")
        assert terminal.state is ConsumptionState.SUCCEEDED
        anchored = anchor.read(anchor_namespace)
        assert anchored is not None
    consumption_signer = signers["normal"]["consumption"]
    unsigned_snapshot = MCPSignedConsumptionSnapshot(
        tenant_id=protocol["tenant_id"],
        anchor_namespace=anchor_namespace,
        store_id=anchored.store_id,
        generation=anchored.generation,
        chain_head=anchored.chain_head,
        state_root=anchored.state_root,
        key_id=consumption_signer.key_id,
        algorithm="ed25519",
        signature="0" * 128,
    )
    snapshot = dataclasses.replace(
        unsigned_snapshot,
        signature=consumption_signer.sign(unsigned_snapshot.signing_payload()),
    )
    consumption = values["normal-consumption-snapshot.json"]
    consumption.update(
        {
            "event_ids": [event["event_id"]],
            "outcome_record_ids": [protocol["record_id"]],
            "anchor_namespace": anchor_namespace,
            "store_id": anchored.store_id,
            "generation": anchored.generation,
            "chain_head": anchored.chain_head,
            "state_root": anchored.state_root,
            "snapshot": snapshot.to_dict(),
            "records": [
                {
                    "event_id": event["event_id"],
                    "outcome_record_id": protocol["record_id"],
                    "receipt_id": terminal.receipt_id,
                    "receipt_hash": terminal.receipt_hash,
                    "state": terminal.state.value,
                    "result_digest": protocol["result_digest"],
                    "audit_event_hash": event["event_hash"],
                    "tenant_id": terminal.tenant_id,
                    "actor": protocol["actor"],
                    "governed_operation": protocol["governed_operation"],
                    "authority": protocol["authority"],
                    "downstream_tool": protocol["downstream_tool"],
                    "arguments_hash": protocol["arguments_hash"],
                }
            ],
            "outer_signature": "pending",
        }
    )
    unsigned_consumption = copy.deepcopy(consumption)
    unsigned_consumption.pop("outer_signature")
    consumption["outer_signature"] = consumption_signer.sign(
        _CONSUMPTION_WRAPPER_DOMAIN + canonical_json(unsigned_consumption).encode()
    )

    fixture = values["normal-fixture-state.json"]
    event_ids = [event["event_id"]]
    outcome_ids = [protocol["record_id"]]
    ledger_before: list[dict[str, Any]] = []
    ledger_after = [copy.deepcopy(args)]
    call_log = [{"tool": protocol["downstream_tool"]}]
    fixture.update(
        {
            "event_ids": event_ids,
            "outcome_record_ids": outcome_ids,
            "ledger_before": ledger_before,
            "ledger_after": ledger_after,
            "ledger_before_count": 0,
            "ledger_after_count": 1,
            "write_delta": 1,
            "call_count": 1,
            "event_digest": strict_json_hash(event_ids),
            "outcome_digest": strict_json_hash(outcome_ids),
            "ledger_before_digest": strict_json_hash(ledger_before),
            "ledger_after_digest": strict_json_hash(ledger_after),
            "write_delta_digest": strict_json_hash({"before": 0, "after": 1, "delta": 1}),
            "call_log_digest": strict_json_hash(call_log),
            "call_log": call_log,
        }
    )


def _values() -> tuple[dict[str, Any], dict[str, Any]]:
    values, trust, _signers = _fixture_values()
    return values, trust


def _build(tmp_path: Path) -> tuple[Path, Path, str]:
    values, trust = _values()
    pack = export_mcp_proof_pack(tmp_path / "pack", MCPActionProofPayloads.from_values(values))
    trust_path = tmp_path / "trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    return pack.directory, trust_path, pack.pack_digest


def _copy_pack(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination, symlinks=True)
    return destination


def _reseal(pack: Path) -> str:
    payloads = {name: (pack / name).read_bytes() for name in MCP_ACTION_PROOF_PAYLOAD_FILES}
    entries = MCP_ACTION_PROOF_CODEC.manifest_entries(payloads)
    unsigned = MCP_ACTION_PROOF_CODEC.manifest_payload(entries)
    digest = MCP_ACTION_PROOF_CODEC.pack_digest(unsigned)
    (pack / "manifest.json").write_bytes(
        MCP_ACTION_PROOF_CODEC.json_bytes({**unsigned, "pack_digest": digest})
    )
    return digest


def _rewrite_json(pack: Path, name: str, value: Any) -> str:
    (pack / name).write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(value))
    return _reseal(pack)


def _rewrite_payload(pack: Path, name: str, value: Any) -> str:
    if name.endswith(".jsonl"):
        data = MCP_ACTION_PROOF_CODEC.jsonl_bytes(value)
    else:
        data = MCP_ACTION_PROOF_CODEC.json_bytes(value)
    (pack / name).write_bytes(data)
    return _reseal(pack)


def _record_from_audit_event(event: dict[str, Any]) -> DecisionRecord:
    return DecisionRecord(
        decision=Decision(event["decision"]),
        tool=event["tool"],
        argument_hash=event["argument_hash"],
        policy_version=event["policy_version"],
        event_id=event["event_id"],
        matched_rules=tuple(event["matched_rules"]),
        reason=event["reason"],
        timestamp_iso=event["timestamp_iso"],
        transformed_args=copy.deepcopy(event["transformed_args"]),
        goal=event["goal"],
        actor=event["actor"],
        path=tuple(event["path"]),
        state_hash=event["state_hash"],
        decision_request_hash=event["decision_request_hash"],
        action_tier=event["action_tier"],
        declared_action_tier=event["declared_action_tier"],
        record_kind=RecordKind(event["record_kind"]),
        execution_evidence=copy.deepcopy(event.get("execution_evidence")),
        lifecycle_attestation=(
            LifecycleAttestation.from_dict(event["lifecycle_attestation"])
            if "lifecycle_attestation" in event
            else None
        ),
    )


def _rebuild_audit_lane(
    values: dict[str, Any],
    signers: dict[str, dict[str, Ed25519Signer]],
    lane: str,
    events: list[dict[str, Any]],
) -> None:
    """Recompute the local chain and signed final checkpoint after an attack mutation."""

    wrapper_template = values[f"{lane}-audit.jsonl"][0]
    rebuilt: list[dict[str, Any]] = []
    checkpoint: AuditCheckpoint | None = None
    with tempfile.TemporaryDirectory() as temporary:
        anchor = _Anchor()
        store = ChainHashAuditStore(
            Path(temporary) / f"{lane}-audit.jsonl",
            checkpoint_anchor=anchor,
            checkpoint_namespace=f"mcp-proof:{lane}",
            checkpoint_signer=signers[lane]["checkpoint"],
            checkpoint_verifier={signers[lane]["checkpoint"].key_id: signers[lane]["checkpoint"]},
            require_trusted_checkpoint=True,
        )
        for event in events:
            committed = store.append_committed(_record_from_audit_event(event))
            rebuilt.append(committed.event)
            checkpoint = committed.checkpoint

    values[f"{lane}-audit.jsonl"] = [
        {
            **{
                key: copy.deepcopy(value)
                for key, value in wrapper_template.items()
                if key not in {"record_id", "event_id", "event"}
            },
            "record_id": f"audit-{event['event_id']}",
            "event_id": event["event_id"],
            "event": event,
        }
        for event in rebuilt
    ]
    checkpoint_wrapper = values[f"{lane}-audit-checkpoint.json"]
    checkpoint_wrapper["event_ids"] = [event["event_id"] for event in rebuilt]
    if checkpoint is not None:
        checkpoint_wrapper["head_hash"] = checkpoint.head_hash
        checkpoint_wrapper["generation"] = checkpoint.generation
        checkpoint_wrapper["namespace"] = checkpoint.namespace
        checkpoint_wrapper["checkpoint"] = checkpoint.to_dict()


def _attacker_rechain_audit_lane(
    values: dict[str, Any],
    lane: str,
    events: list[dict[str, Any]],
    signer: Ed25519Signer,
) -> AuditCheckpoint:
    """Re-chain and re-checkpoint a lane from raw wire events under an attacker key.

    Unlike :func:`_rebuild_audit_lane` this never routes the events through
    :class:`DecisionRecord`, so it can express payloads the typed constructor
    refuses. That is the attacker's real capability: they write JSONL bytes and
    re-sign a checkpoint, they do not call our constructors. The resulting lane
    is internally coherent, which is exactly what verify/replay must still reject.
    """

    previous = GENESIS_HASH
    for event in events:
        event["previous_hash"] = previous
        event.pop("event_hash", None)
        event["event_hash"] = hashlib.sha256(canonical_json(event).encode("utf-8")).hexdigest()
        previous = event["event_hash"]

    namespace = f"mcp-proof:{lane}"

    def signed_checkpoint(
        generation: int, head_hash: str, previous_checkpoint_hash: str
    ) -> AuditCheckpoint:
        unsigned = AuditCheckpoint(
            namespace=namespace,
            generation=generation,
            head_hash=head_hash,
            previous_checkpoint_hash=previous_checkpoint_hash,
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            signature="pending",
        )
        return dataclasses.replace(unsigned, signature=signer.sign(unsigned.signing_payload()))

    checkpoint = signed_checkpoint(0, GENESIS_HASH, GENESIS_CHECKPOINT_HASH)
    for generation, event in enumerate(events, start=1):
        checkpoint = signed_checkpoint(generation, event["event_hash"], checkpoint.checkpoint_hash)

    wrapper_template = values[f"{lane}-audit.jsonl"][0]
    values[f"{lane}-audit.jsonl"] = [
        {
            **{
                key: copy.deepcopy(value)
                for key, value in wrapper_template.items()
                if key not in {"record_id", "event_id", "event"}
            },
            "record_id": f"audit-{event['event_id']}",
            "event_id": event["event_id"],
            "event": event,
        }
        for event in events
    ]
    checkpoint_wrapper = values[f"{lane}-audit-checkpoint.json"]
    checkpoint_wrapper["event_ids"] = [event["event_id"] for event in events]
    checkpoint_wrapper["head_hash"] = checkpoint.head_hash
    checkpoint_wrapper["generation"] = checkpoint.generation
    checkpoint_wrapper["namespace"] = checkpoint.namespace
    checkpoint_wrapper["checkpoint"] = checkpoint.to_dict()
    return checkpoint


def _assert_attacker_lane_is_internally_coherent(
    values: dict[str, Any],
    lane: str,
    checkpoint: AuditCheckpoint,
    signer: Ed25519Signer,
) -> None:
    """Prove the forged lane passes its own chain+checkpoint verification.

    Without this, a fail-closed verify result would not prove the schema
    defence — the rejection could merely be a broken hash chain.
    """

    anchor = _Anchor()
    anchor.current[checkpoint.namespace] = checkpoint
    with tempfile.TemporaryDirectory() as temporary:
        audit_path = Path(temporary) / f"{lane}-audit.jsonl"
        audit_path.write_text(
            "".join(
                canonical_json(wrapper["event"]) + "\n" for wrapper in values[f"{lane}-audit.jsonl"]
            ),
            encoding="utf-8",
        )
        store = ChainHashAuditStore(
            audit_path,
            checkpoint_anchor=anchor,
            checkpoint_namespace=checkpoint.namespace,
            checkpoint_verifier={signer.key_id: signer},
            require_trusted_checkpoint=True,
        )
        assert store.verify_checkpointed_chain()["valid"] is True


def _assert_verify_and_replay_fail(
    pack: Path,
    trust: Path,
    digest: str,
) -> None:
    for verifier in (verify_mcp_proof_pack, replay_mcp_proof_pack):
        with pytest.raises(MCPActionProofError):
            verifier(pack, trust_bundle=trust, expected_pack_digest=digest)


def test_fixed_member_set_and_verifier_returns_only_canonical_digest(tmp_path: Path) -> None:
    pack, trust, digest = _build(tmp_path)
    assert MCP_ACTION_PROOF_CODEC.schema.schema == MCP_ACTION_PROOF_SCHEMA
    assert MCP_ACTION_PROOF_CODEC.schema.payload_files == MCP_ACTION_PROOF_PAYLOAD_FILES
    assert set(path.name for path in pack.iterdir()) == {
        *MCP_ACTION_PROOF_PAYLOAD_FILES,
        "manifest.json",
    }
    result = verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)
    replay = replay_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)
    assert type(result) is str
    assert result == replay == digest
    normal = [
        wrapper["event"]["record_kind"]
        for wrapper in MCP_ACTION_PROOF_CODEC.strict_jsonl(
            (pack / "normal-audit.jsonl").read_bytes(), "normal-audit.jsonl"
        )
    ]
    poison = [
        wrapper["event"]["record_kind"]
        for wrapper in MCP_ACTION_PROOF_CODEC.strict_jsonl(
            (pack / "poison-audit.jsonl").read_bytes(), "poison-audit.jsonl"
        )
    ]
    assert normal == ["policy_decision", "execution_lifecycle", "execution_lifecycle"]
    assert poison == ["policy_decision"]
    trust_value = json.loads(trust.read_text(encoding="utf-8"))
    for lane in ("normal", "poison"):
        lane_trust = trust_value["lanes"][lane]
        assert lane_trust["checkpoint_authority_id"] == f"audit-checkpoint:mcp-proof:{lane}"
        assert lane_trust["lifecycle_authority_id"] == f"mcp-execution-validator:{lane}"
        assert lane_trust["keys"]["lifecycle"]["purpose"] == "lifecycle-attestation"
        assert (
            lane_trust["keys"]["lifecycle"]["key_id"] != lane_trust["keys"]["checkpoint"]["key_id"]
        )
    normal_events = MCP_ACTION_PROOF_CODEC.strict_jsonl(
        (pack / "normal-audit.jsonl").read_bytes(), "normal-audit.jsonl"
    )
    for wrapper in normal_events[1:]:
        attestation = wrapper["event"]["lifecycle_attestation"]
        assert attestation["authority_id"] == "mcp-execution-validator:normal"
        assert (
            attestation["key_id"] == trust_value["lanes"]["normal"]["keys"]["lifecycle"]["key_id"]
        )
        assert attestation["algorithm"] == "ed25519"
    assert "private" not in trust.read_text(encoding="utf-8").lower()


def test_normal_issuance_anchor_and_final_checkpoint_are_independently_bound(
    tmp_path: Path,
) -> None:
    pack, trust, digest = _build(tmp_path)
    audit = [
        json.loads(line)
        for line in (pack / "normal-audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    receipt = json.loads((pack / "receipts.jsonl").read_text(encoding="utf-8").splitlines()[0])[
        "evidence"
    ]
    checkpoint = json.loads((pack / "normal-audit-checkpoint.json").read_text(encoding="utf-8"))

    issuance_hash = audit[0]["event"]["event_hash"]
    final_hash = audit[-1]["event"]["event_hash"]
    assert receipt["audit_event_hash"] == issuance_hash
    assert checkpoint["head_hash"] == final_hash
    assert checkpoint["checkpoint"]["head_hash"] == final_hash
    assert issuance_hash != final_hash
    assert verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest) == digest
    assert replay_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest) == digest


@pytest.mark.parametrize(
    "mutation",
    [
        "delete-claim",
        "insert-claim",
        "reorder-claim-terminal",
        "replace-claim-with-terminal",
    ],
)
def test_recheckpointed_normal_lifecycle_structure_mutations_fail_verify_and_replay(
    tmp_path: Path,
    mutation: str,
) -> None:
    values, trust, signers = _fixture_values()
    events = [copy.deepcopy(wrapper["event"]) for wrapper in values["normal-audit.jsonl"]]
    if mutation == "delete-claim":
        del events[1]
    elif mutation == "insert-claim":
        inserted = copy.deepcopy(events[1])
        inserted["event_id"] = "normal-inserted-claim-event"
        events.insert(2, inserted)
    elif mutation == "reorder-claim-terminal":
        events[1], events[2] = events[2], events[1]
    else:
        replacement = copy.deepcopy(events[2])
        replacement["event_id"] = "normal-replaced-claim-event"
        events[1] = replacement
    _rebuild_audit_lane(values, signers, "normal", events)

    pack = export_mcp_proof_pack(
        tmp_path / "normal-lifecycle-attack", MCPActionProofPayloads.from_values(values)
    )
    trust_path = tmp_path / "normal-lifecycle-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    _assert_verify_and_replay_fail(pack.directory, trust_path, pack.pack_digest)


@pytest.mark.parametrize(
    ("lane", "event_index", "replacement"),
    [
        ("normal", 0, RecordKind.EXECUTION_LIFECYCLE.value),
        ("normal", 1, RecordKind.POLICY_DECISION.value),
        ("poison", 0, RecordKind.EXECUTION_LIFECYCLE.value),
    ],
)
def test_recheckpointed_record_kind_flips_fail_verify_and_replay(
    tmp_path: Path,
    lane: str,
    event_index: int,
    replacement: str,
) -> None:
    values, trust, signers = _fixture_values()
    events = [copy.deepcopy(wrapper["event"]) for wrapper in values[f"{lane}-audit.jsonl"]]
    events[event_index]["record_kind"] = replacement

    # The attacker re-chains and re-checkpoints with the LEGITIMATE checkpoint
    # key, so the trust bundle stays untouched and genuine. Nothing about the
    # audit chain can reject this lane — only the independent lifecycle
    # attestation can, which is exactly the invariant under test.
    checkpoint_signer = signers[lane]["checkpoint"]
    checkpoint = _attacker_rechain_audit_lane(values, lane, events, checkpoint_signer)
    _assert_attacker_lane_is_internally_coherent(values, lane, checkpoint, checkpoint_signer)

    pack = export_mcp_proof_pack(
        tmp_path / f"{lane}-record-kind-attack-{event_index}",
        MCPActionProofPayloads.from_values(values),
    )
    trust_path = tmp_path / f"{lane}-record-kind-trust-{event_index}.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    _assert_verify_and_replay_fail(pack.directory, trust_path, pack.pack_digest)


_LIFECYCLE_STABLE_DIGEST_FIELDS = (
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
)


@pytest.mark.parametrize(
    ("event_index", "location", "field"),
    [
        (1, "evidence", "phase"),
        (1, "evidence", "consumption_state"),
        *((1, "evidence", field) for field in _LIFECYCLE_STABLE_DIGEST_FIELDS),
        (2, "event", "reason"),
        (2, "event", "matched_rules"),
        (2, "evidence", "reason_code"),
        (2, "evidence", "consumption_state"),
        *((2, "evidence", field) for field in _LIFECYCLE_STABLE_DIGEST_FIELDS),
    ],
)
def test_recheckpointed_normal_lifecycle_field_mutations_fail_verify_and_replay(
    tmp_path: Path,
    event_index: int,
    location: str,
    field: str,
) -> None:
    values, trust, signers = _fixture_values()
    events = [copy.deepcopy(wrapper["event"]) for wrapper in values["normal-audit.jsonl"]]
    event = events[event_index]
    target = event if location == "event" else event["execution_evidence"]
    target[field] = ["receipt.execution.failed"] if field == "matched_rules" else "f" * 64
    _rebuild_audit_lane(values, signers, "normal", events)

    pack = export_mcp_proof_pack(
        tmp_path / f"normal-field-attack-{event_index}-{field}",
        MCPActionProofPayloads.from_values(values),
    )
    trust_path = tmp_path / f"normal-field-trust-{event_index}-{field}.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    _assert_verify_and_replay_fail(pack.directory, trust_path, pack.pack_digest)


@pytest.mark.parametrize(
    "mutation",
    [
        "delete-claim-evidence",
        "append-claim",
        "append-terminal",
        "prepend-claim",
        "replace-authorization-with-claim",
    ],
)
def test_recheckpointed_poison_lifecycle_mutations_fail_verify_and_replay(
    tmp_path: Path,
    mutation: str,
) -> None:
    values, trust, signers = _fixture_values()
    poison = copy.deepcopy(values["poison-audit.jsonl"][0]["event"])
    normal = [copy.deepcopy(wrapper["event"]) for wrapper in values["normal-audit.jsonl"]]
    claim = normal[1]
    terminal = normal[2]
    claim["event_id"] = "poison-injected-claim-event"
    terminal["event_id"] = "poison-injected-terminal-event"
    if mutation == "delete-claim-evidence":
        del claim["execution_evidence"]
        events: list[dict[str, Any]] = [poison, claim]
    elif mutation == "append-claim":
        events = [poison, claim]
    elif mutation == "append-terminal":
        events = [poison, terminal]
    elif mutation == "prepend-claim":
        events = [claim, poison]
    else:
        events = [claim]
    if mutation == "delete-claim-evidence":
        with pytest.raises(ValueError, match="execution lifecycle"):
            _rebuild_audit_lane(values, signers, "poison", events)
        return
    _rebuild_audit_lane(values, signers, "poison", events)

    pack = export_mcp_proof_pack(
        tmp_path / f"poison-lifecycle-attack-{mutation}",
        MCPActionProofPayloads.from_values(values),
    )
    trust_path = tmp_path / f"poison-lifecycle-trust-{mutation}.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    _assert_verify_and_replay_fail(pack.directory, trust_path, pack.pack_digest)


def test_expected_digest_and_external_trust_are_mandatory(tmp_path: Path) -> None:
    pack, trust, digest = _build(tmp_path)
    with pytest.raises(MCPActionProofError, match="expected pack digest"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest="0" * 64)
    with pytest.raises((MCPActionProofError, OSError)):
        verify_mcp_proof_pack(
            pack,
            trust_bundle=tmp_path / "missing-trust.json",
            expected_pack_digest=digest,
        )


@pytest.mark.parametrize("lane", ["normal", "poison"])
@pytest.mark.parametrize(
    "field",
    ["tenant_id", "policy_version", "policy_digest", "policy_attestation", "target"],
)
def test_wrong_lane_pin_fails_closed(tmp_path: Path, lane: str, field: str) -> None:
    pack, trust_path, digest = _build(tmp_path)
    trust = json.loads(trust_path.read_text())
    if field == "tenant_id":
        trust["lanes"][lane][field] = "tenant-attacker"
    elif field == "policy_version":
        trust["lanes"][lane][field] = "policy-attacker/v1"
    elif field == "policy_digest":
        trust["lanes"][lane][field] = "0" * 64
    elif field == "policy_attestation":
        trust["lanes"][lane][field]["resolver_id"] = "attacker-resolver"
    else:
        trust["lanes"][lane][field]["launch_digest"] = "0" * 64
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError):
        verify_mcp_proof_pack(pack, trust_bundle=trust_path, expected_pack_digest=digest)


@pytest.mark.parametrize(
    ("purpose", "field", "value"),
    [
        ("receipt", "purpose", "refusal"),
        ("refusal", "algorithm", "none"),
        ("checkpoint", "key_id", ""),
        ("consumption", "public_bytes_hex", "00"),
    ],
)
def test_strict_ed25519_trust_key_pins_fail_closed(
    tmp_path: Path, purpose: str, field: str, value: str
) -> None:
    pack, trust_path, digest = _build(tmp_path)
    trust = json.loads(trust_path.read_text())
    trust["lanes"]["normal"]["keys"][purpose][field] = value
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError):
        verify_mcp_proof_pack(pack, trust_bundle=trust_path, expected_pack_digest=digest)


@pytest.mark.parametrize("attack", ["wrong-public-key", "unknown-authority", "cross-event"])
def test_lifecycle_attestation_substitution_attacks_fail_closed(
    tmp_path: Path, attack: str
) -> None:
    values, trust, signers = _fixture_values()
    events = [copy.deepcopy(wrapper["event"]) for wrapper in values["normal-audit.jsonl"]]
    if attack == "wrong-public-key":
        attacker = Ed25519Signer.generate("wrong-lifecycle-key")
        trust["lanes"]["normal"]["keys"]["lifecycle"]["public_bytes_hex"] = (
            attacker.public_bytes().hex()
        )
    elif attack == "unknown-authority":
        events[1]["lifecycle_attestation"]["authority_id"] = "unknown-lifecycle-authority"
        _rebuild_audit_lane(values, signers, "normal", events)
    else:
        events[2]["lifecycle_attestation"] = copy.deepcopy(events[1]["lifecycle_attestation"])
        _rebuild_audit_lane(values, signers, "normal", events)
    pack = export_mcp_proof_pack(
        tmp_path / f"lifecycle-substitution-{attack}", MCPActionProofPayloads.from_values(values)
    )
    trust_path = tmp_path / f"lifecycle-substitution-{attack}-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    _assert_verify_and_replay_fail(pack.directory, trust_path, pack.pack_digest)


@pytest.mark.parametrize(
    "attack",
    ["duplicate-key", "checkpoint-key", "checkpoint-authority"],
)
def test_lifecycle_trust_registry_separation_attacks_fail_closed(
    tmp_path: Path, attack: str
) -> None:
    values, trust, _signers = _fixture_values()
    if attack == "duplicate-key":
        copied = copy.deepcopy(trust["lanes"]["normal"]["keys"]["lifecycle"])
        trust["lanes"]["poison"]["keys"]["lifecycle"] = copied
    elif attack == "checkpoint-key":
        copied = copy.deepcopy(trust["lanes"]["normal"]["keys"]["checkpoint"])
        copied["purpose"] = "lifecycle-attestation"
        trust["lanes"]["normal"]["keys"]["lifecycle"] = copied
    else:
        trust["lanes"]["normal"]["lifecycle_authority_id"] = trust["lanes"]["normal"][
            "checkpoint_authority_id"
        ]
    pack = export_mcp_proof_pack(
        tmp_path / f"lifecycle-separation-{attack}", MCPActionProofPayloads.from_values(values)
    )
    trust_path = tmp_path / f"lifecycle-separation-{attack}-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    _assert_verify_and_replay_fail(pack.directory, trust_path, pack.pack_digest)


def test_coordinated_policy_lifecycle_rewrite_and_reseal_fails_closed(tmp_path: Path) -> None:
    values, trust, signers = _fixture_values()
    attacker = Ed25519Signer.generate("attacker-lifecycle-key")
    attacker_authority = "attacker-lifecycle-authority"
    events = [copy.deepcopy(wrapper["event"]) for wrapper in values["normal-audit.jsonl"]]
    for event in events[1:]:
        event["policy_version"] = "attacker-policy/v1"
        record = _record_from_audit_event(event)
        event["lifecycle_attestation"] = LifecycleAttestation.issue(
            record.lifecycle_signing_payload(),
            signer=attacker,
            authority_id=attacker_authority,
        ).to_dict()
    trust["lanes"]["normal"]["lifecycle_authority_id"] = attacker_authority
    trust["lanes"]["normal"]["keys"]["lifecycle"] = _key("lifecycle", attacker)
    _rebuild_audit_lane(values, signers, "normal", events)
    pack = export_mcp_proof_pack(
        tmp_path / "coordinated-policy-lifecycle-rewrite",
        MCPActionProofPayloads.from_values(values),
    )
    trust_path = tmp_path / "coordinated-policy-lifecycle-rewrite-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    _assert_verify_and_replay_fail(pack.directory, trust_path, pack.pack_digest)


@pytest.mark.parametrize("mutation", ["extra", "missing", "symlink"])
def test_extra_missing_and_symlink_members_fail_closed(tmp_path: Path, mutation: str) -> None:
    original, trust, digest = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "mutated")
    if mutation == "extra":
        (pack / "extra.json").write_text("{}\n")
    elif mutation == "missing":
        (pack / "scenario.json").unlink()
    else:
        target = pack / "scenario-target.json"
        os.replace(pack / "scenario.json", target)
        (pack / "scenario.json").symlink_to(target.name)
    with pytest.raises(MCPActionProofError):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


def test_noncanonical_duplicate_jsonl_and_manifest_tamper_fail_closed(tmp_path: Path) -> None:
    original, trust, digest = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "noncanonical")
    scenario = json.loads((pack / "scenario.json").read_text())
    (pack / "scenario.json").write_text(json.dumps(scenario, indent=2) + "\n")
    resealed = _reseal(pack)
    with pytest.raises(MCPActionProofError, match="canonical"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=resealed)

    pack = _copy_pack(original, tmp_path / "duplicate")
    row = json.loads((pack / "receipts.jsonl").read_text().splitlines()[0])
    (pack / "receipts.jsonl").write_bytes(MCP_ACTION_PROOF_CODEC.jsonl_bytes([row, row]))
    resealed = _reseal(pack)
    with pytest.raises(MCPActionProofError, match="duplicate"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=resealed)

    pack = _copy_pack(original, tmp_path / "manifest")
    manifest = (pack / "manifest.json").read_text()
    (pack / "manifest.json").write_text(
        manifest.replace('{"files":', '{"schema":"duplicate","files":', 1)
    )
    with pytest.raises(MCPActionProofError):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("token", "redacted"),
        ("credential", "redacted"),
        ("private_key", "redacted"),
        ("hmac_key", "redacted"),
        ("nonce", "redacted"),
        ("idempotency", "redacted"),
        ("_meta", {"progressToken": "redacted"}),
    ],
)
def test_recursive_secret_and_raw_meta_rejection(tmp_path: Path, field: str, value: Any) -> None:
    values, _trust = _values()
    values["normal-fixture-state.json"] = {"safe": {"nested": {field: value}}}
    with pytest.raises(MCPActionProofError, match="forbidden field"):
        MCPActionProofPayloads.from_values(values)


@pytest.mark.parametrize("path", ["/home/alice/state", "C:\\Users\\alice\\state", "file:///tmp/x"])
def test_path_neutral_payload_rejection(path: str) -> None:
    values, _trust = _values()
    values["normal-fixture-state.json"] = {"artifact": path}
    with pytest.raises(MCPActionProofError, match="absolute path"):
        MCPActionProofPayloads.from_values(values)


def test_unknown_policy_artifact_fails_closed(tmp_path: Path) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "policy-tamper")
    policy = json.loads((pack / "policy.json").read_text())
    policy["lanes"]["normal"]["artifact"]["decision"] = "deny"
    digest = _rewrite_json(pack, "policy.json", policy)
    with pytest.raises(MCPActionProofError, match="unknown policy artifact"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


def test_size_limit_and_atomic_no_replace(tmp_path: Path) -> None:
    values, _trust = _values()
    values["normal-fixture-state.json"] = {"blob": "x" * (2 * 1024 * 1024)}
    with pytest.raises(MCPActionProofError, match="size limits"):
        export_mcp_proof_pack(tmp_path / "oversize", MCPActionProofPayloads.from_values(values))
    assert not (tmp_path / "oversize").exists()

    values, _trust = _values()
    payloads = MCPActionProofPayloads.from_values(values)
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_text("preserve")
    with pytest.raises(SealedPackExportError) as captured:
        export_mcp_proof_pack(output, payloads)
    assert captured.value.committed is False
    assert sentinel.read_text() == "preserve"


def test_shared_export_api_commits_through_exact_pinned_parent_capability(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "pinned-parent"
    parent.mkdir()
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    info = os.fstat(descriptor)
    identity = (info.st_dev, info.st_ino)
    opened_paths: list[Path] = []

    def open_pinned(path: Path) -> tuple[int, tuple[int, int]]:
        opened_paths.append(path)
        assert Path(os.path.abspath(path)) == parent
        return os.dup(descriptor), identity

    try:
        values, _trust = _values()
        pack = export_mcp_proof_pack(
            parent / "pack",
            MCPActionProofPayloads.from_values(values),
            open_directory=open_pinned,
            expected_output_parent=parent,
            expected_parent_identity=identity,
        )
    finally:
        os.close(descriptor)

    assert pack.directory == parent / "pack"
    assert (pack.directory / "manifest.json").is_file()
    assert opened_paths
    assert set(opened_paths) == {parent}


def test_shared_export_api_rejects_incomplete_or_mismatched_parent_capability(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "expected-parent"
    other = tmp_path / "other-parent"
    parent.mkdir()
    other.mkdir()
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    info = os.fstat(descriptor)
    identity = (info.st_dev, info.st_ino)

    def open_pinned(_path: Path) -> tuple[int, tuple[int, int]]:
        return os.dup(descriptor), identity

    values, _trust = _values()
    payloads = MCPActionProofPayloads.from_values(values)
    try:
        with pytest.raises(TypeError, match="must be provided together"):
            export_mcp_proof_pack(
                parent / "incomplete",
                payloads,
                open_directory=open_pinned,
            )
        with pytest.raises(MCPActionProofError, match="exact output parent"):
            export_mcp_proof_pack(
                other / "mismatch",
                payloads,
                open_directory=open_pinned,
                expected_output_parent=parent,
                expected_parent_identity=identity,
            )
    finally:
        os.close(descriptor)

    assert list(parent.iterdir()) == []
    assert list(other.iterdir()) == []


def test_shared_export_api_rejects_capability_redirect_identity(
    tmp_path: Path,
) -> None:
    expected = tmp_path / "expected-parent"
    redirected = tmp_path / "redirected-parent"
    expected.mkdir()
    redirected.mkdir()
    expected_info = expected.stat()
    expected_identity = (expected_info.st_dev, expected_info.st_ino)

    def redirect(_path: Path) -> tuple[int, tuple[int, int]]:
        descriptor = os.open(redirected, os.O_RDONLY | os.O_DIRECTORY)
        info = os.fstat(descriptor)
        return descriptor, (info.st_dev, info.st_ino)

    values, _trust = _values()
    with pytest.raises(SealedPackExportError, match="wrong directory identity") as captured:
        export_mcp_proof_pack(
            expected / "pack",
            MCPActionProofPayloads.from_values(values),
            open_directory=redirect,
            expected_output_parent=expected,
            expected_parent_identity=expected_identity,
        )
    assert captured.value.committed is False
    assert list(expected.iterdir()) == []
    assert list(redirected.iterdir()) == []


def test_unknown_protocol_outcome_is_semantically_incomplete(tmp_path: Path) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "unknown")
    rows = [json.loads(line) for line in (pack / "protocol-results.jsonl").read_text().splitlines()]
    rows[0]["status"] = "outcome_unknown"
    rows[0]["outcome_unknown"] = True
    digest = _rewrite_payload(pack, "protocol-results.jsonl", rows)
    with pytest.raises(MCPActionProofError, match="protocol decision/status"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize("name", MCP_ACTION_PROOF_PAYLOAD_FILES)
def test_every_payload_has_an_exact_verifier_boundary_schema(tmp_path: Path, name: str) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "extra-field")
    if name.endswith(".jsonl"):
        value = [json.loads(line) for line in (pack / name).read_text().splitlines()]
        value[0]["unexpected"] = True
    else:
        value = json.loads((pack / name).read_text())
        value["unexpected"] = True
    digest = _rewrite_payload(pack, name, value)
    with pytest.raises(MCPActionProofError, match="incompatible shape"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize(
    ("name", "path", "replacement"),
    [
        ("policy.json", ("lanes", "normal", "target", "launch_digest"), "0" * 64),
        ("protocol-results.jsonl", (1, "retryable"), True),
        ("protocol-results.jsonl", (1, "downstream_call_count"), 1),
        ("protocol-results.jsonl", (1, "side_effect_write_count"), 1),
        ("receipts.jsonl", (0, "decision_id"), "wrong-decision"),
        ("normal-audit.jsonl", (0, "event", "actor"), "wrong-actor"),
        ("normal-replay.jsonl", (0, "side_record", "actor"), "wrong-actor"),
        ("normal-audit-checkpoint.json", ("event_ids",), []),
        ("normal-consumption-snapshot.json", ("outcome_record_ids",), []),
        ("normal-fixture-state.json", ("calls",), 0),
    ],
)
def test_resealed_cross_link_and_unknown_mutations_fail_closed(
    tmp_path: Path, name: str, path: tuple[Any, ...], replacement: Any
) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "cross-link")
    if name.endswith(".jsonl"):
        value: Any = [json.loads(line) for line in (pack / name).read_text().splitlines()]
    else:
        value = json.loads((pack / name).read_text())
    cursor = value
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    digest = _rewrite_payload(pack, name, value)
    with pytest.raises(MCPActionProofError):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize(
    ("name", "path", "replacement"),
    [
        ("receipts.jsonl", (0, "evidence", "signature"), "0" * 128),
        ("refusals.jsonl", (0, "evidence", "signature"), "0" * 128),
        ("normal-audit-checkpoint.json", ("checkpoint", "signature"), "0" * 128),
        ("normal-consumption-snapshot.json", ("snapshot", "signature"), "0" * 128),
        ("normal-consumption-snapshot.json", ("outer_signature",), "0" * 128),
        ("normal-replay.jsonl", (0, "side_record", "args", "record"), "tampered"),
        ("normal-consumption-snapshot.json", ("records", 0, "state"), "UNKNOWN"),
        ("poison-fixture-state.json", ("ledger_after_digest",), "0" * 64),
    ],
)
def test_resealed_crypto_replay_consumption_and_fixture_mutations_fail_closed(
    tmp_path: Path,
    name: str,
    path: tuple[Any, ...],
    replacement: Any,
) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "semantic-tamper")
    value: Any
    if name.endswith(".jsonl"):
        value = [json.loads(line) for line in (pack / name).read_text().splitlines()]
    else:
        value = json.loads((pack / name).read_text())
    cursor = value
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    digest = _rewrite_payload(pack, name, value)
    with pytest.raises(MCPActionProofError):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("decision", "deny"),
        ("decision", "transform"),
        ("previous_audit_hash", "f" * 64),
        ("timestamp", "2026-01-01T00:00:02+00:00"),
        ("declared_goal", "attacker goal"),
        ("matched_rules", ["ATTACKER_ALLOW"]),
        ("argument_hash", _digest("attacker arguments")),
        ("expires_at", "2025-12-31T23:59:59+00:00"),
    ],
)
def test_trusted_key_resigned_receipt_semantic_mutations_fail_cross_links(
    tmp_path: Path,
    field: str,
    replacement: Any,
) -> None:
    values, trust, signers = _fixture_values()
    receipt_row = values["receipts.jsonl"][0]
    wire = receipt_row["evidence"]
    wire[field] = replacement
    receipt = DecisionReceipt.from_dict(wire)
    wire["receipt_hash"] = receipt.compute_hash()
    wire["signature"] = signers["normal"]["receipt"].sign(wire["receipt_hash"].encode())
    pack = export_mcp_proof_pack(
        tmp_path / "resigned-pack", MCPActionProofPayloads.from_values(values)
    )
    trust_path = tmp_path / "resigned-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError, match="receipt semantic cross-link mismatch"):
        verify_mcp_proof_pack(
            pack.directory,
            trust_bundle=trust_path,
            expected_pack_digest=pack.pack_digest,
        )


@pytest.mark.parametrize(("lane", "generation"), [("normal", 4), ("poison", 1)])
def test_trusted_consumption_signer_cannot_expand_dedicated_store_generation(
    tmp_path: Path,
    lane: str,
    generation: int,
) -> None:
    values, trust, signers = _fixture_values()
    wrapper = values[f"{lane}-consumption-snapshot.json"]
    signer = signers[lane]["consumption"]
    wrapper["generation"] = generation
    snapshot_wire = wrapper["snapshot"]
    snapshot_wire["generation"] = generation
    snapshot_wire["signature"] = "0" * 128
    snapshot = MCPSignedConsumptionSnapshot(**snapshot_wire)
    snapshot_wire["signature"] = signer.sign(snapshot.signing_payload())
    assert signer.verify(snapshot.signing_payload(), snapshot_wire["signature"])

    unsigned_wrapper = copy.deepcopy(wrapper)
    unsigned_wrapper.pop("outer_signature")
    outer_payload = _CONSUMPTION_WRAPPER_DOMAIN + canonical_json(unsigned_wrapper).encode()
    wrapper["outer_signature"] = signer.sign(outer_payload)
    assert signer.verify(outer_payload, wrapper["outer_signature"])

    pack = export_mcp_proof_pack(
        tmp_path / f"{lane}-generation-pack", MCPActionProofPayloads.from_values(values)
    )
    trust_path = tmp_path / f"{lane}-generation-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError, match="consumption anchor/wrapper binding mismatch"):
        verify_mcp_proof_pack(
            pack.directory,
            trust_bundle=trust_path,
            expected_pack_digest=pack.pack_digest,
        )


def test_valid_but_wrong_evidence_trust_key_cross_link_fails_closed(tmp_path: Path) -> None:
    original, trust_path, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "wrong-evidence-key")
    trust = json.loads(trust_path.read_text())
    receipts = [json.loads(line) for line in (pack / "receipts.jsonl").read_text().splitlines()]
    receipts[0]["key_id"] = trust["lanes"]["normal"]["keys"]["refusal"]["key_id"]
    digest = _rewrite_payload(pack, "receipts.jsonl", receipts)
    with pytest.raises(MCPActionProofError, match="protocol/trust binding mismatch"):
        verify_mcp_proof_pack(pack, trust_bundle=trust_path, expected_pack_digest=digest)


@pytest.mark.parametrize(
    ("reason_code", "reason_codes"),
    [
        (AuthorizationReasonCode.DENIED, ("authorization.denied",)),
        (
            AuthorizationReasonCode.INTERNAL_FAILURE,
            ("mcp.gateway.catalog_unavailable",),
        ),
        (
            AuthorizationReasonCode.INTERNAL_FAILURE,
            ("mcp.gateway.catalog_mismatch", "mcp.gateway.catalog_unavailable"),
        ),
        (
            AuthorizationReasonCode.INTERNAL_FAILURE,
            ("mcp.gateway.catalog_unavailable", "mcp.gateway.catalog_mismatch"),
        ),
    ],
)
def test_resigned_reaudited_poison_semantic_substitutions_fail_closed(
    tmp_path: Path,
    reason_code: AuthorizationReasonCode,
    reason_codes: tuple[str, ...],
) -> None:
    values, trust, signers = _fixture_values()
    _replace_poison_refusal_semantics(
        values,
        signers,
        reason_code=reason_code,
        reason_codes=reason_codes,
    )
    pack = export_mcp_proof_pack(
        tmp_path / "poison-semantic-pack", MCPActionProofPayloads.from_values(values)
    )
    trust_path = tmp_path / "poison-semantic-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError, match="refusal semantic/integrity"):
        verify_mcp_proof_pack(
            pack.directory,
            trust_bundle=trust_path,
            expected_pack_digest=pack.pack_digest,
        )


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"record": 7},
        {"record": "x" * 257},
        {"record": "valid", "extra": "not-allowed"},
    ],
    ids=["missing-record", "non-string-record", "oversize-record", "extra-property"],
)
def test_fully_rebuilt_invalid_fixture_write_once_inputs_fail_schema(
    tmp_path: Path, args: dict[str, Any]
) -> None:
    values, trust, signers = _fixture_values()
    _replace_normal_input_semantics(values, signers, args)
    pack = export_mcp_proof_pack(
        tmp_path / "invalid-input-pack", MCPActionProofPayloads.from_values(values)
    )
    trust_path = tmp_path / "invalid-input-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError, match="fixture.write_once input schema"):
        verify_mcp_proof_pack(
            pack.directory,
            trust_bundle=trust_path,
            expected_pack_digest=pack.pack_digest,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Access Token", "redacted"),
        ("secret-material", "redacted"),
        ("credential-material", "redacted"),
        ("private key", "redacted"),
        ("HMAC key", "redacted"),
        ("raw nonce", "redacted"),
        ("idempotency-value", "redacted"),
        ("_meta", {"progress": "redacted"}),
        ("note", "contains a private-key value"),
        ("note", "contains credential material"),
        ("note", "Bearer abc123"),
        ("note", "_meta"),
    ],
)
def test_resealed_nested_jsonl_secret_classes_fail_at_verifier(
    tmp_path: Path, field: str, value: Any
) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "secret")
    records = [json.loads(line) for line in (pack / "normal-audit.jsonl").read_text().splitlines()]
    records[0]["nested"] = {field: value}
    digest = _rewrite_payload(pack, "normal-audit.jsonl", records)
    with pytest.raises(MCPActionProofError, match="forbidden"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize(
    "path_value",
    [
        "/home/alice/state",
        "C:\\Users\\alice\\state",
        "file:///tmp/state",
        "file:/tmp/state",
        "file:C:\\state",
        "FiLe : // /tmp/state",
        "~alice/state",
        "\\\\server\\share\\state",
        "\\\\?\\C:\\state",
        "\\\\.\\PhysicalDrive0",
    ],
)
def test_resealed_nested_jsonl_paths_fail_at_verifier(tmp_path: Path, path_value: str) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "path")
    records = [json.loads(line) for line in (pack / "normal-audit.jsonl").read_text().splitlines()]
    records[0]["nested"] = {"location": path_value}
    digest = _rewrite_payload(pack, "normal-audit.jsonl", records)
    with pytest.raises(MCPActionProofError, match="absolute path"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


def test_resealed_duplicate_replay_event_with_distinct_record_id_fails_closed(
    tmp_path: Path,
) -> None:
    original, trust, _digest_value = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "duplicate-replay-event")
    records = [json.loads(line) for line in (pack / "normal-replay.jsonl").read_text().splitlines()]
    duplicate = copy.deepcopy(records[0])
    duplicate["record_id"] = "replay-distinct-record"
    records.append(duplicate)
    digest = _rewrite_payload(pack, "normal-replay.jsonl", records)
    with pytest.raises(MCPActionProofError, match="exactly one raw row"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


def test_verifier_rejects_hardlinked_member_and_oversize_member(tmp_path: Path) -> None:
    original, trust, digest = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / "hardlink")
    (pack / "scenario.json").unlink()
    os.link(original / "scenario.json", pack / "scenario.json")
    with pytest.raises(MCPActionProofError):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)

    pack = _copy_pack(original, tmp_path / "oversize-verifier")
    (pack / "normal-fixture-state.json").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(MCPActionProofError, match="size"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_external_trust_bundle_links_fail_closed(tmp_path: Path, link_kind: str) -> None:
    pack, trust, digest = _build(tmp_path)
    linked = tmp_path / f"trust-{link_kind}.json"
    if link_kind == "symlink":
        linked.symlink_to(trust.name)
    else:
        os.link(trust, linked)
    with pytest.raises((MCPActionProofError, OSError)):
        verify_mcp_proof_pack(pack, trust_bundle=linked, expected_pack_digest=digest)


def test_no_success_bearing_result_class_token_factory_or_closure_exists() -> None:
    assert not hasattr(mcp_proof_module, "MCPActionProofVerification")
    assert not hasattr(mcp_proof_module, "_VERIFIED_RESULT_TOKEN")
    assert not hasattr(mcp_proof_module, "_VerifiedMCPActionProofVerification")
    assert all(
        not name.lower().endswith(("verification_factory", "verified_result"))
        for name in vars(mcp_proof_module)
    )


def test_verifier_api_accepts_no_report_or_preverified_result(tmp_path: Path) -> None:
    pack, trust, digest = _build(tmp_path)
    assert set(inspect.signature(verify_mcp_proof_pack).parameters) == {
        "directory",
        "trust_bundle",
        "expected_pack_digest",
    }
    assert set(inspect.signature(replay_mcp_proof_pack).parameters) == {
        "directory",
        "trust_bundle",
        "expected_pack_digest",
    }
    with pytest.raises(TypeError):
        verify_mcp_proof_pack(
            pack,
            trust_bundle=trust,
            expected_pack_digest=digest,
            verification_report={"valid": True, "pack_digest": digest},
        )
    with pytest.raises(MCPActionProofError, match="external expected pack digest"):
        verify_mcp_proof_pack(
            pack,
            trust_bundle=trust,
            expected_pack_digest="0" * 64,
        )


@pytest.mark.parametrize(
    ("name", "schema"),
    [
        ("scenario.json", "gove-zone.mcp-action-proof-scenario/v1"),
        ("runtime-bindings.json", "gove-zone.mcp-action-runtime-bindings/v1"),
        ("policy.json", "gove-zone.mcp-action-policy-evidence/v1"),
        ("normal-audit-checkpoint.json", "gove-zone.mcp-action-audit-checkpoint/v1"),
        (
            "normal-consumption-snapshot.json",
            "gove-zone.mcp-action-consumption-snapshot/v1",
        ),
        ("normal-fixture-state.json", "gove-zone.mcp-action-fixture-state/v1"),
    ],
)
def test_v1_member_schemas_are_rejected(tmp_path: Path, name: str, schema: str) -> None:
    original, trust, _ = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / f"v1-{name}")
    value = json.loads((pack / name).read_text(encoding="utf-8"))
    value["schema"] = schema
    digest = _rewrite_payload(pack, name, value)
    with pytest.raises(
        MCPActionProofError,
        match="schema|trust pin|semantic mismatch|binding mismatch|coverage mismatch",
    ):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


def test_v1_pack_and_trust_schemas_are_rejected(tmp_path: Path) -> None:
    original, trust_path, digest = _build(tmp_path)
    manifest = json.loads((original / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema"] = "gove-zone.mcp-action-proof-pack/v1"
    (original / "manifest.json").write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(manifest))
    with pytest.raises(MCPActionProofError, match="schema|manifest|digest"):
        verify_mcp_proof_pack(original, trust_bundle=trust_path, expected_pack_digest=digest)

    second_root = tmp_path / "trust-v1"
    second_root.mkdir()
    original, trust_path, digest = _build(second_root)
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["schema"] = "gove-zone.mcp-action-trust-bundle/v1"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError, match="trust bundle schema"):
        verify_mcp_proof_pack(original, trust_bundle=trust_path, expected_pack_digest=digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-attacker"),
        ("artifact_id", "attacker-policy"),
        ("policy_version", "attacker-policy/v1"),
        ("digest", "0" * 64),
        ("resolver_id", "attacker-resolver"),
    ],
)
def test_every_policy_attestation_field_is_exactly_bound(
    tmp_path: Path, field: str, value: str
) -> None:
    original, trust, _ = _build(tmp_path)
    pack = _copy_pack(original, tmp_path / f"attestation-{field}")
    policy = json.loads((pack / "policy.json").read_text(encoding="utf-8"))
    policy["lanes"]["normal"]["policy_attestation"][field] = value
    digest = _rewrite_payload(pack, "policy.json", policy)
    with pytest.raises(MCPActionProofError, match="trust pin|attestation"):
        verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)


@pytest.mark.parametrize("kind", ["exchange", "consumption"])
def test_v1_signature_domains_are_rejected(tmp_path: Path, kind: str) -> None:
    values, trust, signers = _fixture_values()
    if kind == "exchange":
        normal = values["protocol-results.jsonl"][0]
        unsigned = dict(normal)
        unsigned.pop("signature")
        normal["signature"] = signers["normal"]["exchange"].sign(
            b"gove-zone:mcp-gateway-exchange:v1\x00" + canonical_json(unsigned).encode()
        )
    else:
        wrapper = values["normal-consumption-snapshot.json"]
        unsigned = dict(wrapper)
        unsigned.pop("outer_signature")
        wrapper["outer_signature"] = signers["normal"]["consumption"].sign(
            b"gove-zone:mcp-action-consumption-wrapper:v1\x00" + canonical_json(unsigned).encode()
        )
    pack = export_mcp_proof_pack(tmp_path / "v1-domain", MCPActionProofPayloads.from_values(values))
    trust_path = tmp_path / "v1-domain-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))
    with pytest.raises(MCPActionProofError, match="identity/signature|consumption .*signature"):
        verify_mcp_proof_pack(
            pack.directory,
            trust_bundle=trust_path,
            expected_pack_digest=pack.pack_digest,
        )


@pytest.mark.parametrize("legacy_schema", [False, True])
def test_nested_v1_consumption_snapshot_is_rejected(
    tmp_path: Path,
    legacy_schema: bool,
) -> None:
    values, trust, signers = _fixture_values()
    wrapper = values["normal-consumption-snapshot.json"]
    unsigned_snapshot = dict(wrapper["snapshot"])
    unsigned_snapshot.pop("signature")
    if legacy_schema:
        unsigned_snapshot["schema"] = "gove-zone.mcp-consumption-snapshot/v1"
    wrapper["snapshot"] = {
        **unsigned_snapshot,
        "signature": signers["normal"]["consumption"].sign(
            b"gove-zone:mcp-consumption-snapshot:v1\x00"
            + canonical_json(unsigned_snapshot).encode()
        ),
    }
    unsigned_wrapper = dict(wrapper)
    unsigned_wrapper.pop("outer_signature")
    wrapper["outer_signature"] = signers["normal"]["consumption"].sign(
        _CONSUMPTION_WRAPPER_DOMAIN + canonical_json(unsigned_wrapper).encode()
    )
    pack = export_mcp_proof_pack(
        tmp_path / "nested-v1-domain",
        MCPActionProofPayloads.from_values(values),
    )
    trust_path = tmp_path / "nested-v1-domain-trust.json"
    trust_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(trust))

    with pytest.raises(MCPActionProofError, match="snapshot schema|consumption snapshot"):
        verify_mcp_proof_pack(
            pack.directory,
            trust_bundle=trust_path,
            expected_pack_digest=pack.pack_digest,
        )


def test_offline_replay_uses_canonical_runtime_policy_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack, trust, digest = _build(tmp_path)
    calls = 0
    canonical_factory = mcp_reference_module.create_reference_policy

    def tracked_factory() -> mcp_reference_module.MCPReferencePolicy:
        nonlocal calls
        calls += 1
        return canonical_factory()

    monkeypatch.setattr(mcp_proof_module, "create_reference_policy", tracked_factory)
    result = verify_mcp_proof_pack(pack, trust_bundle=trust, expected_pack_digest=digest)
    assert result == digest
    assert calls == 1
    assert type(canonical_factory()) is mcp_reference_module.MCPReferencePolicy
