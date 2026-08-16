"""Unit tests for P1 MCP protocol and fixed-stdio runtime boundaries."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pickle
import shlex
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from mcp import StdioServerParameters

import gove_zone.mcp_proof as mcp_proof_module
import gove_zone.mcp_reference as mcp_reference_module
import gove_zone.mcp_stdio_transport as stdio_transport_module
from gove_zone import mcp_fixture_server
from gove_zone.authorization import (
    ExecutionReasonCode,
    ExecutionRefusalEvidence,
    ExecutionRefusalPhase,
)
from gove_zone.consumption import (
    AnchoredConsumptionState,
    ConsumptionStoreError,
)
from gove_zone.decision import Decision, DecisionRecord, canonical_json
from gove_zone.mcp_gateway import (
    MCPGatewayResponse,
    MCPGatewayStatus,
    MCPPendingApproval,
)
from gove_zone.mcp_reference import MCPPublicVerificationKey, create_reference_runtime
from gove_zone.mcp_runtime import (
    _call_params,
    _governance_meta,
    _handler_request_id,
    _request_id,
    build_mcp_server,
    read_secret_file,
)
from gove_zone.mcp_security import MCPStdioError, MCPStdioReasonCode, MCPStdioTargetValidator
from gove_zone.mcp_stdio_transport import MCPFixedStdioTransport
from gove_zone.policy import new_event_id
from gove_zone.receipt import safe_result_hash
from gove_zone.side_effect_kernel import ReceiptGatedSideEffectExecutor
from gove_zone.signing import Ed25519Signer

_ACTION_CONSUMPTION_DOMAIN = b"gove-zone:mcp-action-consumption-wrapper:v2\x00"


def _normal_consumption_record(
    response: MCPGatewayResponse,
    *,
    outcome_record_id: str = "protocol-normal",
) -> dict[str, str]:
    receipt = response.receipt
    assert receipt is not None
    return {
        "event_id": response.audit_event_id,
        "outcome_record_id": outcome_record_id,
        "receipt_id": receipt.receipt_id,
        "receipt_hash": receipt.receipt_hash,
        "state": "SUCCEEDED",
        "result_digest": safe_result_hash(response.payload),
        "audit_event_hash": receipt.audit_event_hash,
        "tenant_id": receipt.tenant_id,
        "actor": receipt.actor,
        "governed_operation": receipt.proposed_action,
        "authority": receipt.authority,
        "downstream_tool": "fixture.write_once",
        "arguments_hash": receipt.argument_hash,
    }


def _dispatch_reference_write(
    runtime: Any,
    *,
    request_id: str,
    record: str,
    nonce: str,
    idempotency_key: str,
) -> MCPGatewayResponse:
    metadata = _authorization()
    authorization = metadata["io.acgs/authorization"]
    assert isinstance(authorization, dict)
    authorization["nonce"] = nonce
    authorization["idempotencyKey"] = idempotency_key
    response = runtime.gateway.dispatch(
        "tools/call",
        inbound_token="fixture-token",
        session_id="session-1",
        request_id=request_id,
        params=_call_params("fixture.write_once", {"record": record}, metadata),
    )
    assert isinstance(response, MCPGatewayResponse)
    return response


def _authorization() -> dict[str, object]:
    return {
        "io.acgs/authorization": {
            "nonce": "nonce-1",
            "idempotencyKey": "idem-m1",
            "requestedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "evidence": [],
            "goal": "execute a fixture call",
        }
    }


def _fixture_environment(tmp_path: Path) -> dict[str, str]:
    return {
        "ACGS_FIXTURE_LEDGER": str(tmp_path / "ledger.jsonl"),
        "ACGS_FIXTURE_PID_FILE": str(tmp_path / "fixture.pid"),
        "ACGS_FIXTURE_CATALOG_MODE": "normal",
        "ACGS_FIXTURE_AMBIGUOUS_DELAY_MS": "0",
        "PYTHONPATH": str(Path(__import__("mcp").__file__).resolve().parent.parent),
    }


def _fixture_artifact(tmp_path: Path) -> Path:
    artifact = tmp_path / "private-fixture.py"
    artifact.write_bytes(Path(mcp_fixture_server.__file__).read_bytes())
    artifact.chmod(0o500)
    return artifact


def _python_wrapper(path: Path, *, marker: Path | None = None) -> Path:
    lines = ["#!/bin/sh"]
    if marker is not None:
        lines.append(f"printf launched > {shlex.quote(str(marker))}")
    lines.append(f'exec {shlex.quote(str(Path(sys.executable).resolve(strict=True)))} "$@"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


async def _assert_process_reaped(pid_path: Path) -> None:
    if not pid_path.exists():
        return
    pid = int(pid_path.read_text(encoding="utf-8").strip())
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        await anyio.sleep(0.01)
    pytest.fail(f"fixture process {pid} was not reaped")


def test_authorization_metadata_is_exact_and_observed_time_is_server_owned() -> None:
    params = _call_params("fixture.write_once", {"record": "one"}, _authorization())

    assert params["nonce"] == "nonce-1"
    assert params["idempotency_key"] == "idem-m1"
    assert params["observed_at"] != params["requested_at"]

    unknown = _authorization()
    authorization = unknown["io.acgs/authorization"]
    assert isinstance(authorization, dict)
    authorization["tenantId"] = "attacker"
    assert _call_params("fixture.write_once", {"record": "one"}, unknown) == {
        "name": "fixture.write_once",
        "arguments": {"record": "one"},
        "malformed_authorization": True,
    }


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _execution_refusal_evidence(**overrides: Any) -> ExecutionRefusalEvidence:
    fields: dict[str, Any] = {
        "request_id_digest": _digest("request"),
        "receipt_id_digest": _digest("receipt-id"),
        "receipt_hash": _digest("receipt"),
        "tenant_digest": _digest("tenant"),
        "execution_boundary_digest": _digest("boundary"),
        "adapter_id_digest": _digest("adapter"),
        "authorization_audit_digest": _digest("authorization-audit"),
        "binding_hash": _digest("binding"),
        "argument_hash": _digest("arguments"),
        "reason_code": ExecutionReasonCode.REPLAY,
        "phase": ExecutionRefusalPhase.POST_RESERVATION,
        "attempt_id_digest": _digest("attempt"),
        "audited": True,
        "audit_event_id": "evt-execution-refusal",
        "audit_event_hash": _digest("refusal-event"),
        "audit_checkpoint_hash": _digest("refusal-checkpoint"),
        "audit_checkpoint_parent_hash": _digest("refusal-checkpoint-parent"),
    }
    fields.update(overrides)
    return ExecutionRefusalEvidence(**fields)


def _failed_closed_response(**overrides: Any) -> MCPGatewayResponse:
    fields: dict[str, Any] = {
        "request_id": "req-1",
        "decision": Decision.ALLOW,
        "status": MCPGatewayStatus.FAILED_CLOSED,
        "reason_codes": (ExecutionReasonCode.REPLAY.value,),
        "retryable": False,
        "executed": False,
        "audit_event_id": "evt-authorization",
    }
    fields.update(overrides)
    return MCPGatewayResponse(**fields)


def test_governance_meta_exposes_exact_execution_refusal_evidence() -> None:
    """The executor's own proof must reach the consumer whole and unconflated.

    A consumer can only verify a refusal against the exact attempt if it
    receives the full evidence — not a summary — and can tell the execution
    refusal's audit record apart from the authorization's.
    """

    evidence = _execution_refusal_evidence()
    meta = _governance_meta(_failed_closed_response(execution_refusal_evidence=evidence))

    # Exact and complete: the full evidence, not a lossy projection of it.
    assert meta["executionRefusalEvidence"] == evidence.to_dict()
    assert meta["executionRefusalAuditEventId"] == "evt-execution-refusal"
    assert meta["executionRefusalAudited"] is True
    assert meta["executionRefusalSigned"] is False
    # The two audit ids belong to different records and are never conflated.
    assert meta["auditEventId"] == "evt-authorization"
    assert meta["executionRefusalAuditEventId"] != meta["auditEventId"]
    # The wire form is JSON-safe and survives a round trip byte for byte.
    assert json.loads(json.dumps(meta)) == meta
    # The refusal still proves the adapter never ran.
    assert meta["executionRefusalEvidence"]["adapter_invoked"] is False
    assert meta["executed"] is False


def test_governance_meta_reports_execution_refusal_proof_status_as_represented() -> None:
    """``audited``/``signed`` report what survived; neither is ever asserted."""

    unproven = _execution_refusal_evidence(
        audited=False,
        audit_event_id="",
        audit_event_hash="",
        audit_checkpoint_hash="",
        audit_checkpoint_parent_hash="",
    )
    meta = _governance_meta(_failed_closed_response(execution_refusal_evidence=unproven))

    assert meta["executionRefusalAudited"] is False
    assert meta["executionRefusalSigned"] is False
    # Explicitly unavailable rather than an invented audit identifier.
    assert meta["executionRefusalAuditEventId"] is None
    assert meta["executionRefusalEvidence"] == unproven.to_dict()


def test_governance_meta_omits_execution_refusal_fields_when_nothing_is_proved() -> None:
    """No refusal, no execution refusal fields: the surface stays additive."""

    meta = _governance_meta(_failed_closed_response())

    assert "executionRefusalEvidence" not in meta
    assert "executionRefusalAuditEventId" not in meta
    assert "executionRefusalAudited" not in meta
    assert "executionRefusalSigned" not in meta
    assert "pendingApproval" not in meta
    # Authorization metadata is unaffected.
    assert meta["auditEventId"] == "evt-authorization"


def test_governance_meta_exposes_pending_approval_handle() -> None:
    pending = MCPPendingApproval(
        pending_id="request-1",
        request_id="request-1",
        tool="payments.create",
        actor_id="agent-user-1",
        tenant_id="tenant-a",
        audit_hash="evt-escalation",
        decision_request_hash="a" * 64,
    )
    meta = _governance_meta(
        MCPGatewayResponse(
            request_id="request-1",
            decision=Decision.ESCALATE,
            status=MCPGatewayStatus.ESCALATED,
            reason_codes=("mcp.gateway.human_approval_required",),
            retryable=False,
            executed=False,
            audit_event_id="evt-escalation",
            pending_approval=pending,
        )
    )

    assert meta["pendingApproval"] == {
        "pendingId": "request-1",
        "requestId": "request-1",
        "tool": "payments.create",
        "actorId": "agent-user-1",
        "tenantId": "tenant-a",
        "auditHash": "evt-escalation",
        "decisionRequestHash": "a" * 64,
    }


def test_token_file_requires_private_regular_file(tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("fixture-token\n", encoding="utf-8")
    token.chmod(0o600)
    assert read_secret_file(token) == "fixture-token"

    token.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        read_secret_file(token)
    token.chmod(0o700)
    with pytest.raises(ValueError, match="0600"):
        read_secret_file(token)


def test_token_file_rejects_symlink_oversize_and_invalid_utf8(tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("fixture-token\n", encoding="utf-8")
    token.chmod(0o600)
    linked = tmp_path / "linked-token"
    linked.symlink_to(token)
    with pytest.raises(ValueError, match="private owner"):
        read_secret_file(linked)

    token.write_bytes(b"x" * 8193)
    token.chmod(0o600)
    with pytest.raises(ValueError, match="bounded size|0600"):
        read_secret_file(token)

    token.write_bytes(b"\xff\xfe")
    token.chmod(0o600)
    with pytest.raises(ValueError, match="UTF-8"):
        read_secret_file(token)


def test_token_file_rejects_nonowner_fd_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = tmp_path / "token"
    token.write_text("fixture-token\n", encoding="utf-8")
    token.chmod(0o600)
    original_fstat = os.fstat

    def foreign_owner(descriptor: int) -> SimpleNamespace:
        info = original_fstat(descriptor)
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_uid=os.geteuid() + 1,
            st_size=info.st_size,
        )

    monkeypatch.setattr(os, "fstat", foreign_owner)
    with pytest.raises(ValueError, match="owner-owned"):
        read_secret_file(token)


def test_token_file_path_swap_reads_original_open_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = tmp_path / "token"
    token.write_text("original-token\n", encoding="utf-8")
    token.chmod(0o600)
    replacement = tmp_path / "replacement"
    replacement.write_text("attacker-token\n", encoding="utf-8")
    replacement.chmod(0o600)
    original_open = os.open

    def swap_after_open(path: os.PathLike[str] | str, flags: int) -> int:
        descriptor = original_open(path, flags)
        os.replace(replacement, token)
        return descriptor

    monkeypatch.setattr(os, "open", swap_after_open)
    assert read_secret_file(token) == "original-token"


def test_request_id_is_type_separated_bounded_and_collision_resistant() -> None:
    assert _request_id("session", 1) != _request_id("session", "1")
    assert _request_id("a\x00b", "c") != _request_id("a", "b\x00c")
    assert _request_id("session", "stable") == _request_id("session", "stable")
    with pytest.raises(TypeError):
        _request_id("session", True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="oversized"):
        _request_id("session", "x" * 4097)
    assert _handler_request_id("session", True) == ""
    assert _handler_request_id("session", "x" * 4097) == ""


def test_invalid_protocol_request_id_becomes_verifiable_gateway_denial(tmp_path: Path) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: runtime.gateway.list_tools(
                    inbound_token="fixture-token",
                    session_id="session-1",
                    request_id=_handler_request_id("session-1", True),
                )
            )
            assert response.status is MCPGatewayStatus.DENIED
            assert response.reason_codes == ("mcp.gateway.invalid_request",)
            assert response.refusal_evidence is not None
            assert response.refusal_evidence.verify_integrity(audit=runtime.audit)
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_poisoned_downstream_catalog_is_denied_with_verifiable_evidence(tmp_path: Path) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
            catalog_mode="poison-description",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: runtime.gateway.list_tools(
                    inbound_token="fixture-token",
                    session_id="session-1",
                    request_id="list-poisoned",
                )
            )
            assert response.status is MCPGatewayStatus.DENIED
            assert response.reason_codes == ("mcp.gateway.catalog_mismatch",)
            assert response.refusal_evidence is not None
            assert response.refusal_evidence.verify_integrity(audit=runtime.audit)
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_same_low_level_server_is_configurable_for_stdio_without_sdk_global_state(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            server = build_mcp_server(
                runtime.gateway,
                stdio_token="fixture-token",
                stdio_session_id="session-1",
            )
            assert len(server.request_handlers) >= 2
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_reference_runtime_construction_failure_reaps_started_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        def fail_post_init(_runtime: object) -> None:
            raise RuntimeError("injected MCPReferenceRuntime construction failure")

        monkeypatch.setattr(
            mcp_reference_module.MCPReferenceRuntime,
            "__post_init__",
            fail_post_init,
        )
        with pytest.raises(RuntimeError, match="injected MCPReferenceRuntime"):
            await create_reference_runtime(
                tmp_path,
                inbound_token="fixture-token",
                session_id="session-1",
            )
        pid_path = tmp_path / "fixture.pid"
        assert pid_path.is_file()
        await _assert_process_reaped(pid_path)

    anyio.run(run)


def test_closed_fixed_child_is_not_restarted_or_fallen_back(tmp_path: Path) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        target = runtime.transport.target
        await runtime.aclose()
        with pytest.raises(RuntimeError, match="unavailable"):
            runtime.transport._event_loop_token()
        assert target.instance_id
        assert not (tmp_path / "fixture-ledger.jsonl").exists()

    anyio.run(run)


def test_reference_executes_private_immutable_attested_script(tmp_path: Path) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            target = runtime.transport.target
            artifact = Path(target.artifact_path)
            info = artifact.stat(follow_symlinks=False)
            assert target.argv == (target.artifact_path,)
            assert artifact.is_symlink() is False
            assert info.st_nlink == 1
            assert info.st_uid == os.geteuid()
            assert info.st_ino == target.artifact_inode
            assert info.st_dev == target.artifact_device
            assert info.st_size == target.artifact_size
            assert info.st_mode & 0o777 == 0o500
            assert artifact.parent.stat().st_mode & 0o777 == 0o700
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_identical_artifact_swap_during_spawn_fails_closed_without_fixture_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        artifact = tmp_path / "private-fixture.py"
        artifact.write_bytes(Path(mcp_fixture_server.__file__).read_bytes())
        artifact.chmod(0o500)
        ledger = tmp_path / "ledger.jsonl"
        validator = MCPStdioTargetValidator()
        transport = MCPFixedStdioTransport(
            validator=validator,
            server_id="fixture-server",
            executable=str(Path(sys.executable).resolve(strict=True)),
            argv=(str(artifact.resolve()),),
            cwd=str(tmp_path),
            artifact_path=str(artifact.resolve()),
            environment={
                "ACGS_FIXTURE_LEDGER": str(ledger),
                "ACGS_FIXTURE_CATALOG_MODE": "normal",
                "ACGS_FIXTURE_AMBIGUOUS_DELAY_MS": "0",
                "PYTHONPATH": str(Path(__import__("mcp").__file__).resolve().parent.parent),
            },
        )
        original_stdio_client = stdio_transport_module.stdio_client

        @asynccontextmanager
        async def swap_before_spawn(
            parameters: StdioServerParameters,
        ) -> AsyncIterator[Any]:
            replacement = tmp_path / "replacement.py"
            replacement.write_bytes(artifact.read_bytes())
            replacement.chmod(0o500)
            os.replace(replacement, artifact)
            async with original_stdio_client(parameters) as streams:
                yield streams

        monkeypatch.setattr(stdio_transport_module, "stdio_client", swap_before_spawn)
        with pytest.raises(MCPStdioError) as raised:
            await transport.start()
        assert raised.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT
        assert not ledger.exists()

    anyio.run(run)


@pytest.mark.parametrize("unsafe_shape", ["other-writable", "symlink"])
def test_unsafe_malicious_interpreter_never_runs(
    tmp_path: Path,
    unsafe_shape: str,
) -> None:
    async def run() -> None:
        artifact = _fixture_artifact(tmp_path)
        marker = tmp_path / "interpreter-ran"
        interpreter = _python_wrapper(tmp_path / "malicious-python", marker=marker)
        if unsafe_shape == "other-writable":
            interpreter.chmod(0o777)
        else:
            linked = tmp_path / "linked-python"
            linked.symlink_to(interpreter)
            interpreter = linked
        transport = MCPFixedStdioTransport(
            validator=MCPStdioTargetValidator(),
            server_id="fixture-server",
            executable=str(interpreter.absolute()),
            argv=(str(artifact),),
            cwd=str(tmp_path),
            artifact_path=str(artifact),
            environment=_fixture_environment(tmp_path),
        )

        with pytest.raises(MCPStdioError) as raised:
            await transport.start()

        assert raised.value.reason_code is MCPStdioReasonCode.INVALID_TARGET
        assert not marker.exists()
        assert not (tmp_path / "ledger.jsonl").exists()
        assert not (tmp_path / "fixture.pid").exists()

    anyio.run(run)


@pytest.mark.parametrize("mutation", ["content", "inode", "mode"])
def test_interpreter_drift_before_spawn_fails_closed_without_side_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    async def run() -> None:
        artifact = _fixture_artifact(tmp_path)
        marker = tmp_path / "interpreter-ran"
        interpreter = _python_wrapper(tmp_path / "python-wrapper", marker=marker)
        validator = MCPStdioTargetValidator()
        original_revalidate = validator.revalidate
        mutated = False

        def mutate_before_revalidate(target: Any) -> Any:
            nonlocal mutated
            if not mutated:
                mutated = True
                if mutation == "content":
                    _python_wrapper(interpreter, marker=marker)
                    with interpreter.open("a", encoding="utf-8") as stream:
                        stream.write("# drift\n")
                elif mutation == "inode":
                    replacement = _python_wrapper(
                        tmp_path / "replacement-python",
                        marker=marker,
                    )
                    os.replace(replacement, interpreter)
                else:
                    interpreter.chmod(0o777)
            return original_revalidate(target)

        monkeypatch.setattr(validator, "revalidate", mutate_before_revalidate)
        transport = MCPFixedStdioTransport(
            validator=validator,
            server_id="fixture-server",
            executable=str(interpreter),
            argv=(str(artifact),),
            cwd=str(tmp_path),
            artifact_path=str(artifact),
            environment=_fixture_environment(tmp_path),
        )

        with pytest.raises(MCPStdioError) as raised:
            await transport.start()

        assert raised.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT
        assert not marker.exists()
        assert not (tmp_path / "ledger.jsonl").exists()
        assert not (tmp_path / "fixture.pid").exists()

    anyio.run(run)


@pytest.mark.parametrize("mutation", ["content", "inode", "mode"])
def test_interpreter_drift_during_initialize_fails_closed_without_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    async def run() -> None:
        artifact = _fixture_artifact(tmp_path)
        interpreter = _python_wrapper(tmp_path / "python-wrapper")
        marker = tmp_path / "replacement-ran"
        original_stdio_client = stdio_transport_module.stdio_client

        @asynccontextmanager
        async def swap_after_spawn(
            parameters: StdioServerParameters,
        ) -> AsyncIterator[Any]:
            async with original_stdio_client(parameters) as streams:
                pid_path = tmp_path / "fixture.pid"
                for _ in range(100):
                    if pid_path.exists():
                        break
                    await anyio.sleep(0.01)
                assert pid_path.exists()
                if mutation == "content":
                    _python_wrapper(interpreter, marker=marker)
                elif mutation == "inode":
                    replacement = _python_wrapper(
                        tmp_path / "replacement-python",
                        marker=marker,
                    )
                    os.replace(replacement, interpreter)
                else:
                    interpreter.chmod(0o777)
                yield streams

        monkeypatch.setattr(stdio_transport_module, "stdio_client", swap_after_spawn)
        transport = MCPFixedStdioTransport(
            validator=MCPStdioTargetValidator(),
            server_id="fixture-server",
            executable=str(interpreter),
            argv=(str(artifact),),
            cwd=str(tmp_path),
            artifact_path=str(artifact),
            environment=_fixture_environment(tmp_path),
        )

        with pytest.raises(MCPStdioError) as raised:
            await transport.start()

        assert raised.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT
        assert not marker.exists()
        assert not (tmp_path / "ledger.jsonl").exists()
        await _assert_process_reaped(tmp_path / "fixture.pid")

    anyio.run(run)


def test_grandparent_swap_restore_is_detected_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        grandparent = tmp_path / "trusted-grandparent"
        grandparent.mkdir(mode=0o700)
        private = grandparent / "private"
        private.mkdir(mode=0o700)
        artifact = _fixture_artifact(private)
        marker = tmp_path / "interpreter-ran"
        interpreter = _python_wrapper(private / "python-wrapper", marker=marker)
        validator = MCPStdioTargetValidator()
        original_revalidate = validator.revalidate
        swapped = False

        def swap_ancestor_before_revalidate(target: Any) -> Any:
            nonlocal swapped
            if swapped:
                return original_revalidate(target)
            swapped = True
            saved = tmp_path / "saved-grandparent"
            grandparent.rename(saved)
            grandparent.mkdir(mode=0o700)
            (saved / "private").rename(grandparent / "private")
            try:
                return original_revalidate(target)
            finally:
                (grandparent / "private").rename(saved / "private")
                grandparent.rmdir()
                saved.rename(grandparent)

        monkeypatch.setattr(validator, "revalidate", swap_ancestor_before_revalidate)
        transport = MCPFixedStdioTransport(
            validator=validator,
            server_id="fixture-server",
            executable=str(interpreter),
            argv=(str(artifact),),
            cwd=str(private),
            artifact_path=str(artifact),
            environment=_fixture_environment(tmp_path),
        )

        with pytest.raises(MCPStdioError) as raised:
            await transport.start()

        assert raised.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT
        assert not marker.exists()
        assert not (tmp_path / "ledger.jsonl").exists()
        assert not (tmp_path / "fixture.pid").exists()
        assert grandparent.exists()
        assert not (tmp_path / "saved-grandparent").exists()

    anyio.run(run)


def test_reference_state_root_under_unsafe_ancestor_is_rejected(tmp_path: Path) -> None:
    async def run() -> None:
        unsafe = tmp_path / "unsafe-grandparent"
        unsafe.mkdir(mode=0o700)
        state = unsafe / "private-state"
        state.mkdir(mode=0o700)
        unsafe.chmod(0o777)

        with pytest.raises(RuntimeError, match="state root"):
            await create_reference_runtime(
                state,
                inbound_token="fixture-token",
                session_id="session-1",
            )

        assert not (state / ".mcp-private").exists()
        assert not (state / "fixture.pid").exists()
        assert not (state / "fixture-ledger.jsonl").exists()

    anyio.run(run)


@pytest.mark.parametrize(
    "catalog_mode",
    ["echo-credential-meta", "echo-credential-text", "echo-credential-structured"],
)
def test_echoed_downstream_authority_is_failed_closed_and_never_retried(
    tmp_path: Path,
    catalog_mode: str,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
            catalog_mode=catalog_mode,
        )
        try:
            params = _call_params(
                "fixture.write_once",
                {"record": "must-not-leak"},
                _authorization(),
            )
            response = await anyio.to_thread.run_sync(
                lambda: runtime.gateway.dispatch(
                    "tools/call",
                    inbound_token="fixture-token",
                    session_id="session-1",
                    request_id=f"echo-{catalog_mode}",
                    params=params,
                )
            )
            assert isinstance(response, MCPGatewayResponse)
            assert response.status is MCPGatewayStatus.FAILED_CLOSED
            assert response.outcome_unknown is True
            assert response.retryable is False
            assert response.executed is False
            assert response.payload is None
            calls = (tmp_path / "fixture-calls.jsonl").read_text(encoding="utf-8")
            assert len(calls.splitlines()) == 1
            serialized = repr(response) + repr(runtime)
            state = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
            for forbidden in (b"fixture-token", b"fixture-downstream-secret"):
                assert forbidden not in serialized.encode()
                assert forbidden not in state
            for forbidden in (
                b"fixture-downstream-credential",
                b"io.acgs/downstream-credential",
            ):
                assert forbidden not in serialized.encode()
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_never_reads_token_from_process_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "environ", dict(os.environ))
    assert "--token" not in " ".join(__import__("sys").argv)


def test_reference_proof_sources_are_public_frozen_and_cross_linked(tmp_path: Path) -> None:
    raw_nonce = "nonce-must-never-persist"
    raw_idempotency = "idempotency-must-never-persist"

    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            metadata = _authorization()
            authorization = metadata["io.acgs/authorization"]
            assert isinstance(authorization, dict)
            authorization["nonce"] = raw_nonce
            authorization["idempotencyKey"] = raw_idempotency
            response = await anyio.to_thread.run_sync(
                lambda: runtime.gateway.dispatch(
                    "tools/call",
                    inbound_token="fixture-token",
                    session_id="session-1",
                    request_id="proof-source-allow",
                    params=_call_params(
                        "fixture.write_once",
                        {"record": "proof-source-record"},
                        metadata,
                    ),
                )
            )
            assert isinstance(response, MCPGatewayResponse)
            assert response.status is MCPGatewayStatus.SUCCEEDED
            assert response.receipt is not None

            sources = runtime.public_snapshot()
            assert sources is runtime.proof_sources
            assert sources.audit_path == runtime.audit.path
            assert sources.replay_path == runtime.replay_store.path
            assert sources.consumption_path == runtime.consumption_store.path
            assert sources.fixture_ledger_path == tmp_path / "fixture-ledger.jsonl"
            assert sources.fixture_call_log_path == tmp_path / "fixture-calls.jsonl"
            assert sources.target_server_id == runtime.transport.target.server_id
            assert sources.target_instance_id == runtime.transport.target.instance_id
            assert sources.tenant_id == "fixture-tenant"
            assert sources.policy_digest == response.receipt.policy_hash
            assert sources.receipt_key.key_id == response.receipt.signing_key_id
            assert sources.refusal_key.public_bytes == sources.receipt_key.public_bytes

            event = next(
                item
                for item in runtime.audit.iter_events()
                if item["event_id"] == response.audit_event_id
            )
            replay = runtime.replay_store.get(response.audit_event_id)
            assert replay is not None
            assert replay["event_id"] == event["event_id"]
            assert replay["decision"] == event["decision"] == "allow"
            assert replay["argument_hash"] == event["argument_hash"]
            assert replay["policy_version"] == event["policy_version"]

            checkpoint = runtime.seal_current_audit_checkpoint()
            audit_events = list(runtime.audit.iter_events())
            assert len(audit_events) == 3
            assert audit_events[0]["event_hash"] == response.receipt.audit_event_hash
            assert audit_events[1]["execution_evidence"]["phase"] == "claim_committed"
            assert audit_events[2]["execution_evidence"]["phase"] == "terminal"
            assert checkpoint.generation == 3
            assert checkpoint.head_hash == audit_events[-1]["event_hash"]
            checkpoint_verifier = Ed25519Signer.from_public_bytes(
                sources.checkpoint_key.public_bytes,
                key_id=sources.checkpoint_key.key_id,
            )
            assert checkpoint_verifier.verify(checkpoint.signing_payload(), checkpoint.signature)

            snapshot = runtime.signed_consumption_snapshot()
            assert snapshot.schema == "gove-zone.mcp-consumption-snapshot/v2"
            consumption_verifier = Ed25519Signer.from_public_bytes(
                sources.consumption_key.public_bytes,
                key_id=sources.consumption_key.key_id,
            )
            assert consumption_verifier.verify(snapshot.signing_payload(), snapshot.signature)
            assert snapshot.anchor_namespace == sources.consumption_namespace
            assert snapshot.tenant_id == sources.tenant_id
            assert snapshot.evidence_mode == "signed-redacted-anchor-not-row-membership-proof"
            with pytest.raises(ValueError, match="schema"):
                dataclasses.replace(
                    snapshot,
                    schema="gove-zone.mcp-consumption-snapshot/v1",
                )

            public_json = json.dumps(sources.to_dict(), sort_keys=True)
            serialized = (repr(runtime) + repr(sources) + public_json).encode()
            persisted = b"".join(
                path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
            )
            for forbidden in (
                b"fixture-token",
                b"fixture-downstream-secret",
                raw_nonce.encode(),
                raw_idempotency.encode(),
                b"p1-reference-binding-hmac-key",
                b"p1-reference-consumption-key",
            ):
                assert forbidden not in serialized
                assert forbidden not in persisted
            with pytest.raises(TypeError, match="non-serializable"):
                pickle.dumps(runtime)
            with pytest.raises(dataclasses.FrozenInstanceError):
                sources.tenant_id = "attacker"  # type: ignore[misc]
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_signed_evidence_ignores_mutated_public_snapshot(tmp_path: Path) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            sources = runtime.public_snapshot()
            consumption_key = sources.consumption_key
            canonical_consumption_namespace = sources.consumption_namespace
            canonical_audit_namespace = sources.audit_namespace
            canonical_checkpoint = runtime.audit_anchor.read(canonical_audit_namespace)
            assert canonical_checkpoint is not None

            with pytest.raises(
                (AttributeError, TypeError, ValueError, dataclasses.FrozenInstanceError)
            ):
                runtime.proof_sources = dataclasses.replace(  # type: ignore[misc]
                    sources,
                    tenant_id="attacker-tenant",
                )

            attacker_namespace = "mcp-reference:attacker-namespace"
            attacker_state = AnchoredConsumptionState(
                store_id="a" * 64,
                generation=99,
                chain_head="b" * 64,
                state_root="c" * 64,
            )
            assert runtime.consumption_anchor.compare_and_swap(
                attacker_namespace,
                None,
                attacker_state,
            )
            assert runtime.audit_anchor.compare_and_swap(
                "mcp-reference:attacker-audit",
                None,
                canonical_checkpoint,
            )

            object.__setattr__(sources, "tenant_id", "attacker-tenant")
            object.__setattr__(sources, "consumption_namespace", attacker_namespace)
            object.__setattr__(sources, "audit_namespace", "mcp-reference:attacker-audit")
            with pytest.raises(RuntimeError, match="proof-source snapshot was modified"):
                runtime.public_snapshot()

            snapshot = runtime.signed_consumption_snapshot()
            assert snapshot.tenant_id == "fixture-tenant"
            assert snapshot.anchor_namespace == canonical_consumption_namespace
            assert snapshot.store_id != attacker_state.store_id
            verifier = Ed25519Signer.from_public_bytes(
                consumption_key.public_bytes,
                key_id=consumption_key.key_id,
            )
            assert verifier.verify(snapshot.signing_payload(), snapshot.signature)

            checkpoint = runtime.seal_current_audit_checkpoint()
            assert checkpoint.namespace == canonical_audit_namespace
            assert checkpoint == canonical_checkpoint
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_canonical_consumption_anchor_replacement_fails_closed(tmp_path: Path) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            namespace = runtime.proof_sources.consumption_namespace
            current = runtime.consumption_anchor.read(namespace)
            assert current is not None
            replacement = dataclasses.replace(current, state_root="d" * 64)
            assert runtime.consumption_anchor.compare_and_swap(namespace, current, replacement)
            with pytest.raises(ConsumptionStoreError, match="anchor mismatch"):
                runtime.signed_consumption_snapshot()
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_concurrent_consumption_anchor_change_returns_no_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            namespace = runtime.proof_sources.consumption_namespace
            signer = runtime._consumption_signer
            original_sign = signer.sign

            def sign_then_change(payload: bytes) -> str:
                signature = original_sign(payload)
                current = runtime.consumption_anchor.read(namespace)
                assert current is not None
                replacement = dataclasses.replace(current, chain_head="e" * 64)
                assert runtime.consumption_anchor.compare_and_swap(
                    namespace,
                    current,
                    replacement,
                )
                return signature

            monkeypatch.setattr(signer, "sign", sign_then_change)
            with pytest.raises(RuntimeError, match="changed while it was signed"):
                runtime.signed_consumption_snapshot()
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_captures_row_bound_normal_consumption_without_another_call(
    tmp_path: Path,
) -> None:
    raw_nonce = "capture-nonce-must-not-leak"
    raw_idempotency = "capture-idempotency-must-not-leak"

    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id="capture-normal",
                    record="capture-normal",
                    nonce=raw_nonce,
                    idempotency_key=raw_idempotency,
                )
            )
            assert response.status is MCPGatewayStatus.SUCCEEDED
            call_log = tmp_path / "fixture-calls.jsonl"
            calls_before = call_log.read_text(encoding="utf-8").splitlines()
            record = _normal_consumption_record(response)
            evidence = runtime.capture_consumption_evidence(
                "normal",
                response=response,
                outcome_record_id="protocol-normal",
                records=[record],
            )
            wrapper = evidence.to_dict()
            assert set(wrapper) == mcp_proof_module._CONSUMPTION_KEYS
            assert wrapper["schema"] == "gove-zone.mcp-action-consumption-snapshot/v2"
            assert wrapper["anchor_namespace"] == "mcp-proof-consumption:normal"
            assert wrapper["generation"] == 2
            assert wrapper["event_ids"] == [response.audit_event_id]
            assert wrapper["outcome_record_ids"] == ["protocol-normal"]
            assert wrapper["records"] == [record]
            verifier = Ed25519Signer.from_public_bytes(
                runtime._canonical_consumption_key.public_bytes,
                key_id=runtime._canonical_consumption_key.key_id,
            )
            assert verifier.verify(evidence.snapshot.signing_payload(), evidence.snapshot.signature)
            unsigned = dict(wrapper)
            signature = unsigned.pop("outer_signature")
            assert verifier.verify(
                _ACTION_CONSUMPTION_DOMAIN + canonical_json(unsigned).encode("utf-8"),
                signature,
            )
            with pytest.raises(TypeError):
                evidence.records[0]["state"] = "UNKNOWN"  # type: ignore[index]
            assert call_log.read_text(encoding="utf-8").splitlines() == calls_before

            serialized = canonical_json(wrapper).encode("utf-8")
            persisted = b"".join(
                path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
            )
            for forbidden in (
                raw_nonce.encode(),
                raw_idempotency.encode(),
                b"fixture-downstream-secret",
                b"p1-reference-consumption-key",
            ):
                assert forbidden not in serialized
                assert forbidden not in persisted

            for fabricated in (
                dataclasses.replace(response),
                dataclasses.replace(response, payload={"written": False}),
            ):
                with pytest.raises(RuntimeError, match="captured execution outcome"):
                    runtime.capture_consumption_evidence(
                        "normal",
                        response=fabricated,
                        outcome_record_id="protocol-normal",
                        records=[record],
                    )

            object.__setattr__(response, "payload", {"written": False})
            with pytest.raises(RuntimeError, match="captured execution outcome"):
                runtime.capture_consumption_evidence(
                    "normal",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[record],
                )
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_request_lookup_returns_exact_response_and_fails_closed(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id="exact-response-lookup",
                    record="exact-response-lookup",
                    nonce="exact-response-nonce",
                    idempotency_key="exact-response-idempotency",
                )
            )
            assert runtime.require_gateway_response("exact-response-lookup") is response
            with pytest.raises(RuntimeError, match="unknown"):
                runtime.require_gateway_response("unknown-response")
            with pytest.raises(RuntimeError, match="reused"):
                runtime._outcome_sink.capture(
                    response,
                    request_id="exact-response-lookup",
                    tool_name="fixture.write_once",
                    arguments={"record": "exact-response-lookup"},
                )
            object.__setattr__(response, "payload", {"written": False})
            with pytest.raises(RuntimeError, match="modified"):
                runtime.require_gateway_response("exact-response-lookup")
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_captures_empty_poison_consumption_on_fresh_dedicated_store(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            evidence = runtime.capture_consumption_evidence(
                "poison",
                response=None,
                outcome_record_id=None,
                records=(),
            )
            wrapper = evidence.to_dict()
            assert wrapper["lane"] == "poison"
            assert wrapper["anchor_namespace"] == "mcp-proof-consumption:poison"
            assert wrapper["generation"] == 0
            assert wrapper["event_ids"] == []
            assert wrapper["outcome_record_ids"] == []
            assert wrapper["records"] == []
            verifier = Ed25519Signer.from_public_bytes(
                runtime._canonical_consumption_key.public_bytes,
                key_id=runtime._canonical_consumption_key.key_id,
            )
            unsigned = dict(wrapper)
            signature = unsigned.pop("outer_signature")
            assert verifier.verify(
                _ACTION_CONSUMPTION_DOMAIN + canonical_json(unsigned).encode("utf-8"),
                signature,
            )
            assert not (tmp_path / "fixture-calls.jsonl").exists()
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_consumption_capture_rejects_wrong_row_bindings(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id="wrong-binding",
                    record="wrong-binding",
                    nonce="wrong-binding-nonce",
                    idempotency_key="wrong-binding-idempotency",
                )
            )
            for field, bad_value in (
                ("event_id", "wrong-event"),
                ("outcome_record_id", "wrong-outcome"),
                ("receipt_id", "wrong-receipt"),
                ("receipt_hash", "0" * 64),
                ("state", "RESERVED"),
                ("result_digest", "1" * 64),
                ("audit_event_hash", "2" * 64),
                ("tenant_id", "wrong-tenant"),
                ("actor", "wrong-actor"),
                ("governed_operation", "wrong.operation"),
                ("authority", "wrong.authority"),
                ("downstream_tool", "wrong.tool"),
                ("arguments_hash", "3" * 64),
            ):
                record = _normal_consumption_record(response)
                record[field] = bad_value
                with pytest.raises(RuntimeError, match="record binding mismatch"):
                    runtime.capture_consumption_evidence(
                        "normal",
                        response=response,
                        outcome_record_id="protocol-normal",
                        records=[record],
                    )
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_consumption_capture_rejects_nonterminal_and_wrong_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:

            def fail_completion(*_args: object, **_kwargs: object) -> None:
                raise ConsumptionStoreError("forced terminal failure")

            monkeypatch.setattr(runtime.consumption_store, "mark_succeeded", fail_completion)
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id="before-terminal",
                    record="before-terminal",
                    nonce="before-terminal-nonce",
                    idempotency_key="before-terminal-idempotency",
                )
            )
            assert response.status is MCPGatewayStatus.FAILED_CLOSED
            with pytest.raises(RuntimeError, match="not the captured execution outcome"):
                runtime.capture_consumption_evidence(
                    "normal",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[_normal_consumption_record(response)],
                )
            with pytest.raises(ValueError, match="empty fresh lane"):
                runtime.capture_consumption_evidence(
                    "poison",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[_normal_consumption_record(response)],
                )
            with pytest.raises(ValueError, match="normal or poison"):
                runtime.capture_consumption_evidence(
                    "attacker",
                    response=None,
                    outcome_record_id=None,
                    records=(),
                )
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_consumption_capture_rejects_hidden_generations(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        normal_runtime = await create_reference_runtime(
            tmp_path / "normal",
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            first = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    normal_runtime,
                    request_id="generation-first",
                    record="generation-first",
                    nonce="generation-first-nonce",
                    idempotency_key="generation-first-idempotency",
                )
            )
            second = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    normal_runtime,
                    request_id="generation-second",
                    record="generation-second",
                    nonce="generation-second-nonce",
                    idempotency_key="generation-second-idempotency",
                )
            )
            assert first.status is second.status is MCPGatewayStatus.SUCCEEDED
            with pytest.raises(RuntimeError, match="dedicated lane lifecycle"):
                normal_runtime.capture_consumption_evidence(
                    "normal",
                    response=second,
                    outcome_record_id="protocol-normal",
                    records=[_normal_consumption_record(second)],
                )

        finally:
            await normal_runtime.aclose()

        poison_runtime = await create_reference_runtime(
            tmp_path / "poison",
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            poison_runtime.consumption_store.revoke("fixture-tenant", "never-issued")
            with pytest.raises(RuntimeError, match="dedicated lane lifecycle"):
                poison_runtime.capture_consumption_evidence(
                    "poison",
                    response=None,
                    outcome_record_id=None,
                    records=(),
                )
        finally:
            await poison_runtime.aclose()

    anyio.run(run)


def test_runtime_consumption_capture_rejects_concurrent_mutation_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id="concurrent-capture",
                    record="concurrent-capture",
                    nonce="concurrent-capture-nonce",
                    idempotency_key="concurrent-capture-idempotency",
                )
            )
            signer = runtime._consumption_signer
            original_sign = signer.sign
            calls = 0

            def sign_then_change(payload: bytes) -> str:
                nonlocal calls
                calls += 1
                signature = original_sign(payload)
                if calls == 2:
                    namespace = runtime._canonical_consumption_namespace
                    current = runtime.consumption_anchor.read(namespace)
                    assert current is not None
                    assert runtime.consumption_anchor.compare_and_swap(
                        namespace,
                        current,
                        dataclasses.replace(current, chain_head="e" * 64),
                    )
                return signature

            monkeypatch.setattr(signer, "sign", sign_then_change)
            with pytest.raises(RuntimeError, match="changed while evidence was signed"):
                runtime.capture_consumption_evidence(
                    "normal",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[_normal_consumption_record(response)],
                )
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_consumption_capture_seals_every_construction_time_source_and_pin(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id="private-roots",
                    record="private-roots",
                    nonce="private-roots-nonce",
                    idempotency_key="private-roots-idempotency",
                )
            )
            record = _normal_consumption_record(response)
            for public_field in ("gateway", "transport", "audit", "state_dir"):
                with pytest.raises(dataclasses.FrozenInstanceError):
                    setattr(runtime, public_field, object())

            replacement_key = MCPPublicVerificationKey(
                purpose="consumption-snapshot",
                key_id="attacker-consumption-key",
                algorithm="ed25519",
                public_bytes=Ed25519Signer.generate().public_bytes(),
            )
            replacements: dict[str, object] = {
                "gateway": object(),
                "transport": object(),
                "audit": object(),
                "state_dir": tmp_path / "attacker-state",
                "_proof_sources": dataclasses.replace(
                    runtime.proof_sources,
                    target_instance_id="attacker-instance",
                ),
                "_proof_sources_digest": "0" * 64,
                "_audit_anchor": object(),
                "_replay_store": object(),
                "_consumption_store": object(),
                "_consumption_anchor": object(),
                "_consumption_signer": Ed25519Signer.generate("attacker-consumption-key"),
                "_outcome_sink": object(),
                "_canonical_tenant_id": "attacker-tenant",
                "_canonical_audit_namespace": "attacker-audit",
                "_canonical_consumption_namespace": "attacker-consumption",
                "_canonical_audit_path": tmp_path / "attacker-audit.jsonl",
                "_canonical_consumption_path": tmp_path / "attacker-consumption.sqlite3",
                "_canonical_consumption_key": replacement_key,
                "_canonical_policy_version": "attacker-policy/v1",
                "_canonical_policy_digest": "1" * 64,
                "_canonical_target_server_digest": "2" * 64,
                "_canonical_target_launch_digest": "3" * 64,
                "_canonical_target_transport_digest": "4" * 64,
                "_canonical_target_artifact_digest": "5" * 64,
                "_trust_capsule": dataclasses.replace(
                    runtime._trust_capsule,
                    tenant_id="attacker-tenant",
                ),
                "_trust_capsule_digest": "6" * 64,
            }
            for field_name, replacement in replacements.items():
                original = getattr(runtime, field_name)
                object.__setattr__(runtime, field_name, replacement)
                with pytest.raises(RuntimeError, match="trust-root"):
                    runtime.capture_consumption_evidence(
                        "normal",
                        response=response,
                        outcome_record_id="protocol-normal",
                        records=[record],
                    )
                object.__setattr__(runtime, field_name, original)

            public = runtime.proof_sources
            original_tenant = public.tenant_id
            object.__setattr__(public, "tenant_id", "attacker-tenant")
            with pytest.raises(RuntimeError, match="trust-root"):
                runtime.capture_consumption_evidence(
                    "normal",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[record],
                )
            object.__setattr__(public, "tenant_id", original_tenant)

            canonical_signer = runtime._consumption_signer
            canonical_key_id = canonical_signer._key_id
            canonical_signer._key_id = "receipt-purpose-key"
            with pytest.raises(RuntimeError, match="wrong proof purpose"):
                runtime.capture_consumption_evidence(
                    "normal",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[record],
                )
            canonical_signer._key_id = canonical_key_id
        finally:
            await runtime.aclose()

    anyio.run(run)


@pytest.mark.parametrize("source_name", ["audit", "replay"])
@pytest.mark.parametrize("mutation", ["delete", "swap"])
def test_runtime_consumption_capture_rejects_deleted_or_swapped_proof_files(
    tmp_path: Path,
    source_name: str,
    mutation: str,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id=f"{source_name}-{mutation}",
                    record=f"{source_name}-{mutation}",
                    nonce=f"{source_name}-{mutation}-nonce",
                    idempotency_key=f"{source_name}-{mutation}-idempotency",
                )
            )
            record = _normal_consumption_record(response)
            path = (
                runtime.proof_sources.audit_path
                if source_name == "audit"
                else runtime.proof_sources.replay_path
            )
            contents = path.read_bytes()
            if mutation == "delete":
                path.unlink()
            else:
                path.replace(path.with_suffix(path.suffix + ".swapped"))
                path.write_bytes(contents)
            with pytest.raises(RuntimeError, match="proof source|changed after execution"):
                runtime.capture_consumption_evidence(
                    "normal",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[record],
                )
        finally:
            await runtime.aclose()

    anyio.run(run)


@pytest.mark.parametrize("sign_call", [1, 2])
@pytest.mark.parametrize("mutation", ["rotate-private-public", "replace-signer"])
def test_runtime_consumption_capture_closes_signer_toctou_without_returning_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sign_call: int,
    mutation: str,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    runtime,
                    request_id=f"signer-toctou-{sign_call}-{mutation}",
                    record=f"signer-toctou-{sign_call}-{mutation}",
                    nonce=f"signer-toctou-{sign_call}-{mutation}-nonce",
                    idempotency_key=f"signer-toctou-{sign_call}-{mutation}-idempotency",
                )
            )
            record = _normal_consumption_record(response)
            signer = runtime._consumption_signer
            assert isinstance(signer, Ed25519Signer)
            original_sign = signer.sign
            rotated = Ed25519Signer.generate(signer.key_id)
            calls = 0

            def sign_then_mutate(payload: bytes) -> str:
                nonlocal calls
                calls += 1
                signature = original_sign(payload)
                if calls == sign_call:
                    if mutation == "rotate-private-public":
                        signer._private_key = rotated._private_key
                        signer._public_key = rotated._public_key
                    else:
                        object.__setattr__(
                            runtime,
                            "_consumption_signer",
                            Ed25519Signer.generate(signer.key_id),
                        )
                return signature

            monkeypatch.setattr(signer, "sign", sign_then_mutate)
            captured = None
            with pytest.raises(RuntimeError, match="trust-root|wrong proof purpose"):
                captured = runtime.capture_consumption_evidence(
                    "normal",
                    response=response,
                    outcome_record_id="protocol-normal",
                    records=[record],
                )
            assert captured is None
            assert calls == 2
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_runtime_consumption_wrappers_remain_compatible_with_offline_verifier(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        normal = await create_reference_runtime(
            tmp_path / "normal",
            inbound_token="fixture-token",
            session_id="session-1",
            catalog_mode="normal",
            proof_lane="normal",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: _dispatch_reference_write(
                    normal,
                    request_id="offline-verifier-normal",
                    record="offline-verifier-normal",
                    nonce="offline-verifier-normal-nonce",
                    idempotency_key="offline-verifier-normal-idempotency",
                )
            )
            receipt = response.receipt
            assert receipt is not None
            normal_evidence = normal.capture_consumption_evidence(
                "normal",
                response=response,
                outcome_record_id="protocol-normal",
                records=[_normal_consumption_record(response)],
            )
            normal_sources = normal.proof_sources
        finally:
            await normal.aclose()

        poison = await create_reference_runtime(
            tmp_path / "poison",
            inbound_token="fixture-token",
            session_id="session-1",
            catalog_mode="poison-description",
            proof_lane="poison",
        )
        try:
            poison_evidence = poison.capture_consumption_evidence(
                "poison",
                response=None,
                outcome_record_id=None,
                records=(),
            )
            poison_sources = poison.proof_sources
        finally:
            await poison.aclose()

        def lane(name: str, sources: Any, evidence: Any) -> Any:
            keys = {
                slot: mcp_proof_module.MCPTrustKey(
                    purpose=key.purpose,
                    key_id=key.key_id,
                    public_bytes=key.public_bytes,
                )
                for slot, key in {
                    "receipt": sources.receipt_key,
                    "refusal": sources.refusal_key,
                    "checkpoint": sources.checkpoint_key,
                    "consumption": sources.consumption_key,
                    "exchange": sources.exchange_key,
                    "lifecycle": sources.lifecycle_key,
                }.items()
            }
            return mcp_proof_module.MCPTrustLane(
                tenant_id=sources.tenant_id,
                policy_version=sources.policy_version,
                policy_digest=sources.policy_digest,
                policy_attestation=sources.policy_attestation,
                target=dict(evidence.target),
                checkpoint_authority_id=f"audit-checkpoint:mcp-proof:{name}",
                lifecycle_authority_id=sources.lifecycle_authority_id,
                keys=keys,
            )

        trust = mcp_proof_module.MCPTrustBundle(
            lanes={
                "normal": lane("normal", normal_sources, normal_evidence),
                "poison": lane("poison", poison_sources, poison_evidence),
            }
        )
        mcp_proof_module._verify_consumption(
            {
                "normal-consumption-snapshot.json": normal_evidence.to_dict(),
                "poison-consumption-snapshot.json": poison_evidence.to_dict(),
            },
            trust,
            {
                "normal": {
                    "event_id": response.audit_event_id,
                    "record_id": "protocol-normal",
                    "result_digest": safe_result_hash(response.payload),
                    "actor": receipt.actor,
                    "governed_operation": receipt.proposed_action,
                    "authority": receipt.authority,
                    "downstream_tool": "fixture.write_once",
                    "arguments_hash": receipt.argument_hash,
                },
                "poison": {},
            },
            {
                "normal": {"event_hash": receipt.audit_event_hash},
                "poison": {},
            },
            receipt,
        )

    anyio.run(run)


def test_proof_source_validation_rejects_noncanonical_or_unbounded_inputs(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            sources = runtime.proof_sources
            malformed_artifact = '{"decision": "allow"}'
            malformed_digest = hashlib.sha256(malformed_artifact.encode()).hexdigest()
            oversized_artifact = json.dumps(
                {"value": "x" * mcp_reference_module._MAX_POLICY_ARTIFACT_BYTES},
                sort_keys=True,
                separators=(",", ":"),
            )
            oversized_digest = hashlib.sha256(oversized_artifact.encode()).hexdigest()

            invalid_changes: tuple[dict[str, object], ...] = (
                {"audit_path": Path("relative-audit.jsonl")},
                {"audit_path": Path("/") / ("x" * (mcp_reference_module._MAX_PATH_BYTES + 1))},
                {"replay_path": tmp_path.parent / "replay.jsonl"},
                {"target_artifact_path": tmp_path / "fixture.py"},
                {"tenant_id": "attacker\x00tenant"},
                {"tenant_id": "x" * (mcp_reference_module._MAX_IDENTIFIER_BYTES + 1)},
                {"policy_digest": "a" * 63},
                {"policy_digest": "a" * 65},
                {"policy_digest": "A" * 64},
                {"policy_digest": "f" * 64},
                {
                    "policy_attestation": dataclasses.replace(
                        sources.policy_attestation, tenant_id="tenant-attacker"
                    )
                },
                {
                    "policy_attestation": dataclasses.replace(
                        sources.policy_attestation, artifact_id="attacker-policy"
                    )
                },
                {
                    "policy_attestation": dataclasses.replace(
                        sources.policy_attestation, policy_version="attacker-policy/v1"
                    )
                },
                {
                    "policy_attestation": dataclasses.replace(
                        sources.policy_attestation, digest="0" * 64
                    )
                },
                {
                    "policy_attestation": dataclasses.replace(
                        sources.policy_attestation, resolver_id="attacker-resolver"
                    )
                },
                {"target_launch_digest": "g" * 64},
                {
                    "policy_artifact": malformed_artifact,
                    "policy_digest": malformed_digest,
                },
                {
                    "policy_artifact": oversized_artifact,
                    "policy_digest": oversized_digest,
                },
                {
                    "receipt_key": MCPPublicVerificationKey(
                        purpose="wrong-purpose",
                        key_id=sources.receipt_key.key_id,
                        algorithm="ed25519",
                        public_bytes=sources.receipt_key.public_bytes,
                    )
                },
            )
            for changes in invalid_changes:
                with pytest.raises(ValueError):
                    dataclasses.replace(sources, **changes)  # type: ignore[arg-type]

            first = sources.to_dict()
            second = sources.to_dict()
            assert first == second
            assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
                second,
                sort_keys=True,
                separators=(",", ":"),
            )
            forbidden_keys = {
                "signer",
                "anchor",
                "store",
                "gateway",
                "transport",
                "token",
                "credential",
                "private_key",
                "hmac_key",
                "nonce",
                "idempotency_key",
            }
            assert forbidden_keys.isdisjoint(first)
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_required_replay_commit_failure_denies_before_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:

            def fail_append(*_args: object, **_kwargs: object) -> dict[str, Any]:
                raise OSError("forced replay fsync failure")

            monkeypatch.setattr(
                mcp_reference_module._RequiredReplaySideStore,
                "append",
                fail_append,
            )
            response = await anyio.to_thread.run_sync(
                lambda: runtime.gateway.dispatch(
                    "tools/call",
                    inbound_token="fixture-token",
                    session_id="session-1",
                    request_id="replay-commit-failure",
                    params=_call_params(
                        "fixture.write_once",
                        {"record": "must-not-run"},
                        _authorization(),
                    ),
                )
            )
            assert isinstance(response, MCPGatewayResponse)
            assert response.status is MCPGatewayStatus.DENIED
            assert response.reason_codes == ("authorization.audit_failed",)
            assert response.executed is False
            assert response.refusal_evidence is not None
            assert response.refusal_evidence.signed is True
            refusal_verifier = Ed25519Signer.from_public_bytes(
                runtime.proof_sources.refusal_key.public_bytes,
                key_id=runtime.proof_sources.refusal_key.key_id,
            )
            assert response.refusal_evidence.verify_signature(refusal_verifier)
            assert not (tmp_path / "fixture-ledger.jsonl").exists()
            assert not (tmp_path / "fixture-calls.jsonl").exists()
        finally:
            await runtime.aclose()

    anyio.run(run)


@pytest.mark.parametrize(
    ("decision", "expected_status"),
    [
        (Decision.DENY, MCPGatewayStatus.DENIED),
        (Decision.ESCALATE, MCPGatewayStatus.ESCALATED),
    ],
)
def test_non_executable_policy_decisions_are_cross_linked_without_adapter_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    decision: Decision,
    expected_status: MCPGatewayStatus,
) -> None:
    def decide(
        policy: mcp_reference_module._ReferencePolicy,
        call: Any,
    ) -> DecisionRecord:
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=policy.version,
            event_id=new_event_id(),
            matched_rules=(f"REFERENCE_{decision.value.upper()}",),
            reason=f"fixture {decision.value}",
        )

    monkeypatch.setattr(mcp_reference_module._ReferencePolicy, "evaluate", decide)

    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: runtime.gateway.dispatch(
                    "tools/call",
                    inbound_token="fixture-token",
                    session_id="session-1",
                    request_id=f"policy-{decision.value}",
                    params=_call_params(
                        "fixture.write_once",
                        {"record": "must-not-run"},
                        _authorization(),
                    ),
                )
            )
            assert isinstance(response, MCPGatewayResponse)
            assert response.status is expected_status
            assert response.decision is decision
            assert response.executed is False
            event = next(
                item
                for item in runtime.audit.iter_events()
                if item["event_id"] == response.audit_event_id
            )
            replay = runtime.replay_store.get(response.audit_event_id)
            assert replay is not None
            assert replay["event_id"] == event["event_id"]
            assert replay["decision"] == event["decision"] == decision.value
            assert replay["argument_hash"] == event["argument_hash"]
            assert not (tmp_path / "fixture-ledger.jsonl").exists()
            assert not (tmp_path / "fixture-calls.jsonl").exists()
        finally:
            await runtime.aclose()

    anyio.run(run)


@pytest.mark.parametrize("mutation", ["tool", "arguments"])
def test_captured_authorization_mutation_is_blocked_at_final_adapter_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    async def run() -> None:
        runtime = await create_reference_runtime(
            tmp_path,
            inbound_token="fixture-token",
            session_id="session-1",
        )
        original_execute = ReceiptGatedSideEffectExecutor.execute
        captured: dict[str, object] = {}

        def mutate_before_final_gate(
            executor: ReceiptGatedSideEffectExecutor,
            authorization: Any,
            context: Any,
            *,
            nonce: str,
            idempotency_key: str,
        ) -> Any:
            captured["receipt"] = authorization.receipt
            if mutation == "tool":
                context = dataclasses.replace(context, tool="fixture.read")
            else:
                object.__setattr__(
                    authorization,
                    "approved_arguments",
                    {"record": "mutated-after-approval"},
                )
            return original_execute(
                executor,
                authorization,
                context,
                nonce=nonce,
                idempotency_key=idempotency_key,
            )

        monkeypatch.setattr(
            ReceiptGatedSideEffectExecutor,
            "execute",
            mutate_before_final_gate,
        )
        try:
            response = await anyio.to_thread.run_sync(
                lambda: runtime.gateway.dispatch(
                    "tools/call",
                    inbound_token="fixture-token",
                    session_id="session-1",
                    request_id=f"final-gate-{mutation}",
                    params=_call_params(
                        "fixture.write_once",
                        {"record": "approved-record"},
                        _authorization(),
                    ),
                )
            )
            assert isinstance(response, MCPGatewayResponse)
            assert response.status is MCPGatewayStatus.FAILED_CLOSED
            assert response.executed is False
            assert captured["receipt"] is not None
            assert not (tmp_path / "fixture-ledger.jsonl").exists()
            assert not (tmp_path / "fixture-calls.jsonl").exists()
        finally:
            await runtime.aclose()

    anyio.run(run)


def test_capability_stdio_passes_one_fd_closes_parent_duplicate_and_does_not_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    import subprocess
    import sys

    import anyio

    from gove_zone.mcp_reference import create_reference_runtime
    from gove_zone.proof_pack import PinnedOutputRoot

    observed: dict[str, object] = {}
    original = anyio.open_process

    async def observed_open_process(*args: Any, **kwargs: Any) -> Any:
        observed["pass_fds"] = kwargs.get("pass_fds")
        raw_environment = kwargs.get("env")
        assert isinstance(raw_environment, dict)
        observed["env"] = dict(raw_environment)
        return await original(*args, **kwargs)

    monkeypatch.setattr(anyio, "open_process", observed_open_process)

    async def exercise() -> tuple[int, tuple[int, int]]:
        state = tmp_path / "cap-state"
        with PinnedOutputRoot.create(state) as pinned, pinned.attest() as capability:
            runtime = await create_reference_runtime(
                state,
                inbound_token="fixture-token",
                session_id="fd-contract",
                state_capability=capability,
            )
            try:
                passed = observed["pass_fds"]
                assert type(passed) is tuple and len(passed) == 1
                child_fd = passed[0]
                assert type(child_fd) is int
                with pytest.raises(OSError):
                    os.fstat(child_fd)
                check = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os,sys; expected=(int(sys.argv[1]),int(sys.argv[2])); "
                            "matches=[]; "
                            "[(matches.append(fd) if (lambda s:(s.st_dev,s.st_ino)==expected)"
                            "(os.fstat(fd)) else None) for fd in range(3,256) "
                            "if os.path.exists('/proc/self/fd/'+str(fd))]; "
                            "raise SystemExit(9 if matches else 0)"
                        ),
                        str(capability.identity[0]),
                        str(capability.identity[1]),
                    ],
                    check=False,
                    close_fds=True,
                )
                assert check.returncode == 0
                return child_fd, capability.identity
            finally:
                await runtime.aclose()

    _child_fd, identity = anyio.run(exercise)
    environment = observed["env"]
    assert type(environment) is dict
    assert environment["ACGS_FIXTURE_STATE_DEV"] == str(identity[0])
    assert environment["ACGS_FIXTURE_STATE_INO"] == str(identity[1])
    assert not {
        "ACGS_FIXTURE_LEDGER",
        "ACGS_FIXTURE_CALL_LOG",
        "ACGS_FIXTURE_PID_FILE",
    }.intersection(environment)


def test_capability_stdio_rename_before_spawn_fails_without_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import anyio

    from gove_zone.mcp_reference import create_reference_runtime
    from gove_zone.path_capability import PathCapabilityIdentityError
    from gove_zone.proof_pack import PinnedOutputRoot

    state = tmp_path / "rename-state"
    calls = 0

    async def exercise() -> None:
        nonlocal calls
        with PinnedOutputRoot.create(state) as pinned, pinned.attest() as capability:

            def phase(phase_name: str) -> None:
                nonlocal calls
                if phase_name == "before-spawn":
                    calls += 1
                    state.rename(tmp_path / "moved-state")
                    state.mkdir(mode=0o700)

            with pytest.raises(PathCapabilityIdentityError):
                await create_reference_runtime(
                    state,
                    inbound_token="fixture-token",
                    session_id="rename-before-spawn",
                    state_capability=capability,
                    capability_phase_hook=phase,
                )

    anyio.run(exercise)
    assert calls == 1
    assert not (state / "fixture.pid").exists()


def test_capability_stdio_unsupported_platform_fails_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    import anyio

    from gove_zone.mcp_reference import create_reference_runtime
    from gove_zone.mcp_security import MCPStdioError
    from gove_zone.proof_pack import PinnedOutputRoot

    spawned = 0

    async def forbidden_spawn(*_args: object, **_kwargs: object) -> object:
        nonlocal spawned
        spawned += 1
        raise AssertionError("unsupported capability platform spawned a child")

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(anyio, "open_process", forbidden_spawn)

    async def exercise() -> None:
        state = tmp_path / "unsupported-state"
        with (
            PinnedOutputRoot.create(state) as pinned,
            pinned.attest() as capability,
            pytest.raises(MCPStdioError),
        ):
            await create_reference_runtime(
                state,
                inbound_token="fixture-token",
                session_id="unsupported-platform",
                state_capability=capability,
            )

    anyio.run(exercise)
    assert spawned == 0


def test_direct_proc_state_root_is_rejected_but_direct_path_remains_supported(
    tmp_path: Path,
) -> None:
    import anyio

    from gove_zone.mcp_reference import create_reference_runtime
    from gove_zone.proof_pack import PinnedOutputRoot

    async def exercise() -> None:
        state = tmp_path / "proc-state"
        with (
            PinnedOutputRoot.create(state) as pinned,
            pinned.attest() as capability,
            pytest.raises(RuntimeError, match="not owner-private"),
        ):
            await create_reference_runtime(
                capability.proc_path(),
                inbound_token="fixture-token",
                session_id="direct-proc-rejected",
            )
        direct = await create_reference_runtime(
            tmp_path / "direct-state",
            inbound_token="fixture-token",
            session_id="direct-still-supported",
        )
        await direct.aclose()

    anyio.run(exercise)
