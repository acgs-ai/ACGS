"""Unit tests for immutable MCP identity, catalog, and origin contracts."""

from __future__ import annotations

import dataclasses
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gove_zone.authorization import (
    STRICT_JSON_MAX_CONTAINER_LENGTH,
    STRICT_JSON_MAX_STRING_UTF8_BYTES,
)
from gove_zone.mcp_gateway import (
    MCP_APPROVE_TOOL,
    MCPDownstreamCredential,
    MCPEscalationPolicy,
    MCPGatewayConfig,
    MCPRiskClass,
    MCPSchemaError,
    MCPToolDefinition,
    MCPToolPolicy,
)
from gove_zone.mcp_identity import (
    MCPIdentityError,
    MCPIdentityPolicy,
    MCPIdentityReasonCode,
    MCPIdentityVerifier,
    MCPTokenClaims,
)
from gove_zone.mcp_security import (
    MCPOriginError,
    MCPOriginReasonCode,
    MCPOriginValidator,
    MCPStdioError,
    MCPStdioReasonCode,
    MCPStdioTargetValidator,
    ValidatedMCPOrigin,
    ValidatedMCPStdioTarget,
)

_NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _claims(**changes: object) -> MCPTokenClaims:
    values: dict[str, object] = {
        "issuer": "https://identity.example.test",
        "audiences": ("acgs-mcp-gateway",),
        "resource": "mcp://payments-server",
        "client_id": "agent-client",
        "user_id": "user-7",
        "tenant_id": "tenant-a",
        "role": "automation-agent",
        "authority": "mcp.tools.call",
        "scopes": ("tools:list", "payments:create"),
        "session_id": "session-1",
        "token_id": "token-1",
        "issued_at": _iso(_NOW - timedelta(minutes=5)),
        "expires_at": _iso(_NOW + timedelta(minutes=5)),
    }
    values.update(changes)
    return MCPTokenClaims(**values)  # type: ignore[arg-type]


class _TokenVerifier:
    def __init__(self, claims: MCPTokenClaims) -> None:
        self.claims = claims
        self.seen: list[str] = []

    def verify(self, token: str) -> MCPTokenClaims:
        self.seen.append(token)
        return self.claims


def _identity_verifier(claims: MCPTokenClaims | None = None) -> MCPIdentityVerifier:
    return MCPIdentityVerifier(
        _TokenVerifier(claims or _claims()),
        MCPIdentityPolicy(
            trusted_issuer="https://identity.example.test",
            gateway_audience="acgs-mcp-gateway",
            resource_audience="mcp://payments-server",
            allowed_clients=("agent-client",),
            allowed_tenants=("tenant-a",),
            allowed_roles=("automation-agent",),
        ),
        clock=lambda: _NOW,
    )


def test_verified_claims_become_shared_principal_without_raw_token() -> None:
    verifier = _identity_verifier()

    identity = verifier.verify(
        "inbound-secret-token",
        session_id="session-1",
        required_authority="mcp.tools.call",
        required_scopes=frozenset({"payments:create"}),
    )

    assert identity.principal.tenant_id == "tenant-a"
    assert identity.principal.actor_id == "user-7"
    assert identity.client_id == "agent-client"
    assert identity.scopes == frozenset({"tools:list", "payments:create"})
    context = dict(identity.principal.authentication_context)
    assert context["resource_audience"] == "mcp://payments-server"
    assert context["client_id"] == "agent-client"
    assert "inbound-secret-token" not in repr(context)
    assert len(str(context["token_fingerprint"])) == 64


@pytest.mark.parametrize(
    ("changes", "session", "scopes", "reason"),
    [
        (
            {"issuer": "https://evil.test"},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.ISSUER_MISMATCH,
        ),
        (
            {"audiences": ("other",)},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.AUDIENCE_MISMATCH,
        ),
        (
            {"resource": "mcp://other"},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.RESOURCE_MISMATCH,
        ),
        (
            {"client_id": "untrusted"},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.CLIENT_NOT_ALLOWED,
        ),
        (
            {"tenant_id": "tenant-b"},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.TENANT_NOT_ALLOWED,
        ),
        (
            {"role": "unknown"},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.ROLE_NOT_ALLOWED,
        ),
        ({}, "other-session", {"payments:create"}, MCPIdentityReasonCode.SESSION_MISMATCH),
        (
            {"authority": "mcp.other"},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.AUTHORITY_MISMATCH,
        ),
        ({}, "session-1", {"admin:delete"}, MCPIdentityReasonCode.SCOPE_MISSING),
        (
            {"expires_at": _iso(_NOW)},
            "session-1",
            {"payments:create"},
            MCPIdentityReasonCode.TOKEN_EXPIRED,
        ),
    ],
)
def test_claim_mismatches_fail_closed(
    changes: dict[str, object],
    session: str,
    scopes: set[str],
    reason: MCPIdentityReasonCode,
) -> None:
    verifier = _identity_verifier(_claims(**changes))

    with pytest.raises(MCPIdentityError) as raised:
        verifier.verify(
            "token",
            session_id=session,
            required_authority="mcp.tools.call",
            required_scopes=frozenset(scopes),
        )

    assert raised.value.reason_code is reason


@pytest.mark.parametrize(
    ("token", "session", "reason"),
    [
        ("", "session-1", MCPIdentityReasonCode.TOKEN_INVALID),
        (None, "session-1", MCPIdentityReasonCode.TOKEN_INVALID),
        ("token", "", MCPIdentityReasonCode.SESSION_MISMATCH),
        ("token", None, MCPIdentityReasonCode.SESSION_MISMATCH),
    ],
)
def test_malformed_token_and_session_are_structured_identity_denials(
    token: object,
    session: object,
    reason: MCPIdentityReasonCode,
) -> None:
    verifier = _identity_verifier()

    with pytest.raises(MCPIdentityError) as raised:
        verifier.verify(
            token,  # type: ignore[arg-type]
            session_id=session,  # type: ignore[arg-type]
            required_authority="mcp.tools.call",
        )

    assert raised.value.reason_code is reason


def test_origin_defaults_to_https_and_pins_public_dns() -> None:
    answers = ["8.8.8.8"]
    validator = MCPOriginValidator(resolver=lambda _host, _port: answers)

    origin = validator.validate(
        server_id="payments-server",
        url="https://mcp.example.test/v1",
    )
    validator.revalidate(origin)

    assert origin.pinned_addresses == ("8.8.8.8",)
    assert origin.test_local is False


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://mcp.example.test", MCPOriginReasonCode.TLS_REQUIRED),
        ("https://127.0.0.1", MCPOriginReasonCode.FORBIDDEN_ADDRESS),
        ("https://169.254.169.254", MCPOriginReasonCode.FORBIDDEN_ADDRESS),
        ("https://metadata.google.internal", MCPOriginReasonCode.FORBIDDEN_ADDRESS),
        ("https://user:pass@mcp.example.test", MCPOriginReasonCode.INVALID_ORIGIN),
    ],
)
def test_ssrf_and_credentialed_origin_shapes_are_rejected(
    url: str,
    reason: MCPOriginReasonCode,
) -> None:
    validator = MCPOriginValidator(
        resolver=lambda host, _port: [
            "169.254.169.254" if host == "169.254.169.254" else "127.0.0.1"
        ]
    )

    with pytest.raises(MCPOriginError) as raised:
        validator.validate(server_id="payments-server", url=url)

    assert raised.value.reason_code is reason


def test_explicit_test_local_origin_is_narrow_and_dns_rebinding_is_rejected() -> None:
    answers = ["127.0.0.1"]
    validator = MCPOriginValidator(resolver=lambda _host, _port: list(answers))
    origin = validator.validate(
        server_id="fixture-server",
        url="http://localhost:7777/mcp",
        allow_test_local=True,
    )

    answers[:] = ["10.0.0.8"]
    with pytest.raises(MCPOriginError) as raised:
        validator.revalidate(origin)

    assert raised.value.reason_code is MCPOriginReasonCode.DNS_REBINDING


def test_origin_capability_cannot_be_constructed_or_field_forged() -> None:
    with pytest.raises(TypeError, match="MCPOriginValidator"):
        ValidatedMCPOrigin(
            server_id="forged",
            url="https://mcp.example.test",
            hostname="mcp.example.test",
            port=443,
            pinned_addresses=("8.8.8.8",),
            test_local=False,
        )

    validator = MCPOriginValidator(resolver=lambda _host, _port: ["8.8.8.8"])
    origin = validator.validate(
        server_id="payments-server",
        url="https://mcp.example.test/v1",
    )
    forged = object.__new__(ValidatedMCPOrigin)
    for name, value in (
        ("server_id", origin.server_id),
        ("url", origin.url),
        ("hostname", "internal.example.test"),
        ("port", origin.port),
        ("pinned_addresses", origin.pinned_addresses),
        ("test_local", origin.test_local),
    ):
        object.__setattr__(forged, name, value)

    with pytest.raises(MCPOriginError) as raised:
        validator.reconcile(forged)

    assert raised.value.reason_code is MCPOriginReasonCode.ORIGIN_MISMATCH


def _stdio_target(tmp_path: Path) -> tuple[MCPStdioTargetValidator, ValidatedMCPStdioTarget]:
    artifact = tmp_path / "fixture_server.py"
    artifact.write_text("print('fixture')\n", encoding="utf-8")
    artifact.chmod(0o500)
    validator = MCPStdioTargetValidator()
    target = validator.validate(
        server_id="fixture-server",
        executable=str(Path(sys.executable).resolve(strict=True)),
        argv=(str(artifact.resolve()),),
        cwd=str(tmp_path),
        artifact_path=str(artifact),
        environment={"ACGS_FIXTURE_LEDGER": str(tmp_path / "ledger.jsonl")},
        instance_id="active-session-1",
    )
    return validator, target


def _fixture_artifact(tmp_path: Path) -> Path:
    artifact = tmp_path / "fixture_server.py"
    artifact.write_text("print('fixture')\n", encoding="utf-8")
    artifact.chmod(0o500)
    return artifact


def _interpreter_wrapper(tmp_path: Path, name: str = "python-wrapper") -> Path:
    wrapper = tmp_path / name
    wrapper.write_text(
        f"#!/bin/sh\nexec '{Path(sys.executable).resolve(strict=True)}' \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper


def test_stdio_target_is_validator_minted_and_binds_active_session(tmp_path: Path) -> None:
    validator, target = _stdio_target(tmp_path)

    validator.revalidate(target)
    validator.validate_response(target, transport_binding=target.transport_binding)
    assert target.executable_sha256
    assert target.executable == str(Path(sys.executable).resolve(strict=True))
    assert target.executable_owner in {0, os.geteuid()}
    assert target.executable_mode & 0o022 == 0
    assert target.executable_nlink == 1
    assert target.executable_ancestor_digest
    assert target.artifact_sha256
    assert target.artifact_ancestor_digest
    assert target.cwd_ancestor_digest
    assert target.launch_digest != target.transport_binding

    with pytest.raises(TypeError, match="MCPStdioTargetValidator"):
        ValidatedMCPStdioTarget(
            server_id=target.server_id,
            executable=target.executable,
            executable_sha256=target.executable_sha256,
            executable_device=target.executable_device,
            executable_inode=target.executable_inode,
            executable_size=target.executable_size,
            executable_owner=target.executable_owner,
            executable_mode=target.executable_mode,
            executable_nlink=target.executable_nlink,
            executable_ancestor_digest=target.executable_ancestor_digest,
            argv=target.argv,
            cwd=target.cwd,
            artifact_path=target.artifact_path,
            artifact_sha256=target.artifact_sha256,
            artifact_device=target.artifact_device,
            artifact_inode=target.artifact_inode,
            artifact_size=target.artifact_size,
            artifact_owner=target.artifact_owner,
            artifact_mode=target.artifact_mode,
            artifact_ancestor_digest=target.artifact_ancestor_digest,
            cwd_ancestor_digest=target.cwd_ancestor_digest,
            environment=target.environment,
            instance_id=target.instance_id,
            launch_digest=target.launch_digest,
            transport_binding=target.transport_binding,
        )

    forged = object.__new__(ValidatedMCPStdioTarget)
    for field in dataclasses.fields(target):
        object.__setattr__(forged, field.name, getattr(target, field.name))
    with pytest.raises(MCPStdioError) as unminted:
        MCPStdioTargetValidator().revalidate(forged)
    assert unminted.value.reason_code is MCPStdioReasonCode.SESSION_MISMATCH


@pytest.mark.parametrize("unsafe_shape", ["other-writable", "symlink", "hardlink"])
def test_stdio_target_rejects_unsafe_interpreter_path(
    tmp_path: Path,
    unsafe_shape: str,
) -> None:
    artifact = _fixture_artifact(tmp_path)
    interpreter = _interpreter_wrapper(tmp_path)
    if unsafe_shape == "other-writable":
        interpreter.chmod(0o777)
    elif unsafe_shape == "symlink":
        linked = tmp_path / "linked-python"
        linked.symlink_to(interpreter)
        interpreter = linked
    else:
        linked = tmp_path / "hardlinked-python"
        os.link(interpreter, linked)
        interpreter = linked

    with pytest.raises(MCPStdioError) as raised:
        MCPStdioTargetValidator().validate(
            server_id="fixture-server",
            executable=str(interpreter.absolute()),
            argv=(str(artifact.resolve()),),
            cwd=str(tmp_path),
            artifact_path=str(artifact.resolve()),
            environment={},
            instance_id="active-session-1",
        )

    assert raised.value.reason_code is MCPStdioReasonCode.INVALID_TARGET


def test_stdio_target_accepts_current_owner_0755_canonical_interpreter(tmp_path: Path) -> None:
    artifact = _fixture_artifact(tmp_path)
    interpreter = _interpreter_wrapper(tmp_path)

    target = MCPStdioTargetValidator().validate(
        server_id="fixture-server",
        executable=str(interpreter.resolve(strict=True)),
        argv=(str(artifact.resolve()),),
        cwd=str(tmp_path),
        artifact_path=str(artifact.resolve()),
        environment={},
        instance_id="active-session-1",
    )

    info = interpreter.stat(follow_symlinks=False)
    assert target.executable == str(interpreter)
    assert target.executable_sha256
    assert target.executable_device == info.st_dev
    assert target.executable_inode == info.st_ino
    assert target.executable_size == info.st_size
    assert target.executable_owner == os.geteuid()
    assert target.executable_mode == 0o755
    assert target.executable_nlink == 1


@pytest.mark.parametrize("mutation", ["content", "inode", "mode"])
def test_stdio_target_detects_interpreter_drift(tmp_path: Path, mutation: str) -> None:
    artifact = _fixture_artifact(tmp_path)
    interpreter = _interpreter_wrapper(tmp_path)
    validator = MCPStdioTargetValidator()
    target = validator.validate(
        server_id="fixture-server",
        executable=str(interpreter.resolve(strict=True)),
        argv=(str(artifact.resolve()),),
        cwd=str(tmp_path),
        artifact_path=str(artifact.resolve()),
        environment={},
        instance_id="active-session-1",
    )
    if mutation == "content":
        interpreter.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    elif mutation == "inode":
        replacement = _interpreter_wrapper(tmp_path, "replacement-python")
        os.replace(replacement, interpreter)
    else:
        interpreter.chmod(0o777)

    with pytest.raises(MCPStdioError) as raised:
        validator.revalidate(target)

    assert raised.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT


def test_stdio_target_rejects_private_leaf_under_nonsticky_writable_ancestor(
    tmp_path: Path,
) -> None:
    unsafe = tmp_path / "unsafe-grandparent"
    unsafe.mkdir(mode=0o700)
    private = unsafe / "private"
    private.mkdir(mode=0o700)
    unsafe.chmod(0o777)
    artifact = _fixture_artifact(private)
    interpreter = _interpreter_wrapper(private)

    with pytest.raises(MCPStdioError) as raised:
        MCPStdioTargetValidator().validate(
            server_id="fixture-server",
            executable=str(interpreter),
            argv=(str(artifact),),
            cwd=str(private),
            artifact_path=str(artifact),
            environment={},
            instance_id="active-session-1",
        )

    assert raised.value.reason_code is MCPStdioReasonCode.INVALID_TARGET


def test_stdio_target_rejects_symlink_ancestor_even_when_leaf_identity_is_safe(
    tmp_path: Path,
) -> None:
    actual = tmp_path / "actual-grandparent"
    actual.mkdir(mode=0o700)
    private = actual / "private"
    private.mkdir(mode=0o700)
    artifact = _fixture_artifact(private)
    _interpreter_wrapper(private)
    linked = tmp_path / "linked-grandparent"
    linked.symlink_to(actual, target_is_directory=True)
    linked_private = linked / "private"

    with pytest.raises(MCPStdioError) as raised:
        MCPStdioTargetValidator().validate(
            server_id="fixture-server",
            executable=str(linked_private / "python-wrapper"),
            argv=(str(linked_private / artifact.name),),
            cwd=str(linked_private),
            artifact_path=str(linked_private / artifact.name),
            environment={},
            instance_id="active-session-1",
        )

    assert raised.value.reason_code is MCPStdioReasonCode.INVALID_TARGET


def test_stdio_target_accepts_root_owned_sticky_tmp_ancestor(tmp_path: Path) -> None:
    tmp_info = os.lstat("/tmp")
    assert tmp_info.st_uid == 0
    assert stat.S_IMODE(tmp_info.st_mode) & stat.S_ISVTX
    assert Path("/tmp") in tmp_path.parents

    _validator, target = _stdio_target(tmp_path)

    assert target.executable_ancestor_digest
    assert target.artifact_ancestor_digest
    assert target.cwd_ancestor_digest


def test_stdio_target_ignores_user_owned_ancestor_link_churn(tmp_path: Path) -> None:
    validator, target = _stdio_target(tmp_path)

    before_nlink = os.lstat(tmp_path).st_nlink
    sibling = tmp_path / "ambient-sibling-directory"
    sibling.mkdir()
    assert os.lstat(tmp_path).st_nlink != before_nlink
    unchanged = validator.revalidate(target)
    assert unchanged.executable_ancestor_digest == target.executable_ancestor_digest
    assert unchanged.artifact_ancestor_digest == target.artifact_ancestor_digest
    assert unchanged.cwd_ancestor_digest == target.cwd_ancestor_digest
    assert unchanged.launch_digest == target.launch_digest

    sibling.rmdir()
    restored = validator.revalidate(target)
    assert restored.executable_ancestor_digest == target.executable_ancestor_digest
    assert restored.artifact_ancestor_digest == target.artifact_ancestor_digest
    assert restored.cwd_ancestor_digest == target.cwd_ancestor_digest
    assert restored.launch_digest == target.launch_digest


def test_stdio_target_revalidation_is_stable_during_sibling_directory_churn(
    tmp_path: Path,
) -> None:
    import threading

    validator, target = _stdio_target(tmp_path)
    barrier = threading.Barrier(2)
    stop = threading.Event()
    churn_failures: list[BaseException] = []

    def churn() -> None:
        sibling = tmp_path / "concurrent-ambient-sibling"
        try:
            barrier.wait(timeout=5)
            while not stop.is_set():
                sibling.mkdir()
                sibling.rmdir()
        except BaseException as exc:
            churn_failures.append(exc)
        finally:
            if sibling.exists():
                sibling.rmdir()

    worker = threading.Thread(target=churn, daemon=True)
    worker.start()
    barrier.wait(timeout=5)
    try:
        for _ in range(50):
            unchanged = validator.revalidate(target)
            assert unchanged.launch_digest == target.launch_digest
    finally:
        stop.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert churn_failures == []


@pytest.mark.parametrize("linked_target", ["artifact", "executable"])
def test_stdio_target_detects_post_mint_regular_file_hardlink_drift(
    tmp_path: Path,
    linked_target: str,
) -> None:
    artifact = _fixture_artifact(tmp_path)
    interpreter = _interpreter_wrapper(tmp_path)
    validator = MCPStdioTargetValidator()
    target = validator.validate(
        server_id="fixture-server",
        executable=str(interpreter.resolve(strict=True)),
        argv=(str(artifact.resolve(strict=True)),),
        cwd=str(tmp_path),
        artifact_path=str(artifact.resolve(strict=True)),
        environment={},
        instance_id="active-session-1",
    )
    source = artifact if linked_target == "artifact" else interpreter
    os.link(source, tmp_path / f"{linked_target}-additional-link")

    with pytest.raises(MCPStdioError) as raised:
        validator.revalidate(target)

    assert raised.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT


def test_stdio_target_rejects_secret_environment_and_artifact_drift(tmp_path: Path) -> None:
    artifact = tmp_path / "fixture_server.py"
    artifact.write_text("print('fixture')\n", encoding="utf-8")
    artifact.chmod(0o500)
    validator = MCPStdioTargetValidator()
    with pytest.raises(MCPStdioError) as forbidden:
        validator.validate(
            server_id="fixture-server",
            executable=str(Path(sys.executable).resolve(strict=True)),
            argv=(str(artifact.resolve()),),
            cwd=str(tmp_path),
            artifact_path=str(artifact),
            environment={"INBOUND_TOKEN": "must-not-cross"},
            instance_id="active-session-1",
        )
    assert forbidden.value.reason_code is MCPStdioReasonCode.FORBIDDEN_ENVIRONMENT

    artifact.unlink()
    _validator, target = _stdio_target(tmp_path)
    target_path = Path(target.artifact_path)
    target_path.chmod(0o700)
    target_path.write_text("print('changed')\n", encoding="utf-8")
    with pytest.raises(MCPStdioError) as drift:
        _validator.revalidate(target)
    assert drift.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT


def test_stdio_target_rejects_attested_artifact_different_from_executed_argv(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "attested.py"
    executed = tmp_path / "executed.py"
    artifact.write_text("print('attested')\n", encoding="utf-8")
    executed.write_text("print('different')\n", encoding="utf-8")
    artifact.chmod(0o500)
    executed.chmod(0o500)

    with pytest.raises(MCPStdioError) as raised:
        MCPStdioTargetValidator().validate(
            server_id="fixture-server",
            executable=str(Path(sys.executable).resolve(strict=True)),
            argv=(str(executed.resolve()),),
            cwd=str(tmp_path),
            artifact_path=str(artifact.resolve()),
            environment={},
            instance_id="active-session-1",
        )

    assert raised.value.reason_code is MCPStdioReasonCode.INVALID_TARGET


@pytest.mark.parametrize("artifact_shape", ["symlink", "hardlink", "writable"])
def test_stdio_target_rejects_nonprivate_or_mutable_artifact(
    tmp_path: Path,
    artifact_shape: str,
) -> None:
    source = tmp_path / "source.py"
    source.write_text("print('fixture')\n", encoding="utf-8")
    source.chmod(0o500)
    artifact = source
    if artifact_shape == "symlink":
        artifact = tmp_path / "linked.py"
        artifact.symlink_to(source)
    elif artifact_shape == "hardlink":
        artifact = tmp_path / "hardlinked.py"
        os.link(source, artifact)
    else:
        artifact.chmod(0o700)

    with pytest.raises(MCPStdioError) as raised:
        MCPStdioTargetValidator().validate(
            server_id="fixture-server",
            executable=str(Path(sys.executable).resolve(strict=True)),
            argv=(str(artifact.absolute()),),
            cwd=str(tmp_path),
            artifact_path=str(artifact.absolute()),
            environment={},
            instance_id="active-session-1",
        )

    assert raised.value.reason_code is MCPStdioReasonCode.INVALID_TARGET


def test_stdio_target_detects_identical_content_inode_replacement(tmp_path: Path) -> None:
    validator, target = _stdio_target(tmp_path)
    artifact = Path(target.artifact_path)
    replacement = tmp_path / "replacement.py"
    replacement.write_bytes(artifact.read_bytes())
    replacement.chmod(0o500)
    os.replace(replacement, artifact)

    with pytest.raises(MCPStdioError) as raised:
        validator.revalidate(target)

    assert raised.value.reason_code is MCPStdioReasonCode.ARTIFACT_DRIFT


def test_gateway_config_accepts_fixed_stdio_target(tmp_path: Path) -> None:
    _validator, target = _stdio_target(tmp_path)
    config = MCPGatewayConfig(origin=target, tools=(_tool_policy(_tool()),))

    assert config.origin is target
    assert config.credential_audience == "mcp://fixture-server"


def test_redirect_and_response_origin_change_are_rejected() -> None:
    validator = MCPOriginValidator(resolver=lambda _host, _port: ["127.0.0.1"])
    origin = validator.validate(
        server_id="fixture-server",
        url="http://localhost:7777/mcp",
        allow_test_local=True,
    )

    with pytest.raises(MCPOriginError) as redirected:
        validator.validate_response(
            origin,
            response_origin=origin.url,
            redirect_url="http://localhost:8888/other",
            peer_address="127.0.0.1",
        )
    with pytest.raises(MCPOriginError) as changed:
        validator.validate_response(
            origin,
            response_origin="http://localhost:8888/other",
            redirect_url=None,
            peer_address="127.0.0.1",
        )

    assert redirected.value.reason_code is MCPOriginReasonCode.REDIRECT_FORBIDDEN
    assert changed.value.reason_code is MCPOriginReasonCode.ORIGIN_MISMATCH

    with pytest.raises(MCPOriginError) as peer:
        validator.validate_response(
            origin,
            response_origin=origin.url,
            redirect_url=None,
            peer_address="127.0.0.2",
        )
    assert peer.value.reason_code is MCPOriginReasonCode.PEER_MISMATCH


def _tool(name: str = "payments.create") -> MCPToolDefinition:
    return MCPToolDefinition(
        name=name,
        description="Create one fixture payment",
        input_schema={
            "type": "object",
            "properties": {"amount": {"type": "integer"}},
            "required": ["amount"],
            "additionalProperties": False,
        },
    )


def _tool_policy(definition: MCPToolDefinition) -> MCPToolPolicy:
    return MCPToolPolicy(
        definition=definition,
        required_scopes=("payments:create",),
        downstream_scopes=("payments:execute",),
        risk_class=MCPRiskClass.HIGH,
        escalation_policy=MCPEscalationPolicy.POLICY,
        authority="mcp.tools.call",
        resource="mcp/payments",
        environment="fixture",
        side_effect_class="payment-fixture",
        policy_bundle_id="mcp-policy",
        policy_version="mcp-policy/v1",
        policy_digest="a" * 64,
    )


def test_catalog_digest_binds_name_description_and_schema() -> None:
    expected = _tool()

    assert (
        dataclasses.replace(expected, description="injected instructions").digest != expected.digest
    )
    assert dataclasses.replace(expected, name="payments.delete").digest != expected.digest
    assert dataclasses.replace(expected, input_schema={"type": "object"}).digest != expected.digest


def test_gateway_config_rejects_duplicate_tool_names() -> None:
    origin = MCPOriginValidator(resolver=lambda _host, _port: ["127.0.0.1"]).validate(
        server_id="fixture-server",
        url="http://localhost:7777/mcp",
        allow_test_local=True,
    )
    first = _tool()

    with pytest.raises(ValueError, match="unique"):
        MCPGatewayConfig(origin=origin, tools=(_tool_policy(first), _tool_policy(first)))


def test_gateway_config_rejects_reserved_human_loop_names() -> None:
    origin = MCPOriginValidator(resolver=lambda _host, _port: ["127.0.0.1"]).validate(
        server_id="fixture-server",
        url="http://localhost:7777/mcp",
        allow_test_local=True,
    )

    with pytest.raises(ValueError, match="reserved human-loop"):
        MCPGatewayConfig(origin=origin, tools=(_tool_policy(_tool(MCP_APPROVE_TOOL)),))


@pytest.mark.parametrize(
    ("risk_class", "escalation_policy"),
    [
        ("unknown", MCPEscalationPolicy.POLICY),
        (MCPRiskClass.HIGH, "caller-approved"),
        (MCPRiskClass.HIGH, MCPEscalationPolicy.NONE),
        (MCPRiskClass.CRITICAL, MCPEscalationPolicy.NONE),
    ],
)
def test_risk_and_escalation_policy_are_closed_enums_and_high_risk_is_enforced(
    risk_class: object,
    escalation_policy: object,
) -> None:
    with pytest.raises(ValueError):
        dataclasses.replace(
            _tool_policy(_tool()),
            risk_class=risk_class,  # type: ignore[arg-type]
            escalation_policy=escalation_policy,  # type: ignore[arg-type]
        )


def test_risk_and_escalation_metadata_change_authorization_binding() -> None:
    base = _tool_policy(_tool())
    medium = dataclasses.replace(
        base,
        risk_class=MCPRiskClass.MEDIUM,
        escalation_policy=MCPEscalationPolicy.NONE,
    )
    human_required = dataclasses.replace(
        base,
        escalation_policy=MCPEscalationPolicy.HUMAN_REQUIRED,
    )

    assert base.authorization_side_effect_class != medium.authorization_side_effect_class
    assert base.authorization_side_effect_class != human_required.authorization_side_effect_class


def _credential(**changes: object) -> MCPDownstreamCredential:
    values: dict[str, object] = {
        "credential_type": "fixture-api-key",
        "credential_id": "credential-1",
        "tenant_id": "tenant-a",
        "server_id": "payments-server",
        "audience": "mcp://payments-server",
        "scopes": ("payments:execute",),
        "issued_at": _iso(_NOW - timedelta(minutes=5)),
        "expires_at": _iso(_NOW + timedelta(minutes=5)),
        "secret": "downstream-only-secret",
    }
    values.update(changes)
    return MCPDownstreamCredential(**values)  # type: ignore[arg-type]


def test_downstream_credential_is_secret_safe_and_identity_bound() -> None:
    credential = _credential()

    credential.validate_for(
        tenant_id="tenant-a",
        server_id="payments-server",
        audience="mcp://payments-server",
        required_scopes=frozenset({"payments:execute"}),
        now=_NOW,
    )

    assert "downstream-only-secret" not in repr(credential)
    assert "downstream-only-secret" not in repr(credential.to_safe_dict())
    assert credential.binding_hash == credential.binding_hash


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": "tenant-b"},
        {"server_id": "other-server"},
        {"audience": "mcp://other-server"},
        {"scopes": ("catalog:read",)},
        {
            "issued_at": _iso(_NOW - timedelta(hours=2)),
            "expires_at": _iso(_NOW - timedelta(hours=1)),
        },
    ],
)
def test_downstream_credential_misissuance_fails_closed(changes: dict[str, object]) -> None:
    credential = _credential(**changes)

    with pytest.raises(RuntimeError, match="downstream_credential_mismatch"):
        credential.validate_for(
            tenant_id="tenant-a",
            server_id="payments-server",
            audience="mcp://payments-server",
            required_scopes=frozenset({"payments:execute"}),
            now=_NOW,
        )


@pytest.mark.parametrize(
    "schema",
    [
        {"type": ["object", "null"]},
        {"type": "object", "patternProperties": {}},
        {"type": "object", "properties": {"x": {"type": "string", "pattern": ".*"}}},
        {"type": "array", "items": {"type": "string"}},
    ],
)
def test_unsupported_or_non_object_tool_schema_fails_closed(schema: dict[str, object]) -> None:
    with pytest.raises(MCPSchemaError):
        MCPToolDefinition(
            name="unsupported.schema",
            description="unsupported fixture schema",
            input_schema=schema,
        )


def _deep_schema_value(depth: int) -> dict[str, Any]:
    root: dict[str, Any] = {}
    cursor = root
    for _ in range(depth):
        child: dict[str, Any] = {}
        cursor["next"] = child
        cursor = child
    return root


@pytest.mark.parametrize("depth", [32, 1_400])
def test_deep_enum_schema_values_fail_before_recursive_canonicalization(depth: int) -> None:
    schema = {
        "type": "object",
        "enum": [_deep_schema_value(depth)],
    }

    with pytest.raises(MCPSchemaError):
        MCPToolDefinition(
            name="oversized.enum",
            description="deep enum fixture",
            input_schema=schema,
        )


def test_schema_budget_rejects_cycles_large_const_and_large_containers() -> None:
    cyclic: dict[str, Any] = {"type": "object"}
    cyclic["enum"] = [cyclic]
    schemas = (
        cyclic,
        {
            "type": "object",
            "const": {"payload": "x" * (STRICT_JSON_MAX_STRING_UTF8_BYTES + 1)},
        },
        {
            "type": "object",
            "enum": [{}] * (STRICT_JSON_MAX_CONTAINER_LENGTH + 1),
        },
    )

    for index, schema in enumerate(schemas):
        with pytest.raises(MCPSchemaError):
            MCPToolDefinition(
                name=f"oversized.schema.{index}",
                description="schema budget fixture",
                input_schema=schema,
            )


def test_mcp_token_contracts_are_exported_from_package_root() -> None:
    from gove_zone import MCPTokenClaims as ExportedClaims
    from gove_zone import MCPTokenVerifier as ExportedVerifier

    assert ExportedClaims is MCPTokenClaims
    assert ExportedVerifier is not None
