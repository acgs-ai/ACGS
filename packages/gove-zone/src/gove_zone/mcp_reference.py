"""Safe fixture-only composition for the P1 MCP reference gateway."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any

from gove_zone.audit import AuditCheckpoint, AuditCheckpointAnchor, ChainHashAuditStore
from gove_zone.authorization import (
    AuthorizationReasonCode,
    EvidenceRef,
    PolicyArtifactAttestation,
    ResolvedPolicy,
    ResolvedPolicyRef,
    SideEffectAuthorization,
    SideEffectRequest,
    VerifiedPrincipal,
)
from gove_zone.consumption import (
    AnchoredConsumptionState,
    ConsumptionRecord,
    ConsumptionState,
    ConsumptionStateAnchor,
    ReceiptConsumptionStore,
)
from gove_zone.decision import Decision, DecisionRecord, canonical_json
from gove_zone.mcp_gateway import (
    MCP_TOOLS_CALL_AUTHORITY,
    MCP_TOOLS_LIST_AUTHORITY,
    MCPActionGateway,
    MCPDownstreamCredential,
    MCPEscalationPolicy,
    MCPGatewayConfig,
    MCPGatewayResponse,
    MCPGatewayStatus,
    MCPRiskClass,
    MCPToolDefinition,
    MCPToolPolicy,
)
from gove_zone.mcp_http_transport import MCPFixedHTTPTransport
from gove_zone.mcp_identity import (
    MCPIdentityPolicy,
    MCPIdentityVerifier,
    MCPPrincipalContext,
    MCPTokenClaims,
    MCPTokenVerifier,
)
from gove_zone.mcp_security import (
    MCPOriginValidator,
    MCPStdioError,
    MCPStdioTargetValidator,
    _mint_reference_fixture_http_origin,
    validate_private_state_root,
)
from gove_zone.mcp_stdio_transport import MCPFixedStdioTransport
from gove_zone.path_capability import (
    AttestedDirectory,
    is_proc_fd_path,
    require_attested_directory,
)
from gove_zone.policy import Policy, PolicyArtifactSnapshot, new_event_id
from gove_zone.receipt import Validator, safe_result_hash
from gove_zone.replay_store import ReplaySideStore
from gove_zone.side_effect_kernel import (
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)
from gove_zone.signing import Ed25519Signer, ReceiptSigner
from gove_zone.tool import ToolCall

_BINDING_KEY = b"p1-reference-binding-hmac-key-v1!!"
_CONSUMPTION_KEY = b"p1-reference-consumption-key-v1!!"
_CONSUMPTION_SNAPSHOT_DOMAIN = b"gove-zone:mcp-consumption-snapshot:v2\x00"
_CONSUMPTION_SNAPSHOT_SCHEMA = "gove-zone.mcp-consumption-snapshot/v2"
_CONSUMPTION_EVIDENCE_MODE = "signed-redacted-anchor-not-row-membership-proof"
_ACTION_CONSUMPTION_SCHEMA = "gove-zone.mcp-action-consumption-snapshot/v2"
_ACTION_CONSUMPTION_DOMAIN = b"gove-zone:mcp-action-consumption-wrapper:v2\x00"
_GATEWAY_EXCHANGE_DOMAIN = b"gove-zone:mcp-gateway-exchange:v2\x00"
_NORMAL_OUTCOME_RECORD_ID = "protocol-normal"
MCP_REFERENCE_POLICY_VERSION = "mcp-reference-policy/v1"
MCP_REFERENCE_POLICY_BUNDLE_ID = "mcp-reference-policy"
MCP_REFERENCE_POLICY_RESOLVER_ID = "mcp-reference-policy-resolver"
_ACTION_CONSUMPTION_RECORD_KEYS = frozenset(
    {
        "event_id",
        "outcome_record_id",
        "receipt_id",
        "receipt_hash",
        "state",
        "result_digest",
        "audit_event_hash",
        "tenant_id",
        "actor",
        "governed_operation",
        "authority",
        "downstream_tool",
        "arguments_hash",
    }
)
_MAX_IDENTIFIER_BYTES = 512
_MAX_PATH_BYTES = 4096
_MAX_POLICY_ARTIFACT_BYTES = 1_048_576
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ED25519_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
_HTTP_REFERENCE_FACTORY_TOKEN = object()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _public_text(value: str, name: str, *, max_bytes: int = _MAX_IDENTIFIER_BYTES) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty canonical string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be valid UTF-8") from None
    if len(encoded) > max_bytes:
        raise ValueError(f"{name} exceeds its byte limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{name} contains a control character")
    return value


def _sha256_text(value: str, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be 64 lowercase SHA-256 hex characters")
    return value


def _canonical_public_path(value: Path, name: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise ValueError(f"{name} must be an absolute pathlib.Path")
    try:
        encoded = os.fsencode(value)
        resolved = value.resolve(strict=False)
    except (OSError, UnicodeEncodeError, ValueError):
        raise ValueError(f"{name} must be a canonical absolute path") from None
    if len(encoded) > _MAX_PATH_BYTES:
        raise ValueError(f"{name} exceeds its byte limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in str(value)):
        raise ValueError(f"{name} contains a control character")
    if value != resolved:
        raise ValueError(f"{name} must be a canonical absolute path")
    return value


def _proof_sources_digest(sources: MCPProofSources) -> str:
    return hashlib.sha256(canonical_json(sources.to_dict()).encode("utf-8")).hexdigest()


def _json_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(dict(value)).encode("utf-8")).hexdigest()


def _private_fixture_copy(
    directory: Path,
    source: Path,
    capability: AttestedDirectory | None = None,
) -> Path:
    """Create the exact non-writable script executed by the reference child.

    This establishes a private same-host gateway-owner boundary. It is not an
    OS attestation guarantee against another process running as the same user.
    """

    private = directory / ".mcp-private"
    try:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        cloexec = getattr(os, "O_CLOEXEC", None)
        if nofollow is None or cloexec is None:
            raise OSError("secure local open flags are unavailable")
        private_capability = (
            capability.subdirectory(".mcp-private", create=True) if capability is not None else None
        )
        if private_capability is None:
            private.mkdir(mode=0o700, parents=False, exist_ok=True)
            info = private.stat(follow_symlinks=False)
        else:
            private_capability.checkpoint()
            info = os.fstat(private_capability.root_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (private_capability is None and private.resolve(strict=True) != private)
        ):
            raise OSError("private fixture directory is not owner-only")
        if private_capability is None:
            validate_private_state_root(private)
        artifact = private / f"fixture-{secrets.token_hex(16)}.py"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | cloexec | nofollow
        descriptor = (
            private_capability.open_file(artifact.name, flags, 0o500)
            if private_capability is not None
            else os.open(artifact, flags, 0o500)
        )
        try:
            content = source.read_bytes()
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o500)
        finally:
            os.close(descriptor)
    except OSError:
        raise RuntimeError("private fixture artifact creation failed") from None
    return artifact


class MCPReferencePolicy(Policy):
    """Canonical deterministic policy shared by runtime and offline proof replay."""

    @property
    def version(self) -> str:
        return MCP_REFERENCE_POLICY_VERSION

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        return PolicyArtifactSnapshot.from_artifact(
            {"decision": "allow", "version": self.version},
            evaluator=create_reference_policy(),
        )

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("MCP_REFERENCE_ALLOW",),
            reason="fixture-only reference policy",
        )


def create_reference_policy() -> MCPReferencePolicy:
    """Return the sole reference-policy implementation used by P1 proof paths."""

    return MCPReferencePolicy()


# Compatibility alias for existing local integrations; this is the same class,
# not a second policy implementation.
_ReferencePolicy = MCPReferencePolicy


class _PolicyResolver:
    def __init__(self, resolved: ResolvedPolicy) -> None:
        self._resolved = resolved

    def resolve(self, principal: VerifiedPrincipal) -> ResolvedPolicy:
        if principal.tenant_id != self._resolved.ref.tenant_id:
            raise RuntimeError("tenant policy is unavailable")
        return self._resolved


class _TokenVerifier:
    """Fixture-only static token verifier.

    This authenticates nothing: it compares an inbound string to a string this
    process minted.  It exists so the local proof path can run without a signing
    authority, and :class:`~gove_zone.mcp_runtime.RemoteMCPConfig` refuses it for
    any public bind.  For remote workload identity use
    :class:`~gove_zone.mcp_identity.EdDSAJWSVerifier` instead.
    """

    def __init__(self, token: str, claims: MCPTokenClaims) -> None:
        self._registry: dict[str, MCPTokenClaims] = {token: claims}

    @classmethod
    def from_registry(cls, registry: Mapping[str, MCPTokenClaims]) -> _TokenVerifier:
        """Build a verifier over several distinct fixture identities.

        Distinct tokens must map to distinct claims so that, for example, the
        readiness probe's health identity cannot be confused with the agent's.
        """

        if not registry:
            raise ValueError("token registry must not be empty")
        verifier = cls.__new__(cls)
        verifier._registry = dict(registry)
        return verifier

    def verify(self, token: str) -> MCPTokenClaims:
        claims = self._registry.get(token)
        if claims is None:
            raise ValueError("token rejected")
        return claims


#: Scope that admits a tool's *metadata* into tools/list without admitting a call.
#: Holding it lets an identity see ``fixture.read`` in the catalog; calling that
#: tool additionally needs ``mcp.tools.call`` authority and ``fixture:read``.
FIXTURE_CATALOG_SCOPE = "fixture:catalog"

#: The readiness probe's dedicated identity.  Its separation from the agent is
#: the *signed authority*: the probe's token says ``mcp.tools.list``, so the
#: gateway refuses tools/call for it before policy, kernel or adapter -- no
#: tenant, scope or policy arrangement can make it a caller.  Tenant separation
#: and the absent ``fixture:write`` scope remain as defence in depth.
HEALTH_TENANT_ID = "fixture-health-tenant"
HEALTH_CLIENT_ID = "fixture-health-client"
HEALTH_ROLE = "readiness-probe"
HEALTH_SESSION_ID = "fixture-health-session"
#: The exact catalog the health identity's scopes admit.  A poisoned, colliding,
#: empty, or otherwise altered catalog will not equal this.
HEALTH_EXPECTED_TOOLS: tuple[str, ...] = ("fixture.read",)


def _health_claims(now: datetime, tenant_id: str = HEALTH_TENANT_ID) -> MCPTokenClaims:
    """Build the readiness probe's claims.

    ``tenant_id`` defaults to the probe's own tenant.  The fixed-credential HTTP
    path cannot use that -- its transport pins one credential to one tenant -- so
    that path passes the agent's tenant.  Either way the probe is not a caller:
    its signed authority is ``mcp.tools.list``, which tools/call rejects outright.
    See :func:`create_reference_http_gateway`.
    """

    return MCPTokenClaims(
        issuer="https://identity.fixture.invalid",
        audiences=("acgs-mcp-gateway",),
        resource="mcp://fixture-server",
        client_id=HEALTH_CLIENT_ID,
        user_id="fixture-health-probe",
        tenant_id=tenant_id,
        role=HEALTH_ROLE,
        # Signed for listing only.  This is what stops the readiness credential
        # from being a confused deputy: no fixture:read, no mcp.tools.call.
        authority=MCP_TOOLS_LIST_AUTHORITY,
        # tools:list to reach the catalog, fixture:catalog to see the read-only
        # tool's metadata.  Neither scope can authorize any tools/call.
        scopes=("tools:list", FIXTURE_CATALOG_SCOPE),
        session_id=HEALTH_SESSION_ID,
        token_id="fixture-health-token-id",  # noqa: S106 - identifier, not token material
        issued_at=_iso(now - timedelta(minutes=1)),
        expires_at=_iso(now + timedelta(hours=1)),
    )


class _CredentialProvider:
    def __init__(
        self,
        now: datetime,
        credential: MCPDownstreamCredential | None = None,
    ) -> None:
        self._issued_at = _iso(now - timedelta(minutes=1))
        self._expires_at = _iso(now + timedelta(hours=1))
        self._credential = credential

    def get_credential(self, server_id: str, tenant_id: str) -> MCPDownstreamCredential:
        if self._credential is not None:
            # A fixed credential is pinned to one tenant on purpose: the HTTP
            # transport compares the credential's binding hash against the one it
            # was constructed with, so re-binding it to another tenant here would
            # only be rejected downstream -- and weakening that pin to allow it
            # would trade a real isolation property for a readiness convenience.
            return self._credential
        return MCPDownstreamCredential(
            credential_type="fixture-capability",
            credential_id="fixture-downstream-credential",
            tenant_id=tenant_id,
            server_id=server_id,
            audience="mcp://fixture-server",
            scopes=("fixture:read", "fixture:write"),
            issued_at=self._issued_at,
            expires_at=self._expires_at,
            secret="fixture-downstream-secret",  # noqa: S106 - inert local fixture value
        )


class MCPReferenceHTTPGateway:
    """Receipt-gated, fixture-only HTTP reference lifecycle."""

    __slots__ = ("_transport", "gateway")

    def __init__(
        self,
        *,
        _gateway: MCPActionGateway,
        _transport: MCPFixedHTTPTransport,
        _factory_token: object,
    ) -> None:
        if _factory_token is not _HTTP_REFERENCE_FACTORY_TOKEN:
            raise TypeError("MCPReferenceHTTPGateway must be created by its reference factory")
        self.gateway = _gateway
        self._transport = _transport

    def __repr__(self) -> str:
        return "MCPReferenceHTTPGateway(fixture_only=True)"

    async def aclose(self) -> None:
        await self._transport.aclose()

    async def __aenter__(self) -> MCPReferenceHTTPGateway:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


async def create_reference_http_gateway(
    state_dir: Path,
    *,
    inbound_token: str,
    session_id: str,
    validator: MCPOriginValidator,
    downstream_credential: MCPDownstreamCredential,
    adapter_timeout: float = 2.0,
    health_token: str | None = None,
    token_verifier: MCPTokenVerifier | None = None,
) -> MCPReferenceHTTPGateway:
    """Compose the existing unified kernel around one pinned HTTP transport.

    ``health_token`` registers the readiness probe's dedicated identity; see
    :data:`HEALTH_TENANT_ID`.

    ``token_verifier`` replaces the fixture static verifier with a real one --
    in practice :class:`~gove_zone.mcp_identity.EdDSAJWSVerifier`.  When it is
    supplied, ``inbound_token``/``health_token`` are not registered as accepted
    strings at all; they are only used to *drive* the gateway from this process,
    and the verifier alone decides whether they authenticate anyone.
    """

    if not isinstance(validator, MCPOriginValidator):
        raise TypeError("validator must be an MCPOriginValidator")
    if not isinstance(downstream_credential, MCPDownstreamCredential):
        raise TypeError("downstream_credential must be an MCPDownstreamCredential")
    origin = _mint_reference_fixture_http_origin(validator=validator)
    directory = state_dir.expanduser()
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    try:
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        directory = validate_private_state_root(directory)
    except (OSError, MCPStdioError):
        raise RuntimeError("reference state root is not owner-private") from None

    transport = MCPFixedHTTPTransport(
        validator=validator,
        origin=origin,
        credential=downstream_credential,
        timeout_seconds=adapter_timeout,
    )
    await transport.start()
    try:
        now = datetime.now(UTC)
        claims = MCPTokenClaims(
            issuer="https://identity.fixture.invalid",
            audiences=("acgs-mcp-gateway",),
            resource="mcp://fixture-server",
            client_id="fixture-agent-client",
            user_id="fixture-agent",
            tenant_id="fixture-tenant",
            role="automation-agent",
            authority="mcp.tools.call",
            scopes=("tools:list", FIXTURE_CATALOG_SCOPE, "fixture:read", "fixture:write"),
            session_id=session_id,
            token_id="fixture-token-id",  # noqa: S106 - identifier, not token material
            issued_at=_iso(now - timedelta(minutes=1)),
            expires_at=_iso(now + timedelta(hours=1)),
        )
        registry = {inbound_token: claims}
        allowed_clients = ["fixture-agent-client"]
        allowed_tenants = ["fixture-tenant"]
        allowed_roles = ["automation-agent"]
        if health_token is not None:
            if health_token == inbound_token:
                raise ValueError("the health identity must not reuse the agent token")
            # This path pins one downstream credential to one tenant, so the
            # probe must live in that tenant.  Its scopes still exclude
            # fixture:write, so it cannot reach the high-risk write tool.
            registry[health_token] = _health_claims(now, claims.tenant_id)
            allowed_clients.append(HEALTH_CLIENT_ID)
            allowed_roles.append(HEALTH_ROLE)
        identity_verifier = MCPIdentityVerifier(
            token_verifier
            if token_verifier is not None
            else _TokenVerifier.from_registry(registry),
            MCPIdentityPolicy(
                trusted_issuer="https://identity.fixture.invalid",
                gateway_audience="acgs-mcp-gateway",
                resource_audience="mcp://fixture-server",
                allowed_clients=tuple(allowed_clients),
                allowed_tenants=tuple(allowed_tenants),
                allowed_roles=tuple(allowed_roles),
            ),
        )
        principal_context = MCPPrincipalContext()
        policy = create_reference_policy()
        snapshot = policy.authorization_snapshot()
        ref = ResolvedPolicyRef(
            tenant_id=claims.tenant_id,
            bundle_id=MCP_REFERENCE_POLICY_BUNDLE_ID,
            version=snapshot.policy_version,
            digest=snapshot.digest,
        )
        resolved = ResolvedPolicy(
            ref=ref,
            policy=policy,
            attestation=PolicyArtifactAttestation(
                tenant_id=ref.tenant_id,
                artifact_id=ref.bundle_id,
                policy_version=ref.version,
                digest=ref.digest,
                resolver_id=MCP_REFERENCE_POLICY_RESOLVER_ID,
            ),
            validator=Validator("fixture-security-approver", "approver"),
            authority=claims.authority,
        )
        policy_resolver = _PolicyResolver(resolved)
        signer = Ed25519Signer.generate("mcp-reference-http-receipt-key")
        audit = ChainHashAuditStore(
            directory / "audit.jsonl",
            checkpoint_anchor=_AuditAnchor(),
            checkpoint_namespace="mcp-reference:http-container",
            checkpoint_signer=signer,
            checkpoint_verifier={signer.key_id: signer},
            require_trusted_checkpoint=True,
        )
        replay_store = _RequiredReplaySideStore(directory / "replay.jsonl")
        consumption = ReceiptConsumptionStore(
            directory / "consumption.sqlite3",
            hmac_key=_CONSUMPTION_KEY,
            state_anchor=_ConsumptionAnchor(),
            anchor_namespace="mcp-reference:http-container",
            require_trusted_anchor=True,
        )
        authorizer = _ReplayRequiredAuthorizationKernel(
            required_side_store=replay_store,
            principal_resolver=principal_context,
            policy_resolver=policy_resolver,
            audit=audit,
            signer=signer,
            binding_hmac_key=_BINDING_KEY,
            allowed_validator_roles=("approver",),
        )
        # Lifecycle provenance is signed by a key and authority that are
        # distinct from the audit checkpoint, so re-checkpointing the chain
        # cannot manufacture an execution_lifecycle record.
        lifecycle_signer = Ed25519Signer.generate("mcp-reference-http-lifecycle-key")
        executor = ReceiptGatedSideEffectExecutor(
            principal_resolver=principal_context,
            policy_resolver=policy_resolver,
            audit=audit,
            consumption_store=consumption,
            verifier=signer,
            lifecycle_signer=lifecycle_signer,
            lifecycle_authority_id="mcp-reference-http-execution-validator",
            binding_hmac_key=_BINDING_KEY,
            allowed_validator_roles=("approver",),
            adapter_timeout=adapter_timeout,
        )
        definitions = (
            _definition(
                "fixture.write_once", "Append one sanitized fixture record", arguments=True
            ),
            _definition("fixture.read", "Read the local fixture ledger", arguments=False),
        )

        def tool_policy(definition: MCPToolDefinition, scope: str) -> MCPToolPolicy:
            write = scope == "fixture:write"
            return MCPToolPolicy(
                definition=definition,
                required_scopes=(scope,),
                downstream_scopes=(scope,),
                # The read-only tool is visible to any catalog reader; the
                # write tool stays visible only to holders of fixture:write.
                catalog_scopes=(scope,) if write else (FIXTURE_CATALOG_SCOPE,),
                risk_class=MCPRiskClass.HIGH if write else MCPRiskClass.LOW,
                escalation_policy=(
                    MCPEscalationPolicy.POLICY if write else MCPEscalationPolicy.NONE
                ),
                authority=MCP_TOOLS_CALL_AUTHORITY,
                resource=f"mcp/{definition.name}",
                environment="container-fixture",
                side_effect_class="fixture-write" if write else "fixture-read",
                policy_bundle_id=ref.bundle_id,
                policy_version=ref.version,
                policy_digest=ref.digest,
            )

        config = MCPGatewayConfig(
            origin=origin,
            tools=(
                tool_policy(definitions[0], "fixture:write"),
                tool_policy(definitions[1], "fixture:read"),
            ),
        )
        gateway = MCPActionGateway(
            config=config,
            identity_verifier=identity_verifier,
            principal_context=principal_context,
            origin_validator=validator,
            credential_provider=_CredentialProvider(now, downstream_credential),
            transport=transport,
            authorizer=authorizer,
            executor=executor,
            consumption_store=consumption,
        )
    except BaseException:
        await transport.aclose()
        raise
    return MCPReferenceHTTPGateway(
        _gateway=gateway,
        _transport=transport,
        _factory_token=_HTTP_REFERENCE_FACTORY_TOKEN,
    )


class _AuditAnchor(AuditCheckpointAnchor):
    def __init__(self) -> None:
        self._values: dict[str, AuditCheckpoint] = {}
        self._lock = threading.Lock()

    def read(self, namespace: str) -> AuditCheckpoint | None:
        with self._lock:
            return self._values.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool:
        with self._lock:
            if self._values.get(namespace) != expected:
                return False
            self._values[namespace] = replacement
            return True


class _ConsumptionAnchor(ConsumptionStateAnchor):
    def __init__(self) -> None:
        self._values: dict[str, AnchoredConsumptionState] = {}
        self._lock = threading.Lock()

    def read(self, namespace: str) -> AnchoredConsumptionState | None:
        with self._lock:
            return self._values.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AnchoredConsumptionState | None,
        replacement: AnchoredConsumptionState,
    ) -> bool:
        with self._lock:
            if self._values.get(namespace) != expected:
                return False
            self._values[namespace] = replacement
            return True


class _RequiredReplaySideStore(ReplaySideStore):
    """Replay store whose authorizer requires an exact post-append record.

    The generic kernel keeps its historical best-effort side-store behavior.
    This deployable reference profile is stricter: issuance is rejected before
    the adapter boundary unless the just-audited decision can be read back from
    the durable replay file with its exact decision bindings.
    """

    def __init__(
        self,
        path: Path,
        *,
        redact: Any | None = None,
        _attested_directory: AttestedDirectory | None = None,
        _attested_relative: str | None = None,
    ) -> None:
        super().__init__(
            path,
            redact=redact,
            _attested_directory=_attested_directory,
            _attested_relative=_attested_relative,
        )
        self._failed_event_ids: set[str] = set()
        self._lock = threading.Lock()

    def append(self, call: ToolCall, record: DecisionRecord) -> dict[str, Any]:
        with self._lock:
            try:
                entry = super().append(call, record)
            except Exception:
                self._failed_event_ids.add(record.event_id)
                raise
            self._failed_event_ids.discard(record.event_id)
        return entry

    def require_committed(self, authorization: SideEffectAuthorization) -> None:
        with self._lock:
            failed = authorization.audit_event_id in self._failed_event_ids
            entry = super().get(authorization.audit_event_id)
        receipt = authorization.receipt
        if (
            failed
            or entry is None
            or entry.get("redacted") is True
            or entry.get("event_id") != authorization.audit_event_id
            or entry.get("decision") != authorization.decision.value
            or entry.get("argument_hash") != authorization.original_arguments_hash
            or entry.get("policy_version") != authorization.reserved_binding["policy"]["version"]
            or entry.get("tool") != authorization.reserved_binding["operation"]
            or (authorization.executable and receipt is None)
        ):
            raise RuntimeError("required replay decision was not durably committed")


class _ReplayRequiredAuthorizationKernel(SideEffectAuthorizationKernel):
    """Reference-profile kernel that fail-closes missing replay evidence."""

    def __init__(self, *, required_side_store: _RequiredReplaySideStore, **kwargs: Any) -> None:
        super().__init__(side_store=required_side_store, **kwargs)
        self._required_side_store = required_side_store

    def authorize(self, request: SideEffectRequest) -> SideEffectAuthorization:
        authorization = super().authorize(request)
        try:
            self._required_side_store.require_committed(authorization)
        except Exception:
            self._raise_refusal(
                AuthorizationReasonCode.AUDIT_FAILED,
                request,
                principal_verified=True,
            )
        return authorization


@dataclass(frozen=True, slots=True)
class MCPPublicVerificationKey:
    """Public-only verification material for one proof purpose."""

    purpose: str
    key_id: str
    algorithm: str
    public_bytes: bytes

    def __post_init__(self) -> None:
        _public_text(self.purpose, "public key purpose")
        _public_text(self.key_id, "public key id")
        if self.algorithm != "ed25519":
            raise ValueError("MCP public verification key metadata is invalid")
        if type(self.public_bytes) is not bytes or len(self.public_bytes) != 32:
            raise ValueError("MCP Ed25519 public key must contain exactly 32 bytes")

    def to_dict(self) -> dict[str, str]:
        return {
            "purpose": self.purpose,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_bytes_hex": self.public_bytes.hex(),
        }


@dataclass(frozen=True, slots=True)
class MCPProofSources:
    """Frozen public snapshot of the reference runtime's proof inputs.

    This object contains paths, immutable identifiers, policy bytes, and public
    keys only. Mutable stores, anchors, signers, credentials, and authorization
    capabilities remain on the live runtime and are never serialized here.
    """

    audit_path: Path
    audit_namespace: str
    replay_path: Path
    consumption_path: Path
    consumption_namespace: str
    policy_artifact: str
    policy_attestation: PolicyArtifactAttestation
    policy_digest: str
    policy_version: str
    fixture_ledger_path: Path
    fixture_call_log_path: Path
    target_instance_id: str
    target_server_id: str
    target_launch_digest: str
    target_transport_binding: str
    target_artifact_path: Path
    target_artifact_digest: str
    tenant_id: str
    receipt_key: MCPPublicVerificationKey
    refusal_key: MCPPublicVerificationKey
    checkpoint_key: MCPPublicVerificationKey
    consumption_key: MCPPublicVerificationKey
    exchange_key: MCPPublicVerificationKey
    lifecycle_key: MCPPublicVerificationKey
    lifecycle_authority_id: str

    def __post_init__(self) -> None:
        paths = {
            "audit_path": self.audit_path,
            "replay_path": self.replay_path,
            "consumption_path": self.consumption_path,
            "fixture_ledger_path": self.fixture_ledger_path,
            "fixture_call_log_path": self.fixture_call_log_path,
            "target_artifact_path": self.target_artifact_path,
        }
        for name, path_value in paths.items():
            _canonical_public_path(path_value, name)

        state_root = self.audit_path.parent
        expected_state_paths = {
            "audit_path": state_root / "audit.jsonl",
            "replay_path": state_root / "replay.jsonl",
            "consumption_path": state_root / "consumption.sqlite3",
            "fixture_ledger_path": state_root / "fixture-ledger.jsonl",
            "fixture_call_log_path": state_root / "fixture-calls.jsonl",
        }
        for name, expected in expected_state_paths.items():
            if paths[name] != expected:
                raise ValueError(f"{name} is outside its canonical reference-state boundary")
        if self.target_artifact_path.parent != state_root / ".mcp-private":
            raise ValueError("target_artifact_path is outside the private fixture boundary")

        for name, text_value in (
            ("audit_namespace", self.audit_namespace),
            ("consumption_namespace", self.consumption_namespace),
            ("policy_version", self.policy_version),
            ("target_instance_id", self.target_instance_id),
            ("target_server_id", self.target_server_id),
            ("tenant_id", self.tenant_id),
            ("lifecycle_authority_id", self.lifecycle_authority_id),
        ):
            _public_text(text_value, name)
        if self.audit_namespace not in {
            f"mcp-reference:{self.audit_path}",
            "mcp-proof:normal",
            "mcp-proof:poison",
        }:
            raise ValueError("audit_namespace is not a canonical reference/proof namespace")
        if self.consumption_namespace != f"mcp-reference:{self.consumption_path}":
            raise ValueError("consumption_namespace does not bind the canonical consumption path")

        for name, digest_value in (
            ("policy_digest", self.policy_digest),
            ("target_launch_digest", self.target_launch_digest),
            ("target_transport_binding", self.target_transport_binding),
            ("target_artifact_digest", self.target_artifact_digest),
        ):
            _sha256_text(digest_value, name)

        if type(self.policy_artifact) is not str or not self.policy_artifact:
            raise ValueError("policy_artifact must be a non-empty canonical JSON object")
        try:
            policy_bytes = self.policy_artifact.encode("utf-8")
            policy_value = json.loads(self.policy_artifact)
        except (TypeError, UnicodeEncodeError, ValueError):
            raise ValueError("policy_artifact must be valid canonical JSON") from None
        if len(policy_bytes) > _MAX_POLICY_ARTIFACT_BYTES:
            raise ValueError("policy_artifact exceeds its byte limit")
        if (
            not isinstance(policy_value, dict)
            or canonical_json(policy_value) != self.policy_artifact
        ):
            raise ValueError("policy_artifact must be a canonical JSON object")
        if hashlib.sha256(policy_bytes).hexdigest() != self.policy_digest:
            raise ValueError("policy_digest does not match policy_artifact")
        if type(self.policy_attestation) is not PolicyArtifactAttestation:
            raise ValueError("policy_attestation must be a PolicyArtifactAttestation")
        expected_attestation = PolicyArtifactAttestation(
            tenant_id=self.tenant_id,
            artifact_id=MCP_REFERENCE_POLICY_BUNDLE_ID,
            policy_version=self.policy_version,
            digest=self.policy_digest,
            resolver_id=MCP_REFERENCE_POLICY_RESOLVER_ID,
        )
        if self.policy_attestation != expected_attestation:
            raise ValueError("policy_attestation does not bind the reference policy artifact")

        expected_purposes = {
            "receipt_key": (self.receipt_key, "receipt"),
            "refusal_key": (self.refusal_key, "refusal"),
            "checkpoint_key": (self.checkpoint_key, "audit-checkpoint"),
            "consumption_key": (self.consumption_key, "consumption-snapshot"),
            "exchange_key": (self.exchange_key, "gateway-exchange"),
            "lifecycle_key": (self.lifecycle_key, "lifecycle-attestation"),
        }
        for name, (key, purpose) in expected_purposes.items():
            if type(key) is not MCPPublicVerificationKey or key.purpose != purpose:
                raise ValueError(f"{name} has the wrong public proof purpose")

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_path": str(self.audit_path),
            "audit_namespace": self.audit_namespace,
            "replay_path": str(self.replay_path),
            "consumption_path": str(self.consumption_path),
            "consumption_namespace": self.consumption_namespace,
            "policy_artifact": self.policy_artifact,
            "policy_attestation": self.policy_attestation.to_dict(),
            "policy_digest": self.policy_digest,
            "policy_version": self.policy_version,
            "fixture_ledger_path": str(self.fixture_ledger_path),
            "fixture_call_log_path": str(self.fixture_call_log_path),
            "target_instance_id": self.target_instance_id,
            "target_server_id": self.target_server_id,
            "target_launch_digest": self.target_launch_digest,
            "target_transport_binding": self.target_transport_binding,
            "target_artifact_path": str(self.target_artifact_path),
            "target_artifact_digest": self.target_artifact_digest,
            "tenant_id": self.tenant_id,
            "receipt_key": self.receipt_key.to_dict(),
            "refusal_key": self.refusal_key.to_dict(),
            "checkpoint_key": self.checkpoint_key.to_dict(),
            "consumption_key": self.consumption_key.to_dict(),
            "exchange_key": self.exchange_key.to_dict(),
            "lifecycle_key": self.lifecycle_key.to_dict(),
            "lifecycle_authority_id": self.lifecycle_authority_id,
        }


@dataclass(frozen=True, slots=True)
class MCPSignedConsumptionSnapshot:
    """Signed redacted anchor state; never a row-membership proof."""

    tenant_id: str
    anchor_namespace: str
    store_id: str
    generation: int
    chain_head: str
    state_root: str
    key_id: str
    algorithm: str
    signature: str
    schema: str = _CONSUMPTION_SNAPSHOT_SCHEMA
    evidence_mode: str = _CONSUMPTION_EVIDENCE_MODE

    def __post_init__(self) -> None:
        _public_text(self.tenant_id, "snapshot tenant_id")
        _public_text(self.anchor_namespace, "snapshot anchor_namespace")
        _sha256_text(self.store_id, "snapshot store_id")
        if type(self.generation) is not int or self.generation < 0:
            raise ValueError("snapshot generation must be a non-negative integer")
        _sha256_text(self.chain_head, "snapshot chain_head")
        _sha256_text(self.state_root, "snapshot state_root")
        _public_text(self.key_id, "snapshot key_id")
        if self.algorithm != "ed25519":
            raise ValueError("snapshot algorithm must be ed25519")
        if (
            type(self.signature) is not str
            or _ED25519_SIGNATURE_RE.fullmatch(self.signature) is None
        ):
            raise ValueError("snapshot signature must be 128 lowercase Ed25519 hex characters")
        if self.schema != _CONSUMPTION_SNAPSHOT_SCHEMA:
            raise ValueError("snapshot schema is not supported")
        if self.evidence_mode != _CONSUMPTION_EVIDENCE_MODE:
            raise ValueError("snapshot evidence mode is not supported")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "tenant_id": self.tenant_id,
            "anchor_namespace": self.anchor_namespace,
            "store_id": self.store_id,
            "generation": self.generation,
            "chain_head": self.chain_head,
            "state_root": self.state_root,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "evidence_mode": self.evidence_mode,
        }

    def signing_payload(self) -> bytes:
        return _CONSUMPTION_SNAPSHOT_DOMAIN + canonical_json(self._unsigned_dict()).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "signature": self.signature}


@dataclass(frozen=True, slots=True)
class MCPActionConsumptionEvidence:
    """Immutable public-safe row-bound consumption wrapper for proof export."""

    lane: str
    event_ids: tuple[str, ...]
    outcome_record_ids: tuple[str, ...]
    anchor_namespace: str
    store_id: str
    generation: int
    chain_head: str
    state_root: str
    key_purpose: str
    key_id: str
    snapshot: MCPSignedConsumptionSnapshot
    records: tuple[Mapping[str, str], ...]
    tenant_id: str
    policy_version: str
    policy_digest: str
    target: Mapping[str, str]
    outer_algorithm: str
    outer_signature: str
    schema: str = _ACTION_CONSUMPTION_SCHEMA

    def __post_init__(self) -> None:
        if self.lane not in {"normal", "poison"}:
            raise ValueError("consumption evidence lane is not supported")
        if self.schema != _ACTION_CONSUMPTION_SCHEMA:
            raise ValueError("consumption evidence schema is not supported")
        for name, value in (
            ("anchor_namespace", self.anchor_namespace),
            ("key_purpose", self.key_purpose),
            ("key_id", self.key_id),
            ("tenant_id", self.tenant_id),
            ("policy_version", self.policy_version),
        ):
            _public_text(value, f"consumption evidence {name}", max_bytes=256)
        for name, value in (
            ("store_id", self.store_id),
            ("chain_head", self.chain_head),
            ("state_root", self.state_root),
            ("policy_digest", self.policy_digest),
        ):
            _sha256_text(value, f"consumption evidence {name}")
        if type(self.generation) is not int or self.generation < 0:
            raise ValueError("consumption evidence generation is invalid")
        if self.outer_algorithm != "ed25519":
            raise ValueError("consumption evidence outer algorithm is invalid")
        if _ED25519_SIGNATURE_RE.fullmatch(self.outer_signature) is None:
            raise ValueError("consumption evidence outer signature is invalid")
        if self.snapshot.to_dict() != {
            **self.snapshot._unsigned_dict(),
            "signature": self.snapshot.signature,
        }:
            raise ValueError("consumption evidence snapshot is not canonical")
        target = dict(self.target)
        if set(target) != {
            "server_digest",
            "launch_digest",
            "transport_digest",
            "artifact_digest",
        }:
            raise ValueError("consumption evidence target binding is invalid")
        for name, value in target.items():
            _sha256_text(value, f"consumption evidence target.{name}")
        frozen_records: list[Mapping[str, str]] = []
        for record in self.records:
            plain = dict(record)
            if set(plain) != _ACTION_CONSUMPTION_RECORD_KEYS or any(
                type(value) is not str for value in plain.values()
            ):
                raise ValueError("consumption evidence record is not canonical")
            frozen_records.append(MappingProxyType(plain))
        object.__setattr__(self, "records", tuple(frozen_records))
        object.__setattr__(self, "target", MappingProxyType(target))
        if (
            self.key_purpose != "consumption-snapshot"
            or self.snapshot.tenant_id != self.tenant_id
            or self.snapshot.anchor_namespace != self.anchor_namespace
            or self.snapshot.store_id != self.store_id
            or self.snapshot.generation != self.generation
            or self.snapshot.chain_head != self.chain_head
            or self.snapshot.state_root != self.state_root
            or self.snapshot.key_id != self.key_id
            or self.snapshot.algorithm != self.outer_algorithm
        ):
            raise ValueError("consumption evidence snapshot binding is invalid")
        if self.lane == "normal":
            if (
                self.generation != 2
                or len(self.event_ids) != 1
                or len(self.outcome_record_ids) != 1
                or len(self.records) != 1
                or self.records[0]["event_id"] != self.event_ids[0]
                or self.records[0]["outcome_record_id"] != self.outcome_record_ids[0]
            ):
                raise ValueError("normal consumption evidence coverage is invalid")
        elif self.generation != 0 or self.event_ids or self.outcome_record_ids or self.records:
            raise ValueError("poison consumption evidence coverage is invalid")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "target": dict(self.target),
            "schema": self.schema,
            "lane": self.lane,
            "event_ids": list(self.event_ids),
            "outcome_record_ids": list(self.outcome_record_ids),
            "anchor_namespace": self.anchor_namespace,
            "store_id": self.store_id,
            "generation": self.generation,
            "chain_head": self.chain_head,
            "state_root": self.state_root,
            "key_purpose": self.key_purpose,
            "key_id": self.key_id,
            "snapshot": self.snapshot.to_dict(),
            "records": [dict(record) for record in self.records],
            "outer_algorithm": self.outer_algorithm,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the exact plain-JSON wrapper consumed by ``mcp_proof``."""
        return {**self._unsigned_dict(), "outer_signature": self.outer_signature}


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


def _regular_file_identity(
    path: Path,
    label: str,
    capability: AttestedDirectory | None = None,
) -> _FileIdentity:
    try:
        if capability is None:
            info = path.stat(follow_symlinks=False)
        else:
            descriptor = capability.open_file(
                capability.relative_from_display(path),
                os.O_RDONLY,
            )
            try:
                info = os.fstat(descriptor)
            finally:
                os.close(descriptor)
    except OSError:
        raise RuntimeError(f"MCP {label} proof source is unavailable") from None
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or path.resolve(strict=True) != path:
        raise RuntimeError(f"MCP {label} proof source is not a canonical regular file")
    return _FileIdentity(
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
    )


@dataclass(frozen=True, slots=True)
class _MCPExecutionOutcomeRecord:
    response: MCPGatewayResponse = field(repr=False, compare=False)
    response_identity: int
    opaque_token: str
    response_binding_digest: str
    request_id: str
    event_id: str
    receipt_id: str
    receipt_hash: str
    outcome_record_id: str
    adapter_result_digest: str
    payload_digest: str
    downstream_call_digest: str
    tenant_id: str
    actor: str
    governed_operation: str
    authority: str
    downstream_tool: str
    arguments_hash: str
    audit_event_hash: str
    audit_file_identity: _FileIdentity
    replay_file_identity: _FileIdentity

    def consumption_record(self) -> dict[str, str]:
        return {
            "event_id": self.event_id,
            "outcome_record_id": self.outcome_record_id,
            "receipt_id": self.receipt_id,
            "receipt_hash": self.receipt_hash,
            "state": ConsumptionState.SUCCEEDED.value,
            "result_digest": self.payload_digest,
            "audit_event_hash": self.audit_event_hash,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "governed_operation": self.governed_operation,
            "authority": self.authority,
            "downstream_tool": self.downstream_tool,
            "arguments_hash": self.arguments_hash,
        }


@dataclass(frozen=True, slots=True)
class MCPGatewayExchangeEvidence:
    """Signed, public-safe binding to one exact gateway response exchange."""

    values: Mapping[str, Any]

    def __post_init__(self) -> None:
        plain = dict(self.values)
        if type(self.values) is not dict or type(plain.get("signature")) is not str:
            raise ValueError("gateway exchange evidence is not canonical")
        object.__setattr__(self, "values", MappingProxyType(plain))

    def to_dict(self) -> dict[str, Any]:
        return dict(self.values)


@dataclass(frozen=True, slots=True)
class _MCPGatewayExchangeRecord:
    response: MCPGatewayResponse = field(repr=False, compare=False)
    response_identity: int
    response_binding_digest: str
    evidence: MCPGatewayExchangeEvidence


@dataclass(frozen=True, slots=True)
class _MCPGatewayResponseRecord:
    response: MCPGatewayResponse = field(repr=False, compare=False)
    response_identity: int
    request_id: str
    response_binding_digest: str


def _response_binding_digest(response: MCPGatewayResponse) -> str:
    receipt = response.receipt
    return _json_digest(
        {
            "request_id": response.request_id,
            "decision": response.decision.value,
            "status": response.status.value,
            "reason_codes": list(response.reason_codes),
            "retryable": response.retryable,
            "executed": response.executed,
            "outcome_unknown": response.outcome_unknown,
            "payload_digest": safe_result_hash(response.payload),
            "receipt_id": receipt.receipt_id if receipt is not None else "",
            "receipt_hash": receipt.receipt_hash if receipt is not None else "",
            "audit_event_id": response.audit_event_id,
            "approved_arguments_digest": _json_digest(dict(response.approved_arguments)),
        }
    )


class _MCPExecutionOutcomeSink:
    """Private gateway-owned record of the exact successful response object."""

    def __init__(
        self,
        *,
        audit_path: Path,
        replay_path: Path,
        signer: ReceiptSigner,
        exchange_key: MCPPublicVerificationKey,
        proof_lane: str | None,
        tenant_id: str,
        policy_version: str,
        policy_digest: str,
        target: Mapping[str, str],
        state_capability: AttestedDirectory | None = None,
    ) -> None:
        self._audit_path = audit_path
        self._replay_path = replay_path
        self._signer = signer
        self._exchange_key = exchange_key
        self._proof_lane = proof_lane
        self._tenant_id = tenant_id
        self._policy_version = policy_version
        self._policy_digest = policy_digest
        self._target = dict(target)
        self._state_capability = state_capability
        self._records: dict[int, _MCPExecutionOutcomeRecord] = {}
        self._exchanges: dict[int, _MCPGatewayExchangeRecord] = {}
        self._responses_by_identity: dict[int, _MCPGatewayResponseRecord] = {}
        self._responses_by_request_id: dict[str, _MCPGatewayResponseRecord] = {}
        self._lock = threading.Lock()

    def capture(
        self,
        response: MCPGatewayResponse,
        *,
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> None:
        if type(request_id) is not str or response.request_id != request_id:
            raise RuntimeError("MCP gateway response request binding is invalid")
        response_record = _MCPGatewayResponseRecord(
            response=response,
            response_identity=id(response),
            request_id=request_id,
            response_binding_digest=_response_binding_digest(response),
        )
        with self._lock:
            if (
                id(response) in self._responses_by_identity
                or request_id in self._responses_by_request_id
            ):
                raise RuntimeError("MCP gateway response request ID or identity was reused")
            self._responses_by_identity[id(response)] = response_record
            self._responses_by_request_id[request_id] = response_record
        self._capture_exchange(
            response,
            request_id=request_id,
            downstream_tool=tool_name,
            arguments=arguments,
        )
        if (
            response.status is not MCPGatewayStatus.SUCCEEDED
            or response.decision is not Decision.ALLOW
            or response.executed is not True
            or response.retryable is not False
            or response.outcome_unknown is not False
            or response.receipt is None
        ):
            return
        receipt = response.receipt
        payload_digest = safe_result_hash(response.payload)
        downstream_call_digest = _json_digest(
            {
                "method": "tools/call",
                "request_id": request_id,
                "tool_name": tool_name,
                "arguments": dict(arguments),
            }
        )
        adapter_result_digest = _json_digest(
            {
                "status": response.status.value,
                "payload_digest": payload_digest,
                "event_id": response.audit_event_id,
            }
        )
        record = _MCPExecutionOutcomeRecord(
            response=response,
            response_identity=id(response),
            opaque_token=secrets.token_hex(32),
            response_binding_digest=_response_binding_digest(response),
            request_id=request_id,
            event_id=response.audit_event_id,
            receipt_id=receipt.receipt_id,
            receipt_hash=receipt.receipt_hash,
            outcome_record_id=_NORMAL_OUTCOME_RECORD_ID,
            adapter_result_digest=adapter_result_digest,
            payload_digest=payload_digest,
            downstream_call_digest=downstream_call_digest,
            tenant_id=receipt.tenant_id,
            actor=receipt.actor,
            governed_operation=receipt.proposed_action,
            authority=receipt.authority,
            downstream_tool=tool_name,
            arguments_hash=receipt.argument_hash,
            audit_event_hash=receipt.audit_event_hash,
            audit_file_identity=_regular_file_identity(
                self._audit_path, "audit", self._state_capability
            ),
            replay_file_identity=_regular_file_identity(
                self._replay_path, "replay", self._state_capability
            ),
        )
        with self._lock:
            if id(response) in self._records:
                raise RuntimeError("MCP execution outcome response identity was reused")
            self._records[id(response)] = record

    def require_response(self, request_id: str) -> MCPGatewayResponse:
        canonical_request_id = _public_text(request_id, "MCP gateway request_id")
        with self._lock:
            record = self._responses_by_request_id.get(canonical_request_id)
            identity_record = (
                self._responses_by_identity.get(record.response_identity)
                if record is not None
                else None
            )
        if record is None:
            raise RuntimeError("MCP gateway response request ID is unknown")
        response = record.response
        try:
            binding_digest = _response_binding_digest(response)
        except Exception:
            raise RuntimeError("MCP gateway response was modified after capture") from None
        if (
            identity_record is not record
            or response is not identity_record.response
            or id(response) != record.response_identity
            or response.request_id != canonical_request_id
            or record.request_id != canonical_request_id
        ):
            raise RuntimeError("MCP gateway response request binding is invalid")
        if record.response_binding_digest != binding_digest:
            raise RuntimeError("MCP gateway response was modified after capture")
        return response

    def _capture_exchange(
        self,
        response: MCPGatewayResponse,
        *,
        request_id: str,
        downstream_tool: str,
        arguments: Mapping[str, Any],
    ) -> None:
        lane = self._proof_lane
        if lane is None:
            return
        refusal = response.refusal_evidence
        receipt = response.receipt
        if lane == "normal":
            valid = (
                response.status is MCPGatewayStatus.SUCCEEDED
                and response.decision is Decision.ALLOW
                and response.executed is True
                and receipt is not None
                and refusal is None
            )
            actor = receipt.actor if receipt is not None else ""
            evidence_kind = "receipt"
            key_purpose = "gateway-exchange"
            result_digest = safe_result_hash(response.payload)
            downstream_call_count = 1
            side_effect_write_count = 1
        else:
            valid = (
                response.status is MCPGatewayStatus.DENIED
                and response.decision is Decision.DENY
                and response.executed is False
                and receipt is None
                and refusal is not None
                and response.reason_codes == ("mcp.gateway.catalog_mismatch",)
            )
            actor = refusal.claimed_actor_id if refusal is not None else ""
            evidence_kind = "refusal"
            key_purpose = "gateway-exchange"
            result_digest = ""
            downstream_call_count = 0
            side_effect_write_count = 0
        if not valid or response.retryable or response.outcome_unknown:
            raise RuntimeError(f"{lane} proof lane received an incompatible gateway response")
        arguments_hash = hashlib.sha256(canonical_json(dict(arguments)).encode("utf-8")).hexdigest()
        governed_operation = "tools/call"
        authority = "mcp.tools.call"
        attempt_digest = _json_digest(
            {
                "request_id": request_id,
                "governed_operation": governed_operation,
                "authority": authority,
                "downstream_tool": downstream_tool,
                "arguments_hash": arguments_hash,
            }
        )
        downstream_call_digest = (
            _json_digest(
                {
                    "method": governed_operation,
                    "request_id": request_id,
                    "tool_name": downstream_tool,
                    "arguments": dict(arguments),
                }
            )
            if lane == "normal"
            else ""
        )
        unsigned: dict[str, Any] = {
            "record_id": f"protocol-{lane}",
            "lane": lane,
            "event_id": response.audit_event_id,
            "decision_id": response.audit_event_id,
            "request_id": request_id,
            "actor": actor,
            "decision": response.decision.name,
            "status": "succeeded" if lane == "normal" else "refused",
            "executed": response.executed,
            "retryable": response.retryable,
            "outcome_unknown": response.outcome_unknown,
            "downstream_call_count": downstream_call_count,
            "side_effect_write_count": side_effect_write_count,
            "governed_operation": governed_operation,
            "authority": authority,
            "downstream_tool": downstream_tool,
            "arguments_hash": arguments_hash,
            "attempt_digest": attempt_digest,
            "downstream_call_digest": downstream_call_digest,
            "result_digest": result_digest,
            "evidence_kind": evidence_kind,
            "evidence_id": response.audit_event_id,
            "tenant_id": self._tenant_id,
            "policy_version": self._policy_version,
            "policy_digest": self._policy_digest,
            "target": dict(self._target),
            "signature_purpose": key_purpose,
            "signature_key_id": self._exchange_key.key_id,
            "signature_algorithm": self._exchange_key.algorithm,
        }
        signature = self._signer.sign(
            _GATEWAY_EXCHANGE_DOMAIN + canonical_json(unsigned).encode("utf-8")
        )
        evidence = MCPGatewayExchangeEvidence({**unsigned, "signature": signature})
        record = _MCPGatewayExchangeRecord(
            response=response,
            response_identity=id(response),
            response_binding_digest=_response_binding_digest(response),
            evidence=evidence,
        )
        with self._lock:
            if id(response) in self._exchanges:
                raise RuntimeError("MCP gateway exchange response identity was reused")
            self._exchanges[id(response)] = record

    def require(
        self,
        response: MCPGatewayResponse,
        *,
        outcome_record_id: str,
    ) -> _MCPExecutionOutcomeRecord:
        with self._lock:
            record = self._records.get(id(response))
        try:
            binding_digest = _response_binding_digest(response)
        except Exception:
            raise RuntimeError("MCP gateway response was modified after execution") from None
        if (
            record is None
            or record.response is not response
            or record.response_identity != id(response)
            or record.outcome_record_id != outcome_record_id
            or record.response_binding_digest != binding_digest
            or not record.opaque_token
        ):
            raise RuntimeError("MCP gateway response is not the captured execution outcome")
        return record

    def require_exchange(self, response: MCPGatewayResponse) -> MCPGatewayExchangeEvidence:
        with self._lock:
            record = self._exchanges.get(id(response))
        if (
            record is None
            or record.response is not response
            or record.response_identity != id(response)
            or record.response_binding_digest != _response_binding_digest(response)
        ):
            raise RuntimeError("MCP gateway response is not the captured proof exchange")
        return record.evidence


class _OutcomeCapturingMCPActionGateway(MCPActionGateway):
    def __init__(self, *, outcome_sink: _MCPExecutionOutcomeSink, **kwargs: Any) -> None:
        self._outcome_sink = outcome_sink
        super().__init__(**kwargs)

    def call_tool(
        self,
        *,
        inbound_token: str,
        session_id: str,
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        nonce: str,
        idempotency_key: str,
        requested_at: str,
        observed_at: str,
        evidence: tuple[EvidenceRef, ...] = (),
        goal: str = "",
    ) -> MCPGatewayResponse:
        response = super().call_tool(
            inbound_token=inbound_token,
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
            arguments=arguments,
            nonce=nonce,
            idempotency_key=idempotency_key,
            requested_at=requested_at,
            observed_at=observed_at,
            evidence=evidence,
            goal=goal,
        )
        self._outcome_sink.capture(
            response,
            request_id=request_id,
            tool_name=tool_name,
            arguments=arguments,
        )
        return response


@dataclass(frozen=True, slots=True)
class _MCPRuntimeTrustCapsule:
    gateway: MCPActionGateway = field(repr=False)
    transport: MCPFixedStdioTransport = field(repr=False)
    audit: ChainHashAuditStore = field(repr=False)
    audit_anchor: AuditCheckpointAnchor = field(repr=False)
    replay_store: ReplaySideStore = field(repr=False)
    consumption_store: ReceiptConsumptionStore = field(repr=False)
    consumption_anchor: ConsumptionStateAnchor = field(repr=False)
    consumption_signer: ReceiptSigner = field(repr=False)
    outcome_sink: _MCPExecutionOutcomeSink = field(repr=False)
    proof_sources: MCPProofSources = field(repr=False)
    proof_sources_digest: str
    state_dir: Path
    tenant_id: str
    audit_namespace: str
    consumption_namespace: str
    audit_path: Path
    replay_path: Path
    consumption_path: Path
    consumption_key: MCPPublicVerificationKey
    policy_version: str
    policy_digest: str
    target_server_digest: str
    target_launch_digest: str
    target_transport_digest: str
    target_artifact_digest: str


def _trust_capsule_digest(capsule: _MCPRuntimeTrustCapsule) -> str:
    return _json_digest(
        {
            "gateway_identity": id(capsule.gateway),
            "transport_identity": id(capsule.transport),
            "audit_identity": id(capsule.audit),
            "audit_anchor_identity": id(capsule.audit_anchor),
            "replay_store_identity": id(capsule.replay_store),
            "consumption_store_identity": id(capsule.consumption_store),
            "consumption_anchor_identity": id(capsule.consumption_anchor),
            "consumption_signer_identity": id(capsule.consumption_signer),
            "outcome_sink_identity": id(capsule.outcome_sink),
            "proof_sources_identity": id(capsule.proof_sources),
            "proof_sources_digest": capsule.proof_sources_digest,
            "state_dir": str(capsule.state_dir),
            "tenant_id": capsule.tenant_id,
            "audit_namespace": capsule.audit_namespace,
            "consumption_namespace": capsule.consumption_namespace,
            "audit_path": str(capsule.audit_path),
            "replay_path": str(capsule.replay_path),
            "consumption_path": str(capsule.consumption_path),
            "consumption_key": capsule.consumption_key.to_dict(),
            "policy_version": capsule.policy_version,
            "policy_digest": capsule.policy_digest,
            "target_server_digest": capsule.target_server_digest,
            "target_launch_digest": capsule.target_launch_digest,
            "target_transport_digest": capsule.target_transport_digest,
            "target_artifact_digest": capsule.target_artifact_digest,
        }
    )


def _definition(name: str, description: str, *, arguments: bool) -> MCPToolDefinition:
    schema: dict[str, Any]
    if arguments:
        schema = {
            "type": "object",
            "properties": {"record": {"type": "string", "maxLength": 256}},
            "required": ["record"],
            "additionalProperties": False,
        }
    else:
        schema = {"type": "object", "additionalProperties": False}
    return MCPToolDefinition(name=name, description=description, input_schema=schema)


@dataclass(frozen=True, slots=True)
class MCPReferenceRuntime:
    """Live reference components sharing one receipt-gated kernel."""

    gateway: MCPActionGateway
    transport: MCPFixedStdioTransport
    audit: ChainHashAuditStore
    session_id: str
    state_dir: Path
    _proof_sources: MCPProofSources = field(repr=False)
    _proof_sources_digest: str = field(repr=False)
    _canonical_tenant_id: str = field(repr=False)
    _canonical_audit_namespace: str = field(repr=False)
    _canonical_consumption_namespace: str = field(repr=False)
    _canonical_audit_path: Path = field(repr=False)
    _canonical_consumption_path: Path = field(repr=False)
    _audit_anchor: AuditCheckpointAnchor = field(repr=False)
    _replay_store: ReplaySideStore = field(repr=False)
    _consumption_store: ReceiptConsumptionStore = field(repr=False)
    _consumption_anchor: ConsumptionStateAnchor = field(repr=False)
    _consumption_signer: ReceiptSigner = field(repr=False)
    _outcome_sink: _MCPExecutionOutcomeSink = field(repr=False)
    _canonical_consumption_key: MCPPublicVerificationKey = field(repr=False)
    _canonical_policy_version: str = field(repr=False)
    _canonical_policy_digest: str = field(repr=False)
    _canonical_target_server_digest: str = field(repr=False)
    _canonical_target_launch_digest: str = field(repr=False)
    _canonical_target_transport_digest: str = field(repr=False)
    _canonical_target_artifact_digest: str = field(repr=False)
    _trust_capsule: _MCPRuntimeTrustCapsule = field(repr=False)
    _trust_capsule_digest: str = field(repr=False)
    _state_capability: AttestedDirectory | None = field(default=None, repr=False)
    _consumption_store_identity: int = field(init=False, repr=False)
    _consumption_anchor_identity: int = field(init=False, repr=False)
    _consumption_signer_identity: int = field(init=False, repr=False)
    _trust_capsule_identity: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self._state_capability is not None:
            require_attested_directory(self._state_capability, error_type=ValueError)
            self._state_capability.checkpoint()
            if self._state_capability.display_path != self.state_dir:
                raise ValueError("runtime state capability does not match state_dir")
        if type(self._proof_sources) is not MCPProofSources:
            raise TypeError("proof_sources must be an MCPProofSources snapshot")
        if self._proof_sources_digest != _proof_sources_digest(self._proof_sources):
            raise ValueError("proof_sources digest does not match its canonical public snapshot")
        if (
            self._canonical_tenant_id != self._proof_sources.tenant_id
            or self._canonical_audit_namespace != self._proof_sources.audit_namespace
            or self._canonical_consumption_namespace != self._proof_sources.consumption_namespace
            or self._canonical_audit_path != self._proof_sources.audit_path
            or self._canonical_consumption_path != self._proof_sources.consumption_path
        ):
            raise ValueError("runtime trust roots do not match the canonical proof sources")
        if self.audit.path != self._canonical_audit_path:
            raise ValueError("runtime audit store does not match its canonical proof path")
        if self._consumption_store.path != self._canonical_consumption_path:
            raise ValueError("runtime consumption store does not match its canonical proof path")
        if (
            self._canonical_policy_version != self._proof_sources.policy_version
            or self._canonical_policy_digest != self._proof_sources.policy_digest
            or self._canonical_target_launch_digest != self._proof_sources.target_launch_digest
            or self._canonical_target_transport_digest
            != self._proof_sources.target_transport_binding
            or self._canonical_target_artifact_digest != self._proof_sources.target_artifact_digest
            or self._canonical_target_server_digest
            != hashlib.sha256(self._proof_sources.target_server_id.encode("utf-8")).hexdigest()
            or self._canonical_consumption_key != self._proof_sources.consumption_key
        ):
            raise ValueError("runtime private trust roots do not match the public proof snapshot")
        object.__setattr__(self, "_consumption_store_identity", id(self._consumption_store))
        object.__setattr__(self, "_consumption_anchor_identity", id(self._consumption_anchor))
        object.__setattr__(self, "_consumption_signer_identity", id(self._consumption_signer))
        object.__setattr__(self, "_trust_capsule_identity", id(self._trust_capsule))
        self._validate_capture_trust_roots()

    def _validate_capture_trust_roots(self) -> _MCPRuntimeTrustCapsule:
        if self._state_capability is not None:
            self._state_capability.checkpoint()
        capsule = self._trust_capsule
        try:
            source_digest = _proof_sources_digest(capsule.proof_sources)
            capsule_digest = _trust_capsule_digest(capsule)
            target = capsule.transport.target
            server_digest = hashlib.sha256(target.server_id.encode("utf-8")).hexdigest()
        except Exception:
            raise RuntimeError("MCP capture trust-root capsule was modified") from None
        if (
            id(capsule) != self._trust_capsule_identity
            or capsule_digest != self._trust_capsule_digest
            or source_digest != capsule.proof_sources_digest
            or self.gateway is not capsule.gateway
            or self.transport is not capsule.transport
            or self.audit is not capsule.audit
            or self.state_dir != capsule.state_dir
            or self._proof_sources is not capsule.proof_sources
            or self._proof_sources_digest != capsule.proof_sources_digest
            or self._audit_anchor is not capsule.audit_anchor
            or self._replay_store is not capsule.replay_store
            or self._consumption_store is not capsule.consumption_store
            or self._consumption_anchor is not capsule.consumption_anchor
            or self._consumption_signer is not capsule.consumption_signer
            or self._outcome_sink is not capsule.outcome_sink
            or self._canonical_tenant_id != capsule.tenant_id
            or self._canonical_audit_namespace != capsule.audit_namespace
            or self._canonical_consumption_namespace != capsule.consumption_namespace
            or self._canonical_audit_path != capsule.audit_path
            or self._canonical_consumption_path != capsule.consumption_path
            or self._canonical_consumption_key != capsule.consumption_key
            or self._canonical_policy_version != capsule.policy_version
            or self._canonical_policy_digest != capsule.policy_digest
            or self._canonical_target_server_digest != capsule.target_server_digest
            or self._canonical_target_launch_digest != capsule.target_launch_digest
            or self._canonical_target_transport_digest != capsule.target_transport_digest
            or self._canonical_target_artifact_digest != capsule.target_artifact_digest
            or capsule.audit.path != capsule.audit_path
            or capsule.replay_store.path != capsule.replay_path
            or capsule.consumption_store.path != capsule.consumption_path
            or target.server_id != capsule.proof_sources.target_server_id
            or server_digest != capsule.target_server_digest
            or target.launch_digest != capsule.target_launch_digest
            or target.transport_binding != capsule.target_transport_digest
            or target.artifact_sha256 != capsule.target_artifact_digest
            or Path(target.artifact_path) != capsule.proof_sources.target_artifact_path
            or capsule.proof_sources.audit_path != capsule.audit_path
            or capsule.proof_sources.replay_path != capsule.replay_path
            or capsule.proof_sources.consumption_path != capsule.consumption_path
            or capsule.proof_sources.tenant_id != capsule.tenant_id
            or capsule.proof_sources.policy_version != capsule.policy_version
            or capsule.proof_sources.policy_digest != capsule.policy_digest
            or capsule.proof_sources.consumption_key != capsule.consumption_key
        ):
            raise RuntimeError("MCP capture trust-root capability or pin was replaced")
        return capsule

    @staticmethod
    def _pinned_consumption_verifier(
        signer: ReceiptSigner,
        key: MCPPublicVerificationKey,
    ) -> Ed25519Signer:
        if not isinstance(signer, Ed25519Signer):
            raise RuntimeError("MCP consumption signer has the wrong proof purpose")
        verifier = Ed25519Signer.from_public_bytes(key.public_bytes, key_id=key.key_id)
        private_key = signer._private_key
        if (
            key.purpose != "consumption-snapshot"
            or signer.key_id != key.key_id
            or signer.algorithm != key.algorithm
            or signer.public_bytes() != key.public_bytes
            or private_key is None
            or Ed25519Signer(private_key=private_key, key_id=key.key_id).public_bytes()
            != key.public_bytes
        ):
            raise RuntimeError("MCP consumption signer has the wrong proof purpose")
        return verifier

    @property
    def proof_sources(self) -> MCPProofSources:
        """Return the construction-time public snapshot after tamper detection."""
        try:
            current_digest = _proof_sources_digest(self._proof_sources)
        except Exception:
            raise RuntimeError("MCP public proof-source snapshot was modified") from None
        if current_digest != self._proof_sources_digest:
            raise RuntimeError("MCP public proof-source snapshot was modified")
        return self._proof_sources

    @property
    def replay_store(self) -> ReplaySideStore:
        """Return the caller-owned replay source without exposing a signer."""
        return self._replay_store

    @property
    def consumption_store(self) -> ReceiptConsumptionStore:
        """Return the caller-owned schema-v4 consumption store."""
        return self._consumption_store

    @property
    def audit_anchor(self) -> AuditCheckpointAnchor:
        """Return the caller-owned audit anchor capability."""
        return self._audit_anchor

    @property
    def consumption_anchor(self) -> ConsumptionStateAnchor:
        """Return the caller-owned consumption anchor capability."""
        return self._consumption_anchor

    def public_snapshot(self) -> MCPProofSources:
        """Return the frozen, public-only proof-source snapshot."""
        return self.proof_sources

    def require_gateway_response(self, request_id: str) -> MCPGatewayResponse:
        """Return the exact captured response object for one unique request ID."""

        capsule = self._validate_capture_trust_roots()
        return capsule.outcome_sink.require_response(request_id)

    def capture_gateway_exchange(self, response: MCPGatewayResponse) -> MCPGatewayExchangeEvidence:
        """Return the signed row for the exact response object owned by this gateway."""
        capsule = self._validate_capture_trust_roots()
        evidence = capsule.outcome_sink.require_exchange(response)
        values = evidence.to_dict()
        signature = values.pop("signature")
        verifier = Ed25519Signer.from_public_bytes(
            capsule.proof_sources.exchange_key.public_bytes,
            key_id=capsule.proof_sources.exchange_key.key_id,
        )
        if (
            values.get("signature_purpose") != capsule.proof_sources.exchange_key.purpose
            or values.get("signature_key_id") != capsule.proof_sources.exchange_key.key_id
            or values.get("signature_algorithm") != capsule.proof_sources.exchange_key.algorithm
            or type(signature) is not str
            or not verifier.verify(
                _GATEWAY_EXCHANGE_DOMAIN + canonical_json(values).encode("utf-8"), signature
            )
        ):
            raise RuntimeError("MCP gateway exchange signature is not pinned to this runtime")
        return evidence

    def seal_current_audit_checkpoint(self) -> AuditCheckpoint:
        """Return the current internally signed checkpoint after strict verification."""
        before = self._audit_anchor.read(self._canonical_audit_namespace)
        report = self.audit.verify_checkpointed_chain()
        checkpoint = self._audit_anchor.read(self._canonical_audit_namespace)
        if (
            not report.get("valid")
            or before is None
            or checkpoint is None
            or checkpoint != before
            or checkpoint.namespace != self._canonical_audit_namespace
            or checkpoint.to_dict() != report.get("checkpoint")
        ):
            raise RuntimeError("current MCP audit checkpoint is not strictly verified")
        return checkpoint

    def signed_consumption_snapshot(self) -> MCPSignedConsumptionSnapshot:
        """Sign the current redacted schema-v4 anchor without exposing rows or keys."""
        namespace = self._canonical_consumption_namespace
        before = self._consumption_anchor.read(namespace)
        if before is None or not self._consumption_store.strict_integrity_ready:
            raise RuntimeError("MCP consumption state is not strictly verified")
        verified = self._consumption_anchor.read(namespace)
        if verified is None or verified != before:
            raise RuntimeError("MCP consumption anchor changed during strict verification")
        unsigned = MCPSignedConsumptionSnapshot(
            tenant_id=self._canonical_tenant_id,
            anchor_namespace=namespace,
            store_id=verified.store_id,
            generation=verified.generation,
            chain_head=verified.chain_head,
            state_root=verified.state_root,
            key_id=self._consumption_signer.key_id,
            algorithm=self._consumption_signer.algorithm,
            signature="0" * 128,
        )
        signature = self._consumption_signer.sign(unsigned.signing_payload())
        snapshot = MCPSignedConsumptionSnapshot(
            tenant_id=unsigned.tenant_id,
            anchor_namespace=unsigned.anchor_namespace,
            store_id=unsigned.store_id,
            generation=unsigned.generation,
            chain_head=unsigned.chain_head,
            state_root=unsigned.state_root,
            key_id=unsigned.key_id,
            algorithm=unsigned.algorithm,
            signature=signature,
        )
        after = self._consumption_anchor.read(namespace)
        if after != verified or not self._consumption_store.strict_integrity_ready:
            raise RuntimeError("MCP consumption state changed while it was signed")
        final = self._consumption_anchor.read(namespace)
        if final != verified:
            raise RuntimeError("MCP consumption anchor changed after strict verification")
        return snapshot

    def capture_consumption_evidence(
        self,
        lane: str,
        *,
        response: MCPGatewayResponse | None,
        outcome_record_id: str | None,
        records: Sequence[Mapping[str, Any]],
    ) -> MCPActionConsumptionEvidence:
        """Capture exact row-bound proof evidence without exposing live trust roots.

        ``normal`` accepts one caller-supplied public record and independently
        binds it to a successful gateway response, its receipt/audit/replay
        evidence, and the dedicated generation-2 terminal store row. ``poison``
        accepts only an empty record set on a fresh generation-0 store.
        """
        if lane not in {"normal", "poison"}:
            raise ValueError("consumption evidence lane must be normal or poison")
        if type(records) not in (list, tuple):
            raise TypeError("consumption evidence records must be a list or tuple")
        if lane == "poison" and (
            response is not None or outcome_record_id is not None or len(records) != 0
        ):
            raise ValueError("poison consumption evidence requires an empty fresh lane")
        capsule = self._validate_capture_trust_roots()
        key = capsule.consumption_key
        signer = capsule.consumption_signer
        verifier = self._pinned_consumption_verifier(signer, key)

        namespace = self._canonical_consumption_namespace
        evidence_namespace = f"mcp-proof-consumption:{lane}"
        before = self._consumption_anchor.read(namespace)
        if before is None or not self._consumption_store.strict_integrity_ready:
            raise RuntimeError("MCP consumption state is not strictly verified")
        verified = self._consumption_anchor.read(namespace)
        if verified != before:
            raise RuntimeError("MCP consumption anchor changed during evidence capture")
        expected_generation = 2 if lane == "normal" else 0
        if verified.generation != expected_generation:
            raise RuntimeError("MCP consumption state is not a dedicated lane lifecycle")
        record_values: tuple[dict[str, str], ...]
        event_ids: tuple[str, ...]
        outcome_ids: tuple[str, ...]
        captured_result_digest: str | None = None
        outcome_before: _MCPExecutionOutcomeRecord | None = None
        terminal_before: ConsumptionRecord | None = None
        audit_before: dict[str, Any] | None = None
        replay_before: dict[str, Any] | None = None
        if lane == "normal":
            if type(response) is not MCPGatewayResponse:
                raise TypeError("normal consumption evidence requires an exact gateway response")
            if type(outcome_record_id) is not str:
                raise TypeError("normal consumption evidence requires an outcome record id")
            outcome_id = _public_text(
                outcome_record_id, "consumption outcome_record_id", max_bytes=256
            )
            outcome_before = capsule.outcome_sink.require(
                response,
                outcome_record_id=outcome_id,
            )
            if (
                _regular_file_identity(capsule.audit_path, "audit")
                != outcome_before.audit_file_identity
                or _regular_file_identity(capsule.replay_path, "replay")
                != outcome_before.replay_file_identity
            ):
                raise RuntimeError("MCP audit or replay proof source changed after execution")
            for name, digest in (
                ("adapter_result_digest", outcome_before.adapter_result_digest),
                ("payload_digest", outcome_before.payload_digest),
                ("downstream_call_digest", outcome_before.downstream_call_digest),
            ):
                _sha256_text(digest, f"captured outcome {name}")
            if len(records) != 1 or type(records[0]) is not dict:
                raise ValueError("normal consumption evidence requires exactly one exact record")
            record = dict(records[0])
            if set(record) != _ACTION_CONSUMPTION_RECORD_KEYS or any(
                type(value) is not str for value in record.values()
            ):
                raise ValueError("normal consumption evidence record shape is invalid")
            typed_record = {name: str(record[name]) for name in _ACTION_CONSUMPTION_RECORD_KEYS}
            receipt = response.receipt
            if receipt is None:
                raise RuntimeError("normal consumption evidence requires terminal success")
            result_digest = outcome_before.payload_digest
            captured_result_digest = result_digest
            expected = outcome_before.consumption_record()
            if typed_record != expected or outcome_before.tenant_id != capsule.tenant_id:
                raise RuntimeError("normal consumption evidence record binding mismatch")
            terminal_before = self._consumption_store.status(
                capsule.tenant_id, outcome_before.receipt_id
            )
            if (
                terminal_before is None
                or terminal_before.state is not ConsumptionState.SUCCEEDED
                or terminal_before.revoked_at is not None
                or terminal_before.tenant_id != capsule.tenant_id
                or terminal_before.receipt_id != outcome_before.receipt_id
                or terminal_before.receipt_hash != outcome_before.receipt_hash
            ):
                raise RuntimeError("normal consumption receipt is not terminal and unrevoked")
            events = self.audit.query(
                where=lambda event: event.get("event_id") == outcome_before.event_id,
                limit=2,
            )
            if len(events) != 1:
                raise RuntimeError("normal consumption audit event is missing or duplicated")
            audit_before = dict(events[0])
            replay_value = self._replay_store.get(outcome_before.event_id)
            if replay_value is None:
                raise RuntimeError("normal consumption replay row is missing")
            replay_before = dict(replay_value)
            if (
                outcome_before.event_id != outcome_before.receipt_id
                or audit_before.get("event_hash") != outcome_before.audit_event_hash
                or audit_before.get("decision") != "allow"
                or audit_before.get("tool") != outcome_before.governed_operation
                or audit_before.get("actor") != outcome_before.actor
                or audit_before.get("argument_hash") != outcome_before.arguments_hash
                or replay_before.get("event_id") != outcome_before.event_id
                or replay_before.get("decision") != "allow"
                or replay_before.get("tool") != outcome_before.governed_operation
                or replay_before.get("actor") != outcome_before.actor
                or replay_before.get("argument_hash") != outcome_before.arguments_hash
                or replay_before.get("state", {}).get("operation")
                != outcome_before.governed_operation
                or replay_before.get("state", {}).get("authority") != outcome_before.authority
                or replay_before.get("state", {}).get("tool") != outcome_before.downstream_tool
            ):
                raise RuntimeError("normal consumption runtime cross-link mismatch")
            record_values = (typed_record,)
            event_ids = (outcome_before.event_id,)
            outcome_ids = (outcome_before.outcome_record_id,)
        else:
            record_values = ()
            event_ids = ()
            outcome_ids = ()

        evidence_anchor_before = self._consumption_anchor.read(evidence_namespace)
        if evidence_anchor_before is None:
            if not self._consumption_anchor.compare_and_swap(
                evidence_namespace,
                None,
                verified,
            ):
                raise RuntimeError("MCP consumption proof anchor could not be established")
        elif evidence_anchor_before != verified:
            raise RuntimeError("MCP consumption proof anchor does not match the store")
        if self._consumption_anchor.read(evidence_namespace) != verified:
            raise RuntimeError("MCP consumption proof anchor changed during evidence capture")

        unsigned_snapshot = MCPSignedConsumptionSnapshot(
            tenant_id=self._canonical_tenant_id,
            anchor_namespace=evidence_namespace,
            store_id=verified.store_id,
            generation=verified.generation,
            chain_head=verified.chain_head,
            state_root=verified.state_root,
            key_id=key.key_id,
            algorithm=key.algorithm,
            signature="0" * 128,
        )
        snapshot = dataclass_replace(
            unsigned_snapshot,
            signature=signer.sign(unsigned_snapshot.signing_payload()),
        )
        target = {
            "server_digest": capsule.target_server_digest,
            "launch_digest": capsule.target_launch_digest,
            "transport_digest": capsule.target_transport_digest,
            "artifact_digest": capsule.target_artifact_digest,
        }
        pending = MCPActionConsumptionEvidence(
            lane=lane,
            event_ids=event_ids,
            outcome_record_ids=outcome_ids,
            anchor_namespace=evidence_namespace,
            store_id=verified.store_id,
            generation=verified.generation,
            chain_head=verified.chain_head,
            state_root=verified.state_root,
            key_purpose=key.purpose,
            key_id=key.key_id,
            snapshot=snapshot,
            records=record_values,
            tenant_id=capsule.tenant_id,
            policy_version=capsule.policy_version,
            policy_digest=capsule.policy_digest,
            target=target,
            outer_algorithm=key.algorithm,
            outer_signature="0" * 128,
        )
        outer_signature = signer.sign(
            _ACTION_CONSUMPTION_DOMAIN + canonical_json(pending._unsigned_dict()).encode("utf-8")
        )
        evidence = dataclass_replace(pending, outer_signature=outer_signature)

        after = self._consumption_anchor.read(namespace)
        evidence_after = self._consumption_anchor.read(evidence_namespace)
        if (
            after != verified
            or evidence_after != verified
            or not self._consumption_store.strict_integrity_ready
        ):
            raise RuntimeError("MCP consumption state changed while evidence was signed")
        final = self._consumption_anchor.read(namespace)
        evidence_final = self._consumption_anchor.read(evidence_namespace)
        if final != verified or evidence_final != verified:
            raise RuntimeError("MCP consumption anchor changed after evidence capture")
        if lane == "normal":
            if response is None or outcome_before is None:
                raise RuntimeError("normal consumption response changed during evidence capture")
            terminal_after = self._consumption_store.status(
                capsule.tenant_id, outcome_before.receipt_id
            )
            events_after = self.audit.query(
                where=lambda event: event.get("event_id") == outcome_before.event_id,
                limit=2,
            )
            replay_after = self._replay_store.get(outcome_before.event_id)
            if (
                terminal_after != terminal_before
                or len(events_after) != 1
                or dict(events_after[0]) != audit_before
                or replay_after is None
                or dict(replay_after) != replay_before
                or outcome_before.payload_digest != captured_result_digest
                or capsule.outcome_sink.require(
                    response,
                    outcome_record_id=outcome_before.outcome_record_id,
                )
                != outcome_before
                or _regular_file_identity(capsule.audit_path, "audit")
                != outcome_before.audit_file_identity
                or _regular_file_identity(capsule.replay_path, "replay")
                != outcome_before.replay_file_identity
            ):
                raise RuntimeError("MCP consumption bindings changed during evidence capture")
        final_capsule = self._validate_capture_trust_roots()
        if final_capsule is not capsule:
            raise RuntimeError("MCP capture trust-root capsule was replaced")
        verifier = self._pinned_consumption_verifier(signer, key)
        outer_payload = _ACTION_CONSUMPTION_DOMAIN + canonical_json(
            evidence._unsigned_dict()
        ).encode("utf-8")
        snapshot_valid = verifier.verify(snapshot.signing_payload(), snapshot.signature)
        outer_valid = verifier.verify(outer_payload, evidence.outer_signature)
        if not snapshot_valid or not outer_valid:
            raise RuntimeError(
                "MCP consumption evidence failed pinned local signature verification"
            )
        return evidence

    def __getstate__(self) -> None:
        """Live signer/store capabilities are intentionally non-serializable."""
        raise TypeError("MCPReferenceRuntime is a live non-serializable capability")

    async def aclose(self) -> None:
        await self.transport.aclose()

    async def __aenter__(self) -> MCPReferenceRuntime:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


async def create_reference_runtime(
    state_dir: Path,
    *,
    inbound_token: str,
    session_id: str,
    catalog_mode: str = "normal",
    proof_lane: str | None = None,
    ambiguous_delay_ms: int = 1500,
    adapter_timeout: float | None = 1.0,
    state_capability: AttestedDirectory | None = None,
    capability_phase_hook: Any | None = None,
    health_token: str | None = None,
    token_verifier: MCPTokenVerifier | None = None,
) -> MCPReferenceRuntime:
    """Create a local-only reference runtime; no production systems are used.

    ``health_token`` registers the readiness probe's dedicated identity (see
    :data:`HEALTH_TENANT_ID`).  It is optional so that every existing local proof
    path keeps exactly one identity unless readiness is actually wired.

    ``token_verifier`` replaces the fixture static verifier with a real one --
    in practice :class:`~gove_zone.mcp_identity.EdDSAJWSVerifier`.  When it is
    supplied the fixture strings are not accepted identities at all; the verifier
    alone decides.
    """

    if proof_lane not in {None, "normal", "poison"}:
        raise ValueError("proof_lane must be normal, poison, or None")
    if proof_lane == "normal" and catalog_mode != "normal":
        raise ValueError("normal proof lane requires the normal fixture catalog")
    if proof_lane == "poison" and catalog_mode != "poison-description":
        raise ValueError("poison proof lane requires the poisoned fixture catalog")

    if capability_phase_hook is not None and not callable(capability_phase_hook):
        raise TypeError("capability_phase_hook must be callable")
    directory = state_dir.expanduser()
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    try:
        if state_capability is None:
            if is_proc_fd_path(directory):
                raise OSError("proc descriptor paths are not direct state roots")
            directory.mkdir(mode=0o700, parents=False, exist_ok=True)
            directory = validate_private_state_root(directory)
        else:
            require_attested_directory(state_capability, error_type=RuntimeError)
            state_capability.checkpoint()
            if directory != state_capability.display_path:
                raise RuntimeError("state capability does not match state_dir")
            directory = state_capability.display_path
    except (OSError, MCPStdioError):
        raise RuntimeError("reference state root is not owner-private") from None
    fixture_module = Path(__file__).with_name("mcp_fixture_server.py").resolve()
    fixture_artifact = _private_fixture_copy(directory, fixture_module, state_capability)
    interpreter = Path(sys.executable).resolve(strict=True)
    # The canonical base interpreter does not inherit the venv selected by its
    # symlink. Supply only the current MCP dependency directory to the fixture.
    mcp_module_file = __import__("mcp").__file__
    if mcp_module_file is None:
        raise RuntimeError("the MCP dependency has no filesystem origin")
    mcp_site_packages = Path(mcp_module_file).resolve().parent.parent
    environment = {
        "ACGS_FIXTURE_EXPECTED_PROOF": hashlib.sha256(b"fixture-downstream-secret").hexdigest(),
        "ACGS_FIXTURE_CATALOG_MODE": catalog_mode,
        "ACGS_FIXTURE_AMBIGUOUS_DELAY_MS": str(ambiguous_delay_ms),
        # The fixed child must not mutate its installed package ancestors
        # between preflight and post-handshake target attestation.
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(mcp_site_packages),
    }
    if state_capability is None:
        environment.update(
            {
                "ACGS_FIXTURE_LEDGER": str(directory / "fixture-ledger.jsonl"),
                "ACGS_FIXTURE_CALL_LOG": str(directory / "fixture-calls.jsonl"),
                "ACGS_FIXTURE_PID_FILE": str(directory / "fixture.pid"),
            }
        )
    validator = MCPStdioTargetValidator()
    transport = MCPFixedStdioTransport(
        validator=validator,
        server_id="fixture-server",
        executable=str(interpreter),
        argv=(str(fixture_artifact),),
        cwd=str(fixture_artifact.parent),
        artifact_path=str(fixture_artifact),
        environment=environment,
        timeout_seconds=adapter_timeout or 1.0,
        state_capability=state_capability,
        capability_phase_hook=capability_phase_hook,
    )
    await transport.start()
    try:
        now = datetime.now(UTC)
        claims = MCPTokenClaims(
            issuer="https://identity.fixture.invalid",
            audiences=("acgs-mcp-gateway",),
            resource="mcp://fixture-server",
            client_id="fixture-agent-client",
            user_id="fixture-agent",
            tenant_id="fixture-tenant",
            role="automation-agent",
            authority="mcp.tools.call",
            scopes=("tools:list", FIXTURE_CATALOG_SCOPE, "fixture:read", "fixture:write"),
            session_id=session_id,
            token_id="fixture-token-id",  # noqa: S106 - identifier, not token material
            issued_at=_iso(now - timedelta(minutes=1)),
            expires_at=_iso(now + timedelta(hours=1)),
        )
        registry = {inbound_token: claims}
        allowed_clients = ["fixture-agent-client"]
        allowed_tenants = ["fixture-tenant"]
        allowed_roles = ["automation-agent"]
        if health_token is not None:
            if health_token == inbound_token:
                raise ValueError("the health identity must not reuse the agent token")
            registry[health_token] = _health_claims(now)
            allowed_clients.append(HEALTH_CLIENT_ID)
            allowed_tenants.append(HEALTH_TENANT_ID)
            allowed_roles.append(HEALTH_ROLE)
        identity_verifier = MCPIdentityVerifier(
            token_verifier
            if token_verifier is not None
            else _TokenVerifier.from_registry(registry),
            MCPIdentityPolicy(
                trusted_issuer="https://identity.fixture.invalid",
                gateway_audience="acgs-mcp-gateway",
                resource_audience="mcp://fixture-server",
                allowed_clients=tuple(allowed_clients),
                allowed_tenants=tuple(allowed_tenants),
                allowed_roles=tuple(allowed_roles),
            ),
        )
        principal_context = MCPPrincipalContext()
        policy = create_reference_policy()
        snapshot = policy.authorization_snapshot()
        ref = ResolvedPolicyRef(
            tenant_id="fixture-tenant",
            bundle_id=MCP_REFERENCE_POLICY_BUNDLE_ID,
            version=snapshot.policy_version,
            digest=snapshot.digest,
        )
        resolved = ResolvedPolicy(
            ref=ref,
            policy=policy,
            attestation=PolicyArtifactAttestation(
                tenant_id=ref.tenant_id,
                artifact_id=ref.bundle_id,
                policy_version=ref.version,
                digest=ref.digest,
                resolver_id=MCP_REFERENCE_POLICY_RESOLVER_ID,
            ),
            validator=Validator("fixture-security-approver", "approver"),
            authority="mcp.tools.call",
        )
        policy_resolver = _PolicyResolver(resolved)
        signer = Ed25519Signer.generate("mcp-reference-receipt-key")
        consumption_signer = Ed25519Signer.generate("mcp-reference-consumption-key")
        lifecycle_signer = Ed25519Signer.generate(
            f"mcp-reference-lifecycle-key:{proof_lane or 'default'}"
        )
        lifecycle_authority_id = (
            f"mcp-execution-validator:{proof_lane}"
            if proof_lane is not None
            else "mcp-execution-validator"
        )
        audit_path = directory / "audit.jsonl"
        audit_anchor = _AuditAnchor()
        audit_namespace = (
            f"mcp-proof:{proof_lane}" if proof_lane is not None else f"mcp-reference:{audit_path}"
        )
        if state_capability is None:
            audit = ChainHashAuditStore(
                audit_path,
                checkpoint_anchor=audit_anchor,
                checkpoint_namespace=audit_namespace,
                checkpoint_signer=signer,
                checkpoint_verifier={signer.key_id: signer},
                require_trusted_checkpoint=True,
            )
        else:
            audit = ChainHashAuditStore.from_attested(
                state_capability,
                "audit.jsonl",
                checkpoint_anchor=audit_anchor,
                checkpoint_namespace=audit_namespace,
                checkpoint_signer=signer,
                checkpoint_verifier={signer.key_id: signer},
                require_trusted_checkpoint=True,
            )
        replay_path = directory / "replay.jsonl"
        if state_capability is None:
            replay_store = _RequiredReplaySideStore(replay_path)
        else:
            replay_candidate = _RequiredReplaySideStore.from_attested(
                state_capability, "replay.jsonl"
            )
            if not isinstance(replay_candidate, _RequiredReplaySideStore):
                raise RuntimeError("attested replay store lost its required-commit contract")
            replay_store = replay_candidate
        consumption_path = directory / "consumption.sqlite3"
        consumption_anchor = _ConsumptionAnchor()
        consumption_namespace = f"mcp-reference:{consumption_path}"
        if state_capability is None:
            consumption = ReceiptConsumptionStore(
                consumption_path,
                hmac_key=_CONSUMPTION_KEY,
                state_anchor=consumption_anchor,
                anchor_namespace=consumption_namespace,
                require_trusted_anchor=True,
            )
        else:
            consumption = ReceiptConsumptionStore.from_attested(
                state_capability,
                "consumption.sqlite3",
                hmac_key=_CONSUMPTION_KEY,
                state_anchor=consumption_anchor,
                anchor_namespace=consumption_namespace,
                require_trusted_anchor=True,
            )
        authorizer = _ReplayRequiredAuthorizationKernel(
            required_side_store=replay_store,
            principal_resolver=principal_context,
            policy_resolver=policy_resolver,
            audit=audit,
            signer=signer,
            binding_hmac_key=_BINDING_KEY,
            allowed_validator_roles=("approver",),
        )
        executor = ReceiptGatedSideEffectExecutor(
            principal_resolver=principal_context,
            policy_resolver=policy_resolver,
            audit=audit,
            consumption_store=consumption,
            verifier=signer,
            binding_hmac_key=_BINDING_KEY,
            allowed_validator_roles=("approver",),
            adapter_timeout=adapter_timeout,
            lifecycle_signer=lifecycle_signer,
            lifecycle_authority_id=lifecycle_authority_id,
        )
        definitions = (
            _definition(
                "fixture.write_once", "Append one sanitized fixture record", arguments=True
            ),
            _definition(
                "fixture.ambiguous_write",
                "Append once and delay to simulate an uncertain response",
                arguments=True,
            ),
            _definition("fixture.read", "Read the local fixture ledger", arguments=False),
        )

        def tool_policy(definition: MCPToolDefinition, scope: str) -> MCPToolPolicy:
            write = scope == "fixture:write"
            return MCPToolPolicy(
                definition=definition,
                required_scopes=(scope,),
                downstream_scopes=(scope,),
                catalog_scopes=(scope,) if write else (FIXTURE_CATALOG_SCOPE,),
                risk_class=MCPRiskClass.HIGH if write else MCPRiskClass.LOW,
                escalation_policy=(
                    MCPEscalationPolicy.POLICY if write else MCPEscalationPolicy.NONE
                ),
                authority=MCP_TOOLS_CALL_AUTHORITY,
                resource=f"mcp/{definition.name}",
                environment="local-fixture",
                side_effect_class="fixture-write" if write else "fixture-read",
                policy_bundle_id=ref.bundle_id,
                policy_version=ref.version,
                policy_digest=ref.digest,
            )

        config = MCPGatewayConfig(
            origin=transport.target,
            tools=(
                tool_policy(definitions[0], "fixture:write"),
                tool_policy(definitions[1], "fixture:write"),
                tool_policy(definitions[2], "fixture:read"),
            ),
        )
        exchange_key = MCPPublicVerificationKey(
            purpose="gateway-exchange",
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            public_bytes=signer.public_bytes(),
        )
        outcome_sink = _MCPExecutionOutcomeSink(
            audit_path=audit_path,
            replay_path=replay_path,
            signer=signer,
            exchange_key=exchange_key,
            proof_lane=proof_lane,
            tenant_id=claims.tenant_id,
            policy_version=snapshot.policy_version,
            policy_digest=snapshot.digest,
            target={
                "server_digest": hashlib.sha256(
                    transport.target.server_id.encode("utf-8")
                ).hexdigest(),
                "launch_digest": transport.target.launch_digest,
                "transport_digest": transport.target.transport_binding,
                "artifact_digest": transport.target.artifact_sha256,
            },
            state_capability=state_capability,
        )
        gateway = _OutcomeCapturingMCPActionGateway(
            outcome_sink=outcome_sink,
            config=config,
            identity_verifier=identity_verifier,
            principal_context=principal_context,
            origin_validator=validator,
            credential_provider=_CredentialProvider(now),
            transport=transport,
            authorizer=authorizer,
            executor=executor,
            consumption_store=consumption,
        )
        target = transport.target
        receipt_key = MCPPublicVerificationKey(
            purpose="receipt",
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            public_bytes=signer.public_bytes(),
        )
        proof_sources = MCPProofSources(
            audit_path=audit_path,
            audit_namespace=audit_namespace,
            replay_path=replay_path,
            consumption_path=consumption_path,
            consumption_namespace=consumption_namespace,
            policy_artifact=snapshot.canonical_artifact,
            policy_attestation=resolved.attestation,
            policy_digest=snapshot.digest,
            policy_version=snapshot.policy_version,
            fixture_ledger_path=directory / "fixture-ledger.jsonl",
            fixture_call_log_path=directory / "fixture-calls.jsonl",
            target_instance_id=target.instance_id,
            target_server_id=target.server_id,
            target_launch_digest=target.launch_digest,
            target_transport_binding=target.transport_binding,
            target_artifact_path=Path(target.artifact_path),
            target_artifact_digest=target.artifact_sha256,
            tenant_id=claims.tenant_id,
            receipt_key=receipt_key,
            refusal_key=MCPPublicVerificationKey(
                purpose="refusal",
                key_id=signer.key_id,
                algorithm=signer.algorithm,
                public_bytes=signer.public_bytes(),
            ),
            checkpoint_key=MCPPublicVerificationKey(
                purpose="audit-checkpoint",
                key_id=signer.key_id,
                algorithm=signer.algorithm,
                public_bytes=signer.public_bytes(),
            ),
            consumption_key=MCPPublicVerificationKey(
                purpose="consumption-snapshot",
                key_id=consumption_signer.key_id,
                algorithm=consumption_signer.algorithm,
                public_bytes=consumption_signer.public_bytes(),
            ),
            exchange_key=exchange_key,
            lifecycle_key=MCPPublicVerificationKey(
                purpose="lifecycle-attestation",
                key_id=lifecycle_signer.key_id,
                algorithm=lifecycle_signer.algorithm,
                public_bytes=lifecycle_signer.public_bytes(),
            ),
            lifecycle_authority_id=lifecycle_authority_id,
        )
        target_server_digest = hashlib.sha256(target.server_id.encode("utf-8")).hexdigest()
        proof_sources_digest = _proof_sources_digest(proof_sources)
        trust_capsule = _MCPRuntimeTrustCapsule(
            gateway=gateway,
            transport=transport,
            audit=audit,
            audit_anchor=audit_anchor,
            replay_store=replay_store,
            consumption_store=consumption,
            consumption_anchor=consumption_anchor,
            consumption_signer=consumption_signer,
            outcome_sink=outcome_sink,
            proof_sources=proof_sources,
            proof_sources_digest=proof_sources_digest,
            state_dir=directory,
            tenant_id=claims.tenant_id,
            audit_namespace=audit_namespace,
            consumption_namespace=consumption_namespace,
            audit_path=audit_path,
            replay_path=replay_path,
            consumption_path=consumption_path,
            consumption_key=proof_sources.consumption_key,
            policy_version=snapshot.policy_version,
            policy_digest=snapshot.digest,
            target_server_digest=target_server_digest,
            target_launch_digest=target.launch_digest,
            target_transport_digest=target.transport_binding,
            target_artifact_digest=target.artifact_sha256,
        )
        trust_capsule_digest = _trust_capsule_digest(trust_capsule)
        runtime = MCPReferenceRuntime(
            gateway=gateway,
            transport=transport,
            audit=audit,
            session_id=session_id,
            state_dir=directory,
            _proof_sources=proof_sources,
            _proof_sources_digest=proof_sources_digest,
            _canonical_tenant_id=claims.tenant_id,
            _canonical_audit_namespace=audit_namespace,
            _canonical_consumption_namespace=consumption_namespace,
            _canonical_audit_path=audit_path,
            _canonical_consumption_path=consumption_path,
            _audit_anchor=audit_anchor,
            _replay_store=replay_store,
            _consumption_store=consumption,
            _consumption_anchor=consumption_anchor,
            _consumption_signer=consumption_signer,
            _outcome_sink=outcome_sink,
            _canonical_consumption_key=proof_sources.consumption_key,
            _canonical_policy_version=snapshot.policy_version,
            _canonical_policy_digest=snapshot.digest,
            _canonical_target_server_digest=target_server_digest,
            _canonical_target_launch_digest=target.launch_digest,
            _canonical_target_transport_digest=target.transport_binding,
            _canonical_target_artifact_digest=target.artifact_sha256,
            _trust_capsule=trust_capsule,
            _trust_capsule_digest=trust_capsule_digest,
            _state_capability=state_capability,
        )
    except BaseException:
        await transport.aclose()
        raise
    if state_capability is not None:
        state_capability.checkpoint()
    return runtime


__all__ = [
    "MCPActionConsumptionEvidence",
    "MCPGatewayExchangeEvidence",
    "MCPProofSources",
    "MCPReferencePolicy",
    "MCPReferenceHTTPGateway",
    "MCP_REFERENCE_POLICY_BUNDLE_ID",
    "MCP_REFERENCE_POLICY_RESOLVER_ID",
    "MCP_REFERENCE_POLICY_VERSION",
    "MCPPublicVerificationKey",
    "MCPReferenceRuntime",
    "MCPSignedConsumptionSnapshot",
    "create_reference_runtime",
    "create_reference_http_gateway",
    "create_reference_policy",
]
