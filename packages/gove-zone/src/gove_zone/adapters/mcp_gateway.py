"""Governed-MCP gateway (pilot / alpha).

A transparent stdio proxy that fronts **one** unmodified downstream MCP server
and gates its ``tools/call`` traffic through the sealed gove-zone kernel. It is
simultaneously an MCP *server* (to the host) and an MCP *client* (to the
downstream). Everything except ``tools/call`` is either passed through
(``tools/list``) or left unregistered so the SDK returns *method-not-found* —
fail-closed, never a silent forward. ``sampling/createMessage`` is denied in
alpha (the runtime constructs the downstream session with no sampling callback,
so the downstream's reverse LLM channel is never bridged to the host; partner
opt-in is a reserved, not-yet-honoured follow-up).

Status: **alpha / design-partner pilot**. Nothing here claims production
readiness, certification, compliance approval, or regulator-ready behaviour.

Trust boundary (honest, alpha): the **host→gateway** hop is assumed to be a
trusted local transport (stdio subprocess, same trust domain). The gateway does
not itself authenticate the host; the session principal is only as strong as
that transport's authentication. This is a documented limitation, not an
end-to-end authenticated-identity claim — see ``docs/SECURITY_MODEL.md``.
See docs/design/mcp-gateway-trust-boundaries.md for the host→gateway and
out-of-band operator trust boundaries.

Reuse-only assembly: this module adds **no new gate logic**. Every decision goes
through :meth:`~gove_zone.kernel.Kernel.evaluate_and_record`; every side effect
is authorised by a signed :class:`~gove_zone.receipt.DecisionReceipt` verified
inside :func:`~gove_zone.executor.execute_with_receipt` /
:func:`~gove_zone.escalation.resume_with_receipt`, with a
:class:`~gove_zone.consumption.ReceiptConsumptionLedger` enforcing single use.

The official ``mcp`` SDK is an **optional** dependency: ``import gove_zone`` and
``import gove_zone.adapters`` stay dependency-free (the SDK is imported lazily
inside :func:`build_gateway_server` / :meth:`GovernedGateway.build_server`, which
raise a loud :class:`RuntimeError` with an install hint when it is absent).
Install with ``pip install gove-zone[mcp]`` (add ``,crypto`` for signed
receipts).
"""

from __future__ import annotations

import functools
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from weakref import WeakKeyDictionary

from gove_zone.audit import ChainHashAuditStore
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.errors import (
    AuditError,
    GoveZoneError,
    ReceiptAlreadyUsedError,
    ReceiptValidationError,
)
from gove_zone.escalation import PendingApproval, approve_escalation, resume_with_receipt
from gove_zone.executor import GovernedExecutor, execute_with_receipt
from gove_zone.kernel import Kernel
from gove_zone.policy import Policy, RuleSetPolicy, new_event_id
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.rejection import HUMAN_APPROVAL, REVISE_AND_RETRY, rejection_dict
from gove_zone.tool import ToolCall

if TYPE_CHECKING:  # pragma: no cover - typing only; never imported at runtime top level
    import mcp.types as mcp_types
    from mcp.client.session import ClientSession
    from mcp.server.lowlevel import Server
    from mcp.server.session import ServerSession

#: The standalone transform policy id (``gove_zone.tenant.TransformPolicy``).
#: TRANSFORM routing is out of scope for the pilot; a bundle carrying this id is
#: rejected at config load (§3.2) so an unrouted TRANSFORM cannot silently
#: hard-fail every such call at the receipt gate.
_TRANSFORM_POLICY_ID = "transform-policy"

#: Reserved ``tools/call`` names owned by this gateway. They never forward
#: downstream: ``gove.approve`` mints a same-tenant approval; ``gove.resume``
#: verifies and burns that approval, then executes the original tool once.
MCP_APPROVE_TOOL = "gove.approve"
MCP_RESUME_TOOL = "gove.resume"
MCP_HUMAN_LOOP_TOOLS = frozenset({MCP_APPROVE_TOOL, MCP_RESUME_TOOL})

_MISSING_MCP_MSG = (
    "the governed-MCP gateway requires the official Model Context Protocol SDK; "
    "install with `pip install gove-zone[mcp]` (add `,crypto` for signed receipts)"
)


def _require_mcp() -> None:
    """Import-guard: raise a loud, actionable error when the SDK is absent.

    Never returns a silent ``None`` (the anti-pattern the design flags in
    ``build_fastmcp_server``): a missing SDK is a hard configuration error, not a
    no-op.
    """
    try:
        import mcp  # noqa: F401  # official Model Context Protocol SDK
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without extra
        raise RuntimeError(_MISSING_MCP_MSG) from exc


# --------------------------------------------------------------------------- #
# Config surface (G3) — dependency-free JSON; no Python for the partner.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GatewayConfig:
    """Resolved gateway configuration.

    Built either from a JSON file (:func:`load_gateway_config`, the partner
    surface) or directly (tests / embedders). Holds an already-resolved
    :class:`~gove_zone.profile.GovernanceProfile` (carrying signer/verifier) so
    the runtime never touches key files.
    """

    tenant_id: str
    execution_boundary: str
    policy: Policy
    policy_bundle_id: str
    profile: GovernanceProfile
    validator: Validator
    principals: Mapping[str, str]
    audit_path: Path
    ledger_path: Path
    # Reserved: partner sampling opt-in is NOT yet honoured. In alpha the gateway
    # always constructs its downstream session without a sampling callback, so
    # the downstream reverse LLM channel is denied. Real opt-in requires bridging
    # downstream→host sampling (a documented follow-up); this field is parsed for
    # forward compatibility only.
    allow_sampling: bool = False
    server_name: str = "gove-zone-gateway"
    authority: str = "gove-zone-mcp-gateway"
    downstream: Mapping[str, Any] = field(default_factory=dict)
    # Optional receipt liveness bound: when set, every minted tools/call
    # receipt carries ``expires_at = now + ttl``. Required in practice for the
    # ``production_strict`` profile (``require_expiry=True`` rejects receipts
    # with no expiry at the gate — a TTL-less strict gateway can never forward).
    receipt_ttl_seconds: float | None = None
    # Bounded-capacity back-pressure for parked escalations (finding: _pending /
    # _approvals are only ever written, never cleaned — unbounded growth). These
    # cap how many escalations may be parked awaiting human approval, globally and
    # per parking principal. Non-time-based: an escalation leaves _pending only by
    # a successful resume (post-ledger-burn cleanup), never by a clock. Defaults
    # are generous so existing embedders/tests are unaffected.
    max_pending: int = 256
    max_pending_per_principal: int = 64
    # clientInfo.name → validator_id for MCP ``gove.approve``. Distinct from
    # ``principals`` (proposing agents). Empty means MCP approve is unavailable
    # (CLI ``approve-escalation`` still works). Names and mapped ids must not
    # overlap ``principals`` — otherwise the proposing agent could self-approve
    # through ``tools/call``.
    approver_principals: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Self-validation guard, fail-closed at config load: the validator must
        # differ from every mapped principal (mirrors the tenant.py /
        # from_record validator==actor guard). A self-validated receipt can
        # never be minted, so catch it up front with a clear error.
        clashes = sorted({p for p in self.principals.values() if p == self.validator.validator_id})
        if clashes:
            raise ValueError(
                "self-validation forbidden at config load: validator_id "
                f"{self.validator.validator_id!r} also appears as a mapped principal "
                f"{clashes}; the validator must differ from every actor principal"
            )
        # Fail-closed: a non-positive escalation capacity would either reject
        # every escalation (0) or never bound growth (negative), so refuse it up
        # front rather than at the first ESCALATE.
        if self.max_pending <= 0 or self.max_pending_per_principal <= 0:
            raise ValueError(
                "escalation capacity caps must be positive: "
                f"max_pending={self.max_pending}, "
                f"max_pending_per_principal={self.max_pending_per_principal}"
            )
        name_clash = sorted(set(self.principals) & set(self.approver_principals))
        if name_clash:
            raise ValueError(
                "approver_principals clientInfo names collide with principals "
                f"{name_clash}; an agent session must not also be an approver session"
            )
        id_clash = sorted(set(self.principals.values()) & set(self.approver_principals.values()))
        if id_clash:
            raise ValueError(
                "approver_principals ids collide with principals "
                f"{id_clash}; a proposing actor must not be able to self-approve "
                "through gove.approve"
            )


def _load_policy_bundle(data: Mapping[str, Any], *, source: str) -> Policy:
    """Load a JSON policy bundle, rejecting TRANSFORM bundles at load (§3.2).

    Only dependency-free :class:`~gove_zone.policy.RuleSetPolicy` bundles (a
    ``rules`` array) are accepted. A standalone transform-policy bundle is
    refused with a clear error rather than silently hard-failing every governed
    call at the receipt gate later (the pilot does not route
    ``record.transformed_args``).
    """
    if isinstance(data, Mapping) and data.get("id") == _TRANSFORM_POLICY_ID:
        raise ValueError(
            f"transform-policy bundles are not supported by the gateway pilot ({source}): "
            "TRANSFORM routing (record.transformed_args) is out of scope, so such a "
            "bundle would fail closed at the receipt gate for every call. Use a "
            "RuleSetPolicy (deny/escalate) bundle, or extend the gateway to route "
            "transformed args."
        )
    if isinstance(data, Mapping) and "rules" in data:
        return RuleSetPolicy.from_dict(data)
    raise ValueError(
        f"unsupported policy bundle in {source}: expected a RuleSetPolicy object with a "
        "'rules' array (dependency-free JSON)"
    )


def load_gateway_config(path: str | Path) -> GatewayConfig:
    """Load and resolve a :class:`GatewayConfig` from a JSON file (G3).

    Dependency-free (JSON, not YAML). Rejects transform-policy bundles and a
    validator that clashes with a mapped principal, both at load. Production
    signing keys (raw 32-byte Ed25519) are loaded from the paths named in the
    ``[signing]`` block; a ``dev`` profile is explicitly unsigned.
    """
    cfg_path = Path(path)
    raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    base = cfg_path.parent

    gov = raw.get("governance", {})
    ident = raw.get("identity", {})
    audit = raw.get("audit", {})
    signing = raw.get("signing", {})
    downstream = raw.get("downstream", {})

    tenant_id = str(gov.get("tenant_id") or "")
    if not tenant_id:
        raise ValueError(f"{cfg_path}: governance.tenant_id is required")
    execution_boundary = str(gov.get("execution_boundary") or "")
    if not execution_boundary:
        raise ValueError(f"{cfg_path}: governance.execution_boundary is required")

    bundle_ref = gov.get("policy_bundle")
    if not bundle_ref:
        raise ValueError(f"{cfg_path}: governance.policy_bundle is required")
    bundle_path = (base / str(bundle_ref)).resolve()
    bundle_data = json.loads(bundle_path.read_text(encoding="utf-8"))
    policy = _load_policy_bundle(bundle_data, source=str(bundle_path))
    policy_bundle_id = str(getattr(policy, "policy_id", "custom"))

    validator = Validator(
        validator_id=str(ident.get("validator_id") or ""),
        role=str(ident.get("validator_role") or "validator"),
    )
    principals = {str(k): str(v) for k, v in dict(ident.get("principals", {})).items()}
    approver_principals = {
        str(k): str(v) for k, v in dict(ident.get("approver_principals", {})).items()
    }

    profile_name = str(gov.get("profile") or "production").strip().lower()
    if profile_name == "dev":
        profile = GovernanceProfile.dev()
    else:
        # production (default). Load keys if present; a production gate with no
        # verifier fails closed loud at first governed call (ProductionProfileError).
        signer = _load_signer(signing.get("signer_key"), base, private=True)
        verifier = _load_signer(signing.get("verifier_key"), base, private=False)
        profile = GovernanceProfile.production(signer=signer, verifier=verifier)

    audit_path = (base / str(audit.get("sink") or "evidence/audit.jsonl")).resolve()
    ledger_ref = audit.get("consumption_ledger") or (Path(audit_path).parent / "consumed.jsonl")
    ledger_path = (base / str(ledger_ref)).resolve()

    escalation = raw.get("escalation", {})

    return GatewayConfig(
        tenant_id=tenant_id,
        execution_boundary=execution_boundary,
        policy=policy,
        policy_bundle_id=policy_bundle_id,
        profile=profile,
        validator=validator,
        principals=principals,
        approver_principals=approver_principals,
        audit_path=audit_path,
        ledger_path=ledger_path,
        allow_sampling=bool(raw.get("sampling", {}).get("allow", False)),
        server_name=str(downstream.get("server_name") or "gove-zone-gateway"),
        downstream=dict(downstream),
        max_pending=int(escalation.get("max_pending", 256)),
        max_pending_per_principal=int(escalation.get("max_pending_per_principal", 64)),
    )


def _load_signer(ref: Any, base: Path, *, private: bool) -> Any:
    """Load an Ed25519 signer/verifier from a raw 32-byte key file, or ``None``."""
    if not ref:
        return None
    from gove_zone.signing import Ed25519Signer

    key_bytes = (base / str(ref)).resolve().read_bytes()
    if private:
        return Ed25519Signer.from_private_bytes(key_bytes)
    return Ed25519Signer.from_public_bytes(key_bytes)


# --------------------------------------------------------------------------- #
# Per-session state (G4 / finding #5) — keyed by ServerSession identity.
# --------------------------------------------------------------------------- #


@dataclass
class SessionContext:
    """Per-MCP-session governance state.

    ``principal`` is the actor bound into every receipt for this session,
    derived once from ``clientInfo`` + the config principal map — **never** read
    from a ``tools/call`` body. ``kernel`` is parameterised with that principal
    as its actor. Keying this per session (not process-global) means the
    streamable-HTTP transport swap cannot introduce cross-session actor bleed.
    """

    principal: str
    kernel: Kernel


class GovernedGateway:
    """Governed proxy fronting one downstream MCP server.

    Construct with a resolved :class:`GatewayConfig` and an **already
    initialised** downstream :class:`mcp.client.session.ClientSession` (injected
    so tests can wire an in-memory fixture and production can wire a
    ``stdio_client`` subprocess). Call :meth:`build_server` to obtain the
    low-level MCP :class:`~mcp.server.lowlevel.Server` the host connects to.
    """

    def __init__(
        self,
        config: GatewayConfig,
        downstream: ClientSession,
        *,
        audit_store: ChainHashAuditStore | None = None,
        ledger: ReceiptConsumptionLedger | None = None,
    ) -> None:
        self._config = config
        self._downstream = downstream
        # One audit chain and one consumption ledger for the whole gateway
        # process (single downstream, single tenant in the pilot). A single
        # ledger instance makes every burn visible to both the ALLOW gate and
        # the escalation-resume gate.
        self._audit = audit_store or ChainHashAuditStore(config.audit_path)
        profile_ledger = config.profile.consumption_ledger
        if profile_ledger is not None:
            # The strict profile carries its own ledger. Two live ledgers would
            # mean two sources of truth for "already spent"; fail loud rather
            # than silently splitting burns across files.
            if ledger is not None and ledger is not profile_ledger:
                raise ValueError(
                    "ambiguous consumption ledger: the governance profile and the "
                    "gateway constructor both supply one; configure it in exactly "
                    "one place"
                )
            self._ledger = profile_ledger
        else:
            self._ledger = ledger or ReceiptConsumptionLedger(config.ledger_path)
        # Keyed by the ServerSession object itself via weak references, NOT by
        # id(session): CPython recycles id() after a session is GC'd, so a
        # closed session's address can be reused by a later session and collide
        # in the cache — leaking the earlier session's principal into the newer
        # one (cross-session actor bleed). A WeakKeyDictionary keys on identity,
        # never collides, and auto-evicts when the session dies.
        self._sessions: WeakKeyDictionary[ServerSession, SessionContext] = WeakKeyDictionary()
        # Parked escalations awaiting human approval, keyed by the ESCALATE
        # record's event_id.
        self._pending: dict[str, PendingApproval] = {}
        # Captured approvals keyed by the pending's event_id: the approval
        # receipt and — crucially — the approval receipt's OWN audit_event_hash
        # (NOT pending.audit_hash, which anchors the earlier ESCALATE event and
        # never matches any approval). This is the value pinned as
        # expected_audit_hash at resume (design test #8 / F9).
        self._approvals: dict[str, tuple[DecisionReceipt, str]] = {}

    # -- session / principal binding (G4) ---------------------------------- #

    def _resolve_principal(self, session: ServerSession) -> str | None:
        """Resolve the session principal from ``clientInfo`` + the config map.

        Returns ``None`` (fail-closed) when no principal maps — the caller turns
        that into a DENY. Identity is NEVER read from a request body.
        """
        params = getattr(session, "client_params", None)
        client_info = getattr(params, "clientInfo", None)
        name = getattr(client_info, "name", None)
        if not isinstance(name, str) or not name:
            return None
        return self._config.principals.get(name)

    def _resolve_approver(self, session: ServerSession) -> str | None:
        """Resolve the MCP approver from ``clientInfo`` + ``approver_principals``.

        Never falls back to ``principals``: a proposing agent must not mint
        its own approval through ``gove.approve``.
        """
        params = getattr(session, "client_params", None)
        client_info = getattr(params, "clientInfo", None)
        name = getattr(client_info, "name", None)
        if not isinstance(name, str) or not name:
            return None
        return self._config.approver_principals.get(name)

    def _session_context(self, session: ServerSession) -> SessionContext | None:
        ctx = self._sessions.get(session)
        if ctx is not None:
            return ctx
        principal = self._resolve_principal(session)
        if principal is None:
            return None
        ctx = SessionContext(
            principal=principal,
            kernel=Kernel(policy=self._config.policy, audit=self._audit, actor=principal),
        )
        self._sessions[session] = ctx
        return ctx

    # -- server wiring ----------------------------------------------------- #

    def build_server(self) -> Server:
        """Build the low-level MCP server the host connects to.

        Registers only ``tools/list`` (downstream catalogue plus reserved
        ``gove.approve`` / ``gove.resume``) and ``tools/call`` (the governed
        gate). Reserved names are intercepted before policy or downstream
        forward. Every other method is left unregistered so the SDK answers
        *method-not-found* — a fail-closed non-forward for unknown /
        unsupported side-effecting methods (bar #2).
        ``sampling/createMessage`` is a server→client request and is denied by
        construction: the runtime (:func:`run_stdio_gateway`) constructs the
        downstream client session with no sampling callback (partner opt-in is a
        reserved, not-yet-honoured follow-up).
        """
        _require_mcp()
        from mcp.server.lowlevel import Server

        server: Server = Server(self._config.server_name)

        # The mcp SDK's registration decorators are untyped; the handlers keep
        # their own annotations so their bodies stay strict-checked.
        @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
        async def _list_tools() -> list[mcp_types.Tool]:
            downstream_tools = await self._downstream.list_tools()
            advertised = [
                tool for tool in downstream_tools.tools if tool.name not in MCP_HUMAN_LOOP_TOOLS
            ]
            advertised[0:0] = self._human_loop_tool_defs()
            return advertised

        # validate_input=False: the governance decision runs on RAW args (G6);
        # schema pre-validation must not shadow an arg-keyed deny, and the
        # downstream server does its own validation on forward.
        @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
        async def _call_tool(name: str, arguments: dict[str, Any]) -> mcp_types.CallToolResult:
            return await self._governed_tools_call(server, name, arguments or {})

        return server

    # -- the tools/call gate (§3.2) ---------------------------------------- #

    async def _governed_tools_call(
        self, server: Server, name: str, arguments: dict[str, Any]
    ) -> mcp_types.CallToolResult:
        session = server.request_context.session
        if name in MCP_HUMAN_LOOP_TOOLS:
            # Reserved names never reach policy or the downstream catalog.
            return await self._human_loop_tools_call(session, name, arguments)

        ctx = self._session_context(session)
        if ctx is None:
            # Principal could not be resolved from clientInfo (the low-level
            # Server owns the initialize handshake, so we enforce identity here
            # at first tools/call rather than failing initialize). Fail closed:
            # no decision, no forward.
            return self._unmapped_principal_result(name)

        raw_args = dict(arguments)
        call = ToolCall(
            name=name,
            args=raw_args,
            actor=ctx.principal,
            path=_lift_path(raw_args),
        )
        # Chain-linkage anchor for the minted receipt (informational): the hash
        # the decision event chains onto. Captured before the decision append,
        # mirroring evaluate_tenant_action.
        previous_audit_hash = self._audit.last_hash()
        try:
            record, audit_hash = ctx.kernel.evaluate_and_record(call)
        except AuditError:
            # The decision could not be recorded -> fail closed with a fixed,
            # leak-safe envelope carrying no request-derived text (finding #4).
            return self._audit_unrecordable_result()
        except GoveZoneError:
            return self._governance_error_result()

        if record.decision is Decision.DENY:
            return self._deny_result(record, audit_hash, name)
        if record.decision is Decision.ESCALATE:
            rejection = self._enforce_pending_capacity(record, ctx.principal, name)
            if rejection is not None:
                # Capacity exhausted: fail-closed DENY (audited), never parked.
                return rejection
            pending = PendingApproval(record, audit_hash, dict(raw_args))
            self._pending[record.event_id] = pending
            return self._escalate_result(record, audit_hash, name)
        if record.decision is Decision.TRANSFORM:
            # Config load rejects transform bundles, so this is unreachable in
            # the pilot; treat any residual TRANSFORM as fail-closed.
            return self._governance_error_result()

        # ALLOW: mint a signed receipt and forward downstream through the
        # receipt gate + single-use ledger.
        receipt = DecisionReceipt.from_record(
            record,
            audit_hash=audit_hash,
            previous_audit_hash=previous_audit_hash,
            tenant_id=self._config.tenant_id,
            execution_boundary=self._config.execution_boundary,
            policy_bundle_id=self._config.policy_bundle_id,
            policy_hash=self._config.policy.version,
            request_id=record.decision_request_hash or record.event_id,
            validator=self._config.validator,
            authority=self._config.authority,
            expires_at=self._receipt_expires_at(),
            signer=self._config.profile.signer,
        )
        return await self._forward_allow(name, raw_args, receipt, ctx.principal, record, audit_hash)

    def _receipt_expires_at(self) -> str:
        """``expires_at`` for a freshly minted receipt ("" = no liveness bound).

        With ``config.receipt_ttl_seconds`` unset and a strict profile
        (``require_expiry=True``) the gate rejects every minted receipt —
        deliberately fail-closed rather than silently immortal.
        """
        ttl = self._config.receipt_ttl_seconds
        if ttl is None:
            return ""
        return (datetime.now(UTC) + timedelta(seconds=ttl)).isoformat()

    def _gate_kwargs(self) -> dict[str, Any]:
        """Merged side-effect-gate keywords: profile posture + the ledger.

        The strict profile's ``as_gate_kwargs()`` already emits
        ``consumption_ledger``; passing the gateway's ledger as a second
        explicit keyword raised ``TypeError`` on every governed call (the bug
        that made ``production_strict`` unusable through this gateway).
        ``__init__`` guarantees ``self._ledger`` IS the profile's ledger when
        the profile carries one, so this override never changes which ledger
        burns — it only removes the duplicate keyword.
        """
        kwargs = dict(self._config.profile.as_gate_kwargs())
        kwargs["consumption_ledger"] = self._ledger
        return kwargs

    async def _forward_allow(
        self,
        name: str,
        raw_args: dict[str, Any],
        receipt: DecisionReceipt,
        principal: str,
        record: Any,
        audit_hash: str,
    ) -> mcp_types.CallToolResult:
        """Forward to the downstream **only** as the tool_fn inside the receipt
        gate — reached only after ``verify`` + the single-use ledger burn.

        The gate (:func:`execute_with_receipt`) is synchronous; the downstream
        forward is async. To preserve the "no execution before receipt
        validation" invariant we run the whole gate off the event loop in a
        worker thread and bridge the actual downstream ``await`` back onto the
        loop from inside the gate's tool_fn — so the forward is genuinely the
        gate's tool_fn, not a separate post-gate call.
        """
        import anyio

        def _forward(**kwargs: Any) -> mcp_types.CallToolResult:
            return anyio.from_thread.run(
                functools.partial(self._downstream.call_tool, name, kwargs)
            )

        try:
            downstream_result: mcp_types.CallToolResult = await anyio.to_thread.run_sync(
                lambda: execute_with_receipt(
                    tool_fn=_forward,
                    args=dict(raw_args),
                    receipt=receipt,
                    expected_tenant_id=self._config.tenant_id,
                    expected_execution_boundary=self._config.execution_boundary,
                    expected_action=name,
                    expected_actor=principal,
                    **self._gate_kwargs(),
                )
            )
        except ReceiptValidationError as exc:
            # Signature/actor/args/tenant/audit binding refused execution.
            return self._gate_refused_result(name, exc)
        except Exception:  # noqa: BLE001 - downstream forward raised (F7)
            # The ALLOW is already audited; surface a leak-safe execution
            # failure without the downstream exception text.
            return self._downstream_failure_result(name, audit_hash)

        return self._wrap_allow_result(downstream_result, record, audit_hash)

    # -- escalation back-pressure (bounded-capacity, fail-closed) ---------- #

    def _enforce_pending_capacity(
        self, record: Any, principal: str, name: str
    ) -> mcp_types.CallToolResult | None:
        """Reject a new escalation when the parked-escalation cap is exhausted.

        Returns ``None`` when there is room to park (the caller proceeds to
        park). When either the global cap (``max_pending``) or this principal's
        cap (``max_pending_per_principal``) is already met, refuses the
        escalation fail-closed: it appends a rejection audit event (so the
        refusal is evidenced, never a silent drop) and returns a leak-safe DENY.
        The escalation is NOT parked — this is the back-pressure that bounds the
        otherwise write-only ``_pending`` / ``_approvals`` growth.

        Ordering note: the kernel already recorded the ESCALATE decision (via
        ``evaluate_and_record``); this rejection is a *second*, separate audit
        event documenting that the gateway refused to park it. No time-based
        eviction is involved — capacity is freed only by a successful resume.
        """
        global_full = len(self._pending) >= self._config.max_pending
        principal_pending = sum(1 for p in self._pending.values() if p.record.actor == principal)
        principal_full = principal_pending >= self._config.max_pending_per_principal
        if not (global_full or principal_full):
            return None
        scope = "pending" if global_full else "principal"
        try:
            reject_record = DecisionRecord(
                decision=Decision.DENY,
                tool=record.tool,
                argument_hash=record.argument_hash,
                policy_version=record.policy_version,
                event_id=new_event_id(),
                matched_rules=(f"CAPACITY_REJECTED:{scope}",),
                reason="escalation capacity exhausted; call refused",
                actor=principal,
            )
            event = self._audit.append(reject_record)
            audit_hash: str | None = str(event.get("event_hash")) or None
        except AuditError:
            # Even the rejection could not be recorded -> the fixed leak-safe
            # unrecordable envelope (still a fail-closed DENY, still not parked).
            return self._audit_unrecordable_result()
        return self._capacity_rejected_result(name, audit_hash)

    # -- escalation approve / resume (G5, F9, test #8) --------------------- #

    def pending_ids(self) -> tuple[str, ...]:
        """Event ids of currently-parked escalations (test / operator helper)."""
        return tuple(self._pending)

    def pending_descriptor(self, event_id: str) -> dict[str, Any]:
        """Serialize a parked escalation for out-of-band approval (CLI verb)."""
        pending = self._pending.get(event_id)
        if pending is None:
            raise KeyError(f"no parked escalation with event_id {event_id!r}")
        return pending_to_dict(pending)

    def approve(
        self,
        event_id: str,
        *,
        validator: Validator,
        expires_at: str = "",
    ) -> DecisionReceipt:
        """Approve a parked escalation and capture its approval-hash pin.

        Wraps :func:`~gove_zone.escalation.approve_escalation` with the gateway's
        config (distinct validator, tenant/boundary/policy, audit chain, signer).
        Records ``(receipt, receipt.audit_event_hash)`` keyed by *event_id* so
        :meth:`resume` can pin the approval receipt's **own** audit anchor (the
        approval event), never ``pending.audit_hash`` (the earlier ESCALATE
        event).
        """
        pending = self._pending.get(event_id)
        if pending is None:
            raise KeyError(f"no parked escalation with event_id {event_id!r}")
        receipt = approve_escalation(
            pending,
            validator=validator,
            authority=self._config.authority,
            tenant_id=self._config.tenant_id,
            execution_boundary=self._config.execution_boundary,
            policy_bundle_id=self._config.policy_bundle_id,
            policy_hash=self._config.policy.version,
            audit=self._audit,
            expires_at=expires_at,
            signer=self._config.profile.signer,
        )
        self._approvals[event_id] = (receipt, receipt.audit_event_hash)
        return receipt

    async def resume(self, event_id: str, receipt: DecisionReceipt) -> mcp_types.CallToolResult:
        """Resume an approved escalation, forwarding the side effect exactly once.

        Pins ``expected_audit_hash`` to the approval-hash captured for **this**
        ``event_id`` at :meth:`approve` time. Presenting an approval minted for a
        *different* pending (cross-pending reuse, test #8a) fails closed:
        either no approval-hash is captured for this pending, or the presented
        receipt's ``audit_event_hash`` mismatches the captured one at the gate.
        A second resume of the same approval raises
        :class:`~gove_zone.errors.ReceiptAlreadyUsedError` via the ledger.
        """
        pending = self._pending.get(event_id)
        if pending is None:
            raise KeyError(f"no parked escalation with event_id {event_id!r}")
        captured = self._approvals.get(event_id)
        if captured is None:
            raise ReceiptValidationError(
                f"no approval captured for pending {event_id!r}; refusing resume (fail-closed)"
            )
        _approval_receipt, approval_hash = captured

        import anyio

        executor = GovernedExecutor(
            tenant_id=self._config.tenant_id,
            execution_boundary=self._config.execution_boundary,
            expected_actor=pending.record.actor,
            **self._gate_kwargs(),
        )

        def _forward(**kwargs: Any) -> mcp_types.CallToolResult:
            return anyio.from_thread.run(
                functools.partial(self._downstream.call_tool, pending.record.tool, kwargs)
            )

        executor.register(pending.record.tool, _forward)

        downstream_result: mcp_types.CallToolResult = await anyio.to_thread.run_sync(
            lambda: resume_with_receipt(
                executor,
                pending,
                receipt,
                expected_audit_hash=approval_hash,
            )
        )
        # Success path only (reached after resume_with_receipt returns, i.e. the
        # approval receipt has been verified AND burned in the single-use ledger):
        # evict the now-consumed pending and its captured approval. This bounds
        # the write-only growth of _pending / _approvals and makes a replayed
        # event_id short-circuit with KeyError above, before it can reach the
        # gate. A pre-burn ReceiptValidationError (the ``captured is None`` guard
        # or any gate refusal) raises before this line, so a legitimate retry of
        # an unconsumed pending is preserved.
        del self._pending[event_id]
        self._approvals.pop(event_id, None)
        return self._wrap_allow_result(downstream_result, pending.record, receipt.audit_event_hash)

    # -- MCP-reachable human loop (gove.approve / gove.resume) ------------- #

    def _human_loop_tool_defs(self) -> list[mcp_types.Tool]:
        import mcp.types as types

        event_schema: dict[str, Any] = {
            "type": "object",
            "properties": {"event_id": {"type": "string"}},
            "required": ["event_id"],
            "additionalProperties": False,
        }
        return [
            types.Tool(
                name=MCP_APPROVE_TOOL,
                description=(
                    "Approve a parked ESCALATE pending. Does not execute the "
                    "original tool. Requires an approver session."
                ),
                inputSchema=event_schema,
            ),
            types.Tool(
                name=MCP_RESUME_TOOL,
                description=(
                    "Resume an approved pending exactly once. Caller must be "
                    "the original proposing principal."
                ),
                inputSchema=event_schema,
            ),
        ]

    def _event_id_arg(self, arguments: Mapping[str, Any]) -> str | None:
        if set(arguments) != {"event_id"}:
            return None
        event_id = arguments.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            return None
        return event_id

    async def _human_loop_tools_call(
        self,
        session: ServerSession,
        name: str,
        arguments: dict[str, Any],
    ) -> mcp_types.CallToolResult:
        event_id = self._event_id_arg(arguments)
        if event_id is None:
            return self._human_loop_denied_result(name, "invalid reserved-tool arguments")
        if name == MCP_APPROVE_TOOL:
            return self._mcp_approve(session, event_id)
        return await self._mcp_resume(session, event_id)

    def _mcp_approve(self, session: ServerSession, event_id: str) -> mcp_types.CallToolResult:
        import mcp.types as types

        approver = self._resolve_approver(session)
        if approver is None:
            return self._human_loop_denied_result(
                MCP_APPROVE_TOOL, "caller is not a mapped approver"
            )
        pending = self._pending.get(event_id)
        if pending is None:
            return self._human_loop_denied_result(MCP_APPROVE_TOOL, "unknown pending event")
        if approver == pending.record.actor:
            return self._human_loop_denied_result(MCP_APPROVE_TOOL, "self-approval is forbidden")
        try:
            receipt = self.approve(
                event_id,
                validator=Validator(validator_id=approver, role="approver"),
                expires_at=self._receipt_expires_at(),
            )
        except (KeyError, ReceiptValidationError, GoveZoneError):
            return self._human_loop_denied_result(MCP_APPROVE_TOOL, "approval refused")
        return types.CallToolResult(
            isError=False,
            content=[
                types.TextContent(
                    type="text",
                    text=f"gove-zone APPROVED {event_id}; not executed",
                )
            ],
            structuredContent={
                "decision": "allow",
                "executed": False,
                "event_id": event_id,
                "audit_hash": receipt.audit_event_hash,
            },
            _meta={
                "gove_zone": {
                    "decision": "allow",
                    "executed": False,
                    "escalation_event_id": event_id,
                    "audit_hash": receipt.audit_event_hash,
                }
            },
        )

    async def _mcp_resume(self, session: ServerSession, event_id: str) -> mcp_types.CallToolResult:
        principal = self._resolve_principal(session)
        if principal is None:
            return self._human_loop_denied_result(
                MCP_RESUME_TOOL, "caller is not a mapped principal"
            )
        pending = self._pending.get(event_id)
        if pending is None:
            return self._human_loop_denied_result(MCP_RESUME_TOOL, "unknown pending event")
        if principal != pending.record.actor:
            return self._human_loop_denied_result(
                MCP_RESUME_TOOL, "only the proposing actor may resume"
            )
        captured = self._approvals.get(event_id)
        if captured is None:
            return self._human_loop_denied_result(MCP_RESUME_TOOL, "pending is not approved")
        receipt, _approval_hash = captured
        try:
            return await self.resume(event_id, receipt)
        except ReceiptAlreadyUsedError:
            return self._human_loop_denied_result(MCP_RESUME_TOOL, "approval already consumed")
        except (KeyError, ReceiptValidationError, GoveZoneError):
            return self._human_loop_denied_result(MCP_RESUME_TOOL, "resume refused")

    def _human_loop_denied_result(self, name: str, reason: str) -> mcp_types.CallToolResult:
        import mcp.types as types

        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=f"gove-zone DENIED {name}: {reason}",
                )
            ],
            structuredContent={
                "decision": "deny",
                "reason": reason,
                "audit_hash": None,
            },
            _meta={"gove_zone": {"decision": "deny", "audit_hash": None}},
        )

    # -- MCP result builders (§3.3) ---------------------------------------- #

    def _wrap_allow_result(
        self, downstream_result: mcp_types.CallToolResult, record: Any, audit_hash: str
    ) -> mcp_types.CallToolResult:
        """Re-wrap the downstream result, stamping gove-zone provenance in _meta.

        Preserves the downstream's ``isError`` (a downstream tool-level failure
        after an authorised ALLOW still surfaces as isError to the host, F7).
        """
        import mcp.types as types

        meta = dict(downstream_result.meta or {})
        meta["gove_zone"] = {
            "decision": record.decision.value,
            "audit_hash": audit_hash,
            "decision_request_hash": record.decision_request_hash,
        }
        return types.CallToolResult(
            content=list(downstream_result.content),
            structuredContent=downstream_result.structuredContent,
            isError=bool(downstream_result.isError),
            _meta=meta,
        )

    def _deny_result(self, record: Any, audit_hash: str, name: str) -> mcp_types.CallToolResult:
        import mcp.types as types

        envelope = rejection_dict(record, audit_hash, resumable=False, resolution=REVISE_AND_RETRY)
        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=f"gove-zone DENIED {name}: {envelope['reason']} "
                    f"[rules: {', '.join(envelope['matched_rules']) or 'none'}]",
                )
            ],
            structuredContent=envelope,
            _meta={"gove_zone": {"decision": "deny", "audit_hash": audit_hash}},
        )

    def _escalate_result(self, record: Any, audit_hash: str, name: str) -> mcp_types.CallToolResult:
        import mcp.types as types

        envelope = rejection_dict(
            record,
            audit_hash,
            resumable=True,
            resolution=HUMAN_APPROVAL,
            approval={
                "via": "approve_escalation",
                "event_id": record.event_id,
                "how_to_approve": (
                    "tools/call gove.approve {event_id} from an approver "
                    "session, or gove-zone approve-escalation --pending <descriptor>"
                ),
            },
        )
        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=f"gove-zone ESCALATED {name}: awaiting human approval "
                    f"(event {record.event_id})",
                )
            ],
            structuredContent=envelope,
            _meta={
                "gove_zone": {
                    "decision": "escalate",
                    "audit_hash": audit_hash,
                    "escalation_event_id": record.event_id,
                }
            },
        )

    def _unmapped_principal_result(self, name: str) -> mcp_types.CallToolResult:
        import mcp.types as types

        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text="gove-zone DENIED: no governed principal is mapped for this "
                    "MCP session; call refused",
                )
            ],
            structuredContent={
                "decision": "deny",
                "reason": "unmapped session principal; call refused",
                "audit_hash": None,
            },
            _meta={"gove_zone": {"decision": "deny", "audit_hash": None}},
        )

    def _audit_unrecordable_result(self) -> mcp_types.CallToolResult:
        """Fixed, leak-safe DENY envelope for an audit-append failure (F6).

        No request-derived text, no tool name, no args, no exception message.
        """
        import mcp.types as types

        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text="gove-zone DENIED: governance evidence could not be recorded; "
                    "call refused",
                )
            ],
            structuredContent={
                "decision": "deny",
                "reason": "governance evidence could not be recorded; call refused",
                "audit_hash": None,
            },
            _meta={"gove_zone": {"decision": "deny", "audit_hash": None}},
        )

    def _governance_error_result(self) -> mcp_types.CallToolResult:
        import mcp.types as types

        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text="gove-zone DENIED: governance error; call refused",
                )
            ],
            structuredContent={
                "decision": "deny",
                "reason": "governance error",
                "audit_hash": None,
            },
            _meta={"gove_zone": {"decision": "deny", "audit_hash": None}},
        )

    def _capacity_rejected_result(
        self, name: str, audit_hash: str | None
    ) -> mcp_types.CallToolResult:
        """Leak-safe DENY envelope when escalation capacity is exhausted.

        Mirrors the other leak-safe builders: the tool ``name`` is the only
        request-derived text (no args, no policy internals). ``audit_hash`` is
        the anchor of the recorded capacity-rejection event.
        """
        import mcp.types as types

        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=f"gove-zone DENIED {name}: escalation capacity exhausted; call refused",
                )
            ],
            structuredContent={
                "decision": "deny",
                "reason": "escalation capacity exhausted; call refused",
                "audit_hash": audit_hash,
            },
            _meta={"gove_zone": {"decision": "deny", "audit_hash": audit_hash}},
        )

    def _gate_refused_result(
        self, name: str, exc: ReceiptValidationError
    ) -> mcp_types.CallToolResult:
        """Leak-safe envelope when the receipt gate refuses execution.

        Conveys the stable machine-readable reason code (never the message text,
        which carries hashes/field values).
        """
        import mcp.types as types

        reason_code = getattr(exc, "reason_code", None)
        code = reason_code.value if reason_code is not None else "RECEIPT_REJECTED"
        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=f"gove-zone DENIED {name}: receipt gate refused execution [{code}]",
                )
            ],
            structuredContent={"decision": "deny", "reason_code": code, "audit_hash": None},
            _meta={"gove_zone": {"decision": "deny", "reason_code": code}},
        )

    def _downstream_failure_result(self, name: str, audit_hash: str) -> mcp_types.CallToolResult:
        """Leak-safe envelope when the downstream forward raised after ALLOW (F7).

        The ALLOW is already audited; convey the failure without the downstream
        exception text.
        """
        import mcp.types as types

        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=f"gove-zone: authorized call to {name} failed downstream; "
                    "see the audit chain",
                )
            ],
            structuredContent={
                "decision": "allow",
                "outcome": "execution_failed",
                "audit_hash": audit_hash,
            },
            _meta={"gove_zone": {"decision": "allow", "audit_hash": audit_hash}},
        )


def _lift_path(arguments: Mapping[str, Any]) -> tuple[str, ...]:
    """Lift a path-shaped argument into the governed path context (mirrors
    :func:`gove_zone.mcp.mcp_tools_call`) so path-boundary policies can match a
    string OR list-segmented path. The argument still reaches the tool
    unchanged.
    """
    from gove_zone.tool import normalize_path_context

    path = arguments.get("path")
    if isinstance(path, (str, list, tuple)):
        return normalize_path_context(path)
    return ()


def build_gateway_server(config: GatewayConfig, downstream: ClientSession) -> Server:
    """Convenience: build the host-facing MCP server for *config* + *downstream*.

    Loud :class:`RuntimeError` if the ``mcp`` SDK is not installed.
    """
    _require_mcp()
    return GovernedGateway(config, downstream).build_server()


async def run_stdio_gateway(config: GatewayConfig) -> None:
    """Run the governed gateway over stdio (the alpha runtime entrypoint).

    Spawns the configured downstream MCP server as a subprocess, fronts it, and
    serves the host on this process's stdin/stdout. The downstream client session
    is constructed with **no sampling callback**, so a downstream
    ``sampling/createMessage`` reverse-channel request is refused at the gateway
    and never bridged to the host — the sampling denial is thus a real property
    of the runtime here, not merely a test-harness artifact. ``config.allow_sampling``
    is reserved and not yet honoured (real opt-in requires bridging
    downstream→host sampling, a documented follow-up).

    This is the one runtime-transport piece that is not unit-tested (it needs
    subprocess orchestration across three processes); every SDK API it composes
    is exercised individually by the in-memory conformance suite, and the
    governed decision core it wraps is fully covered there.
    """
    _require_mcp()
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.server.stdio import stdio_server

    command = list(config.downstream.get("command", ()))
    if not command:
        raise ValueError(
            "run_stdio_gateway requires a downstream.command (argv) in the gateway config"
        )
    params = StdioServerParameters(command=command[0], args=command[1:])
    # No sampling_callback on the downstream session -> the downstream reverse
    # LLM channel is denied.
    async with (
        stdio_client(params) as (downstream_read, downstream_write),
        ClientSession(downstream_read, downstream_write) as downstream,
    ):
        await downstream.initialize()
        server = GovernedGateway(config, downstream).build_server()
        async with stdio_server() as (host_read, host_write):
            await server.run(host_read, host_write, server.create_initialization_options())


# --------------------------------------------------------------------------- #
# Pending-escalation (de)serialization — the descriptor the CLI approve verb
# consumes out-of-band. Dependency-free (no mcp SDK).
# --------------------------------------------------------------------------- #


def _record_from_dict(data: Mapping[str, Any]) -> DecisionRecord:
    kwargs: dict[str, Any] = {
        "decision": Decision(data["decision"]),
        "tool": str(data["tool"]),
        "argument_hash": str(data["argument_hash"]),
        "policy_version": str(data["policy_version"]),
        "event_id": str(data["event_id"]),
        "matched_rules": tuple(data.get("matched_rules", ())),
        "reason": str(data.get("reason", "")),
        "transformed_args": data.get("transformed_args"),
        "goal": str(data.get("goal", "")),
        "actor": str(data.get("actor", "")),
        "path": tuple(data.get("path", ())),
        "state_hash": data.get("state_hash"),
        "decision_request_hash": str(data.get("decision_request_hash", "")),
    }
    if data.get("timestamp_iso"):
        kwargs["timestamp_iso"] = str(data["timestamp_iso"])
    return DecisionRecord(**kwargs)


def pending_to_dict(pending: PendingApproval) -> dict[str, Any]:
    """Serialize a parked escalation into a portable descriptor.

    The descriptor carries the full ESCALATE record and the exact proposed args
    (needed to bind the approval), so it is operator-sensitive — hold it with the
    same care as the audit chain. This is the out-of-band artifact the
    ``gove-zone approve-escalation`` CLI verb consumes.
    """
    return {
        "record": pending.record.to_dict(),
        "audit_hash": pending.audit_hash,
        "args": dict(pending.args),
    }


def pending_from_dict(data: Mapping[str, Any]) -> PendingApproval:
    """Reconstruct a :class:`~gove_zone.escalation.PendingApproval` from a
    descriptor produced by :func:`pending_to_dict`. Fail-closed: a non-ESCALATE
    record is rejected by ``PendingApproval.__post_init__``."""
    return PendingApproval(
        _record_from_dict(data["record"]),
        str(data["audit_hash"]),
        dict(data.get("args", {})),
    )
