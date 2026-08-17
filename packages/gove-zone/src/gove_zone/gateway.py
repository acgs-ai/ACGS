"""Universal Agent Gateway — one strong gate, many agent-framework surfaces.

Execution-owning framework surfaces (MCP, OpenAI function calling, LangGraph,
REST) are thin *projections* onto :meth:`UniversalGateway.invoke`, which drives
the full Policy → Receipt → Executor chain:

1. **Policy** — :meth:`~gove_zone.kernel.Kernel.evaluate_and_record` evaluates
   the call under the fail-closed watchdog and appends exactly one decision to
   the chain-hash audit store *before* anything runs.
2. **Receipt** — an ALLOW/TRANSFORM decision mints a
   :class:`~gove_zone.receipt.DecisionReceipt` (signed under a production
   profile) bound to tenant, boundary, action, arguments, actor, audit anchor
   and policy hash.
3. **Executor** — the side effect runs only inside
   :func:`~gove_zone.executor.execute_with_receipt`, which re-verifies the
   receipt against gate-held expectations and burns it in the single-use
   consumption ledger before the tool function is called.

No surface has its own gate: a surface handler that skipped ``invoke`` would
have no receipt to present and the executor gate would refuse it. This is the
strong-gate unification of the weaker per-framework adapters
(:mod:`gove_zone.adapters`, :mod:`gove_zone.mcp`) that route through
``Kernel.dispatch`` without signed receipts or a consumption ledger.

**Bypass detection.** ``register_tool`` never returns the raw callable — it
returns a :class:`SealedTool`. A sealed tool only executes while the gateway's
in-flight gate grant authorizes exactly that sealed instance for exactly one
call; any other invocation through the handle (direct call, a tool internally
calling another sealed tool, a re-entrant call after the one-shot grant is
spent) is **blocked before the side effect**, recorded as a synthesized DENY
on the audit chain with matched rule ``BYPASS_ATTEMPT``, and raised as
:class:`BypassAttemptError`. :meth:`UniversalGateway.bypass_attempts` lists
attempts observed in-process; the audit chain is the tamper-evident record.

Trust boundary: this detection covers every call *through the sealed handle*.
It is a same-process guardrail against framework- and integration-level
bypass, not a defense against hostile same-process Python — code that
introspects closures or object internals can reach the raw function without
tripping it. The cryptographic closure remains the signed receipt gate plus
offline verification of the audit chain and consumption ledger.

The Claude Code hook is deliberately different: it is a policy-decision, audit,
and receipt-minting mediation surface, not a projection onto ``invoke``. The
side effect there is executed by the host runtime, which must honor the
returned deny. That matches the :mod:`gove_zone.integration` gate-mode story;
it cannot be receipt-gated at the executor because the gateway does not run
the tool. Every other surface executes through the receipt gate.

Escalation park/approve/resume is implemented at :meth:`UniversalGateway.invoke`
via reserved tools ``gove.approve`` / ``gove.resume``. The MCP adapter
(:class:`gove_zone.adapters.mcp_gateway.GovernedGateway`) owns the same loop
for the stdio proxy; this gateway is the strong-gate projection.

Zero runtime dependencies, matching the package: the MCP / OpenAI / REST
surfaces operate on plain dicts; the LangGraph surface lazily imports
``langchain_core`` only when used.
"""

from __future__ import annotations

import contextvars
import inspect
import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.capture import (
    CaptureConfig,
    CaptureError,
    CaptureMode,
    CaptureRecord,
    capture_observation,
    capture_record_for_decision,
)
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.errors import (
    AuditError,
    GoveZoneError,
    ProductionProfileError,
    ReceiptValidationError,
    UnknownToolError,
)
from gove_zone.escalation import PendingApproval, approve_escalation
from gove_zone.executor import execute_with_receipt
from gove_zone.integration import tool_calls_from_hook_payload
from gove_zone.kernel import Kernel
from gove_zone.policy import Policy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.rejection import HUMAN_APPROVAL, REVISE_AND_RETRY, rejection_dict
from gove_zone.tool import ToolCall, normalize_path_context
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustRegistry

__all__ = [
    "BypassAttemptError",
    "GatewayResult",
    "MCP_APPROVE_TOOL",
    "MCP_HUMAN_LOOP_TOOLS",
    "MCP_RESUME_TOOL",
    "SealedTool",
    "UniversalGateway",
    "http_json_tool",
]

MCP_APPROVE_TOOL = "gove.approve"
MCP_RESUME_TOOL = "gove.resume"
MCP_HUMAN_LOOP_TOOLS = frozenset({MCP_APPROVE_TOOL, MCP_RESUME_TOOL})

#: matched_rules marker stamped on the synthesized DENY for a bypass attempt.
BYPASS_RULE = "BYPASS_ATTEMPT"

#: policy_version stamped on gateway-synthesized records (bypass attempts,
#: actor-allowlist denials). Distinct from any real policy version so audit
#: consumers can tell gate-synthesized denials from policy verdicts.
_SYNTHETIC_POLICY_VERSION = "gateway/synthesized/v1"

_ACTOR_ALLOWLIST_RULE = "ACTOR_NOT_ALLOWED"
HUMAN_LOOP_REFUSED_RULE = "HUMAN_LOOP_REFUSED"
CAPACITY_REJECTED_RULE = "CAPACITY_REJECTED"

#: One-shot execution grant bound to a specific SealedTool *instance*. Set by
#: ``invoke`` immediately around the executor gate; consumed by that sealed
#: tool before the raw function runs, so a nested or repeated call inside the
#: same gate window — or a stale same-named handle — finds no usable grant and
#: is detected as a bypass.
_ACTIVE_GRANT: contextvars.ContextVar[_GateGrant | None] = contextvars.ContextVar(
    "gove_zone_gateway_grant", default=None
)


class BypassAttemptError(GoveZoneError):
    """A sealed tool was invoked outside the receipt-gated execution path.

    The side effect did NOT run. The attempt is recorded on the audit chain as
    a synthesized DENY with matched rule :data:`BYPASS_RULE`.
    """

    def __init__(self, tool: str) -> None:
        super().__init__(
            f"bypass attempt blocked: sealed tool {tool!r} was called outside "
            "the receipt-gated execution path (no active gate grant)"
        )
        self.tool = tool


class _GateGrant:
    """Single-use permission for one specific SealedTool instance to run once.

    Identity-bound (``sealed is ...``), not name-bound: a stale handle left
    over from a replaced registration can never consume a grant issued for the
    currently registered tool of the same name.
    """

    __slots__ = ("sealed", "spent")

    def __init__(self, sealed: SealedTool) -> None:
        self.sealed = sealed
        self.spent = False


class SealedTool:
    """The only callable handle the gateway hands out for a registered tool.

    Calling it executes the underlying function *only* when the gateway has an
    unspent gate grant for this exact sealed instance in the current context —
    i.e. only as the ``tool_fn`` of
    :func:`~gove_zone.executor.execute_with_receipt` inside
    :meth:`UniversalGateway.invoke`. Every other call *through this handle* is
    blocked, audited, and raised as :class:`BypassAttemptError` before any
    side effect.

    Trust boundary: the raw function is captured in a closure rather than
    stored as an attribute, so no supported attribute path reaches it — but
    same-process Python that introspects closure cells can still extract it
    without tripping detection. This is a guardrail against accidental and
    framework-level bypass, not a sandbox; see the module docstring.
    """

    __slots__ = ("_execute", "_gateway", "name")

    def __init__(self, name: str, fn: Callable[..., Any], gateway: UniversalGateway) -> None:
        self.name = name
        self._gateway = gateway

        def _execute(kwargs: dict[str, Any]) -> Any:
            return fn(**kwargs)

        self._execute = _execute

    def __call__(self, **kwargs: Any) -> Any:
        grant = _ACTIVE_GRANT.get()
        if grant is None or grant.sealed is not self or grant.spent:
            self._gateway._record_bypass_attempt(self.name, kwargs)
            raise BypassAttemptError(self.name)
        # One-shot: spend the grant BEFORE the side effect so a tool that
        # re-enters itself (or another sealed tool) inside its own execution
        # is detected rather than silently authorized.
        grant.spent = True
        return self._execute(kwargs)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"SealedTool({self.name!r})"


@dataclass(frozen=True)
class GatewayResult:
    """Uniform outcome of one governed invocation, shared by every surface.

    ``status`` is one of:

    - ``"executed"`` — receipt verified, ledger burned, tool ran; ``result``
      and ``receipt`` are set.
    - ``"approved"`` — a parked ESCALATE was approved via ``gove.approve``;
      ``receipt`` is the approval receipt; the original tool did **not** run.
    - ``"denied"`` / ``"escalated"`` — policy refused; ``envelope`` carries the
      machine-readable rejection (:func:`gove_zone.rejection.rejection_dict`).
      Nothing executed. An ``"escalated"`` result is parked and resumable.
    - ``"error"`` — fail-closed refusal (audit append failed, receipt gate
      refused, tool raised). ``error_class`` conveys the class name only; the
      leak posture matches :mod:`gove_zone.mcp` (no exception text that could
      echo raw arguments). Nothing executed except in the tool-raised case,
      where the ALLOW decision is already on the audit chain.
    """

    status: str
    tool: str
    actor: str
    audit_hash: str = ""
    result: Any = None
    receipt: DecisionReceipt | None = None
    envelope: dict[str, Any] | None = None
    error_class: str = ""

    @property
    def executed(self) -> bool:
        return self.status == "executed"

    def receipt_anchors(self) -> dict[str, Any]:
        """Leak-safe receipt commitments for surface payloads (no raw args)."""
        if self.receipt is None:
            return {}
        return {
            "receipt_hash": self.receipt.receipt_hash,
            "audit_hash": self.audit_hash,
            "policy_hash": self.receipt.policy_hash,
            "signature_algorithm": self.receipt.signature_algorithm,
            # Schema version, so a transport surface can tell a scoped (v2)
            # authorization from an unscoped (v1) one without the receipt body.
            "receipt_schema_version": self.receipt.receipt_schema_version,
        }

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "tool": self.tool,
            "actor": self.actor,
            "audit_hash": self.audit_hash,
        }
        if self.status == "executed":
            payload["result"] = self.result
            payload["receipt"] = self.receipt_anchors()
        if self.envelope is not None:
            payload["envelope"] = self.envelope
        if self.error_class:
            payload["error_class"] = self.error_class
        return payload


class UniversalGateway:
    """Framework-neutral governed tool gateway (Policy → Receipt → Executor).

    One instance owns one tenant/boundary contract, one policy, one audit
    chain, and one consumption ledger. Per-actor kernels are derived lazily so
    the acting principal is bound into every decision and receipt — identity
    comes from the integrating surface (session, API auth, hook environment),
    never from a request body.

    ``allowed_actors`` (optional) is a fail-closed principal allowlist: an
    actor outside it is denied with an audited synthesized DENY before policy
    evaluation. ``None`` (default) delegates actor authorization entirely to
    the policy / authz layers.

    ``approver_actors`` are the only principals that may call ``gove.approve``.
    Empty (default) leaves MCP approve unavailable. The set must be disjoint
    from ``allowed_actors`` when that allowlist is set, so a proposing agent
    cannot also be configured as its own approver.

    ``max_pending`` / ``max_pending_per_principal`` bound parked escalations.
    Capacity is freed only by a successful resume, never by a clock. Exceeding
    either cap is an audited DENY and the new escalation is not parked.

    The single-use consumption ledger is always on: every executed receipt is
    burned, so one decision authorizes at most one side effect through this
    gateway even when the profile is not strict.

    **Scoped trust (receipt-v2).** Supplying ``project_id`` + ``environment_id``
    + ``trust_epoch`` + ``trust_registry`` puts every surface of this gateway on
    the scoped receipt-v2 contract: receipts are minted with
    :meth:`~gove_zone.receipt.DecisionReceipt.from_record_v2` and the gate
    resolves the signing key through the registry for the full
    tenant/project/environment/purpose scope before any side effect (see
    :mod:`gove_zone.trust`). Scoped mode is all-or-nothing and fail-closed at
    construction: a partial scope, a missing ``trust_registry``, a profile with
    no ``signer``, or no ``receipt_ttl_seconds`` raises ``ValueError`` rather
    than silently downgrading to unscoped v1 receipts. There is no bypass flag —
    ``trust_registry`` is threaded into the gate unconditionally, so a v2
    receipt presented to an unscoped gateway is refused by
    :func:`~gove_zone.executor.execute_with_receipt`.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        execution_boundary: str,
        policy: Policy,
        profile: GovernanceProfile,
        validator: Validator,
        authority: str,
        policy_bundle_id: str = "",
        audit_path: str | Path | None = None,
        ledger: ReceiptConsumptionLedger | None = None,
        ledger_path: str | Path | None = None,
        receipt_ttl_seconds: float | None = None,
        allowed_actors: frozenset[str] | set[str] | None = None,
        capture_config: CaptureConfig | None = None,
        project_id: str = "",
        environment_id: str = "",
        trust_epoch: int | None = None,
        trust_registry: ReceiptTrustRegistry | None = None,
        trust_purpose: str = DECISION_RECEIPT_PURPOSE,
        approver_actors: frozenset[str] | set[str] | None = None,
        max_pending: int = 256,
        max_pending_per_principal: int = 64,
    ) -> None:
        self.tenant_id = tenant_id
        self.execution_boundary = execution_boundary
        self.policy = policy
        self.profile = profile
        self.validator = validator
        self.authority = authority
        self.policy_bundle_id = policy_bundle_id or policy.version
        self.receipt_ttl_seconds = receipt_ttl_seconds
        self.allowed_actors = frozenset(allowed_actors) if allowed_actors is not None else None
        self.capture_config = capture_config
        self.project_id = project_id
        self.environment_id = environment_id
        self.trust_epoch = trust_epoch
        self.trust_registry = trust_registry
        self.trust_purpose = trust_purpose
        self.scoped_trust = self._resolve_scoped_trust()
        self.approver_actors = frozenset(approver_actors or ())
        if self.allowed_actors is not None:
            clash = sorted(self.allowed_actors & self.approver_actors)
            if clash:
                raise ValueError(
                    "approver_actors collide with allowed_actors "
                    f"{clash}; a proposing actor must not be able to self-approve"
                )
        if max_pending <= 0 or max_pending_per_principal <= 0:
            raise ValueError(
                "escalation capacity caps must be positive: "
                f"max_pending={max_pending}, "
                f"max_pending_per_principal={max_pending_per_principal}"
            )
        self.max_pending = max_pending
        self.max_pending_per_principal = max_pending_per_principal

        if profile.require_expiry and receipt_ttl_seconds is None:
            # Fail loud at construction instead of rejecting 100% of calls at
            # the gate: a require_expiry profile with no TTL would mint only
            # expires_at="" receipts, and every one would be refused.
            raise ValueError(
                "the governance profile requires receipt expiry "
                "(require_expiry=True) but receipt_ttl_seconds is None; every "
                "minted receipt would be rejected at the gate — supply "
                "receipt_ttl_seconds"
            )
        if (
            profile.is_production
            and capture_config is not None
            and capture_config.mode in (CaptureMode.BEST_EFFORT, CaptureMode.DISABLED)
        ):
            raise ValueError(
                "production profile rejects BEST_EFFORT and DISABLED runtime capture modes; "
                "use REQUIRED capture or omit capture_config for legacy compatibility"
            )

        resolved_audit = Path(audit_path or Path(".gove-zone") / "gateway-audit.jsonl")
        resolved_audit.parent.mkdir(parents=True, exist_ok=True)
        self._audit = ChainHashAuditStore(str(resolved_audit))

        profile_ledger = profile.consumption_ledger
        if profile_ledger is not None:
            # Mirror adapters.mcp_gateway: two live ledgers would be two
            # sources of truth for "already spent" — fail loud, not split.
            if ledger is not None and ledger is not profile_ledger:
                raise ValueError(
                    "ambiguous consumption ledger: the governance profile and the "
                    "gateway constructor both supply one; configure it in exactly "
                    "one place"
                )
            self._ledger = profile_ledger
        elif ledger is not None:
            self._ledger = ledger
        else:
            resolved_ledger = Path(ledger_path or Path(".gove-zone") / "gateway-ledger.jsonl")
            resolved_ledger.parent.mkdir(parents=True, exist_ok=True)
            self._ledger = ReceiptConsumptionLedger(str(resolved_ledger))

        self._tools: dict[str, SealedTool] = {}
        self._openai_specs: dict[str, dict[str, Any]] = {}
        self._kernels: dict[str, Kernel] = {}
        self._bypass_attempts: list[dict[str, Any]] = []
        self._pending: dict[str, PendingApproval] = {}
        self._approvals: dict[str, tuple[DecisionReceipt, str]] = {}

    def _resolve_scoped_trust(self) -> bool:
        """Decide (and validate) whether this gateway runs the v2 scoped contract.

        Fail loud at construction rather than at every call, matching the
        ``require_expiry`` precedent above: a gateway configured for a scope it
        cannot satisfy would mint receipts that are refused 100% of the time —
        or, worse, quietly fall back to unscoped v1. Scoped trust is
        all-or-nothing: naming any part of the scope commits to all of it.
        """
        requested = (
            bool(self.project_id)
            or bool(self.environment_id)
            or self.trust_epoch is not None
            or self.trust_registry is not None
        )
        if not requested:
            return False

        missing: list[str] = []
        if not self.project_id or not self.project_id.strip():
            missing.append("project_id")
        if not self.environment_id or not self.environment_id.strip():
            missing.append("environment_id")
        if type(self.trust_epoch) is not int or self.trust_epoch <= 0:
            missing.append("trust_epoch (a positive integer)")
        if self.trust_registry is None:
            missing.append("trust_registry")
        if self.profile.signer is None:
            missing.append("a profile signer (receipt v2 must carry a trusted signature)")
        if self.receipt_ttl_seconds is None:
            missing.append("receipt_ttl_seconds (receipt v2 requires expires_at)")
        if not isinstance(self.trust_purpose, str) or not self.trust_purpose.strip():
            missing.append("trust_purpose")
        if missing:
            raise ValueError(
                "scoped receipt-v2 trust is all-or-nothing and fail-closed; this "
                "gateway names a scoped-trust setting but is missing: " + ", ".join(missing)
            )
        return True

    # -- registry ----------------------------------------------------------- #

    def register_tool(self, name: str, fn: Callable[..., Any]) -> SealedTool:
        """Register *fn* under *name* and return its sealed handle.

        The raw callable is never exposed again through the gateway: surfaces
        and integrators only ever see the :class:`SealedTool`.

        Fail-closed on duplicates (matching
        :meth:`gove_zone.tool.ToolRegistry.register`): silently replacing a
        tool would leave stale sealed handles for the same name in circulation.
        """
        if not name or not name.strip():
            raise ValueError("tool name is required")
        if name in MCP_HUMAN_LOOP_TOOLS:
            raise ValueError(
                f"tool {name!r} is reserved for the human-approval loop and "
                "cannot be registered as an executable tool"
            )
        if name in self._tools:
            raise ValueError(f"tool {name!r} is already registered with this gateway")
        sealed = SealedTool(name, fn, self)
        self._tools[name] = sealed
        # Capture the OpenAI function spec now so the raw callable does not
        # need to be retained anywhere outside the sealed closure.
        self._openai_specs[name] = _openai_function_spec(name, fn)
        return sealed

    def tool(self, name: str) -> Callable[[Callable[..., Any]], SealedTool]:
        """Decorator form of :meth:`register_tool`."""

        def decorator(fn: Callable[..., Any]) -> SealedTool:
            return self.register_tool(name, fn)

        return decorator

    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    # -- the single chokepoint ---------------------------------------------- #

    def invoke(
        self,
        actor: str,
        tool: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> GatewayResult:
        """Run one governed tool call through Policy → Receipt → Executor.

        Raises :class:`~gove_zone.errors.UnknownToolError` for unregistered
        tools (structural admission: not registered == not callable) and
        :class:`~gove_zone.errors.ProductionProfileError` for a production
        profile with no verifier (loud misconfiguration, never an envelope).
        Every other refusal is returned as a fail-closed :class:`GatewayResult`
        so transport surfaces can project it without exception plumbing.
        """
        if not actor or not actor.strip():
            raise ValueError("actor is required for governed invocation (fail-closed)")
        if tool in MCP_HUMAN_LOOP_TOOLS:
            return self._human_loop_invoke(actor, tool, dict(args or {}))
        if tool not in self._tools:
            raise UnknownToolError(tool)

        call = ToolCall(
            name=tool,
            args=dict(args or {}),
            goal=goal,
            actor=actor,
            path=normalize_path_context(path),
            state=dict(state or {}),
        )

        if self.allowed_actors is not None and actor not in self.allowed_actors:
            record, audit_hash = self._append_synthesized_deny(
                call,
                rule=_ACTOR_ALLOWLIST_RULE,
                reason=f"actor {actor!r} is not in the gateway actor allowlist",
            )
            return GatewayResult(
                status="denied",
                tool=tool,
                actor=actor,
                audit_hash=audit_hash,
                envelope=rejection_dict(
                    record, audit_hash, resumable=False, resolution=HUMAN_APPROVAL
                ),
            )

        previous_audit_hash = self._audit.last_hash()
        try:
            record, audit_hash = self._kernel_for(actor).evaluate_and_record(call)
        except AuditError:
            # Decision could not be recorded -> nothing may run.
            return GatewayResult(status="error", tool=tool, actor=actor, error_class="AuditError")
        except GoveZoneError as exc:
            return GatewayResult(
                status="error", tool=tool, actor=actor, error_class=type(exc).__name__
            )

        if record.decision is Decision.DENY:
            return GatewayResult(
                status="denied",
                tool=tool,
                actor=actor,
                audit_hash=audit_hash,
                envelope=rejection_dict(
                    record, audit_hash, resumable=False, resolution=REVISE_AND_RETRY
                ),
            )
        if record.decision is Decision.ESCALATE:
            capacity = self._enforce_pending_capacity(call, actor, tool)
            if capacity is not None:
                return capacity
            pending = PendingApproval(record, audit_hash, dict(call.args))
            self._pending[record.event_id] = pending
            return GatewayResult(
                status="escalated",
                tool=tool,
                actor=actor,
                audit_hash=audit_hash,
                envelope=rejection_dict(
                    record,
                    audit_hash,
                    resumable=True,
                    resolution=HUMAN_APPROVAL,
                    approval={
                        "via": "approve_escalation",
                        "event_id": record.event_id,
                        "how_to_approve": (
                            "tools/call gove.approve {event_id} as an approver_actors principal"
                        ),
                    },
                ),
            )
        if record.decision is Decision.TRANSFORM and record.transformed_args is None:
            # Policy bug: TRANSFORM without replacement args. Fail closed.
            return GatewayResult(
                status="error",
                tool=tool,
                actor=actor,
                audit_hash=audit_hash,
                error_class="TransformWithoutArgs",
            )

        exec_args = (
            dict(record.transformed_args)
            if record.decision is Decision.TRANSFORM and record.transformed_args is not None
            else dict(call.args)
        )

        try:
            self._capture_before_receipt(record, audit_hash)
        except CaptureError as exc:
            return GatewayResult(
                status="error",
                tool=tool,
                actor=actor,
                audit_hash=audit_hash,
                error_class=type(exc).__name__,
            )

        receipt = self._mint_receipt(record, audit_hash, previous_audit_hash)

        grant = _GateGrant(self._tools[tool])
        token = _ACTIVE_GRANT.set(grant)
        try:
            result = execute_with_receipt(
                tool_fn=self._tools[tool],
                args=exec_args,
                receipt=receipt,
                expected_tenant_id=self.tenant_id,
                expected_execution_boundary=self.execution_boundary,
                expected_action=tool,
                expected_actor=actor,
                expected_audit_hash=audit_hash,
                policy=self.policy,
                **self._gate_kwargs(),
            )
        except ProductionProfileError:
            # Misconfiguration (production posture, no verifier): fail loud,
            # never degrade into a per-call error envelope.
            raise
        except ReceiptValidationError as exc:
            return GatewayResult(
                status="error",
                tool=tool,
                actor=actor,
                audit_hash=audit_hash,
                error_class=type(exc).__name__,
            )
        except BypassAttemptError:
            raise
        except Exception as exc:  # noqa: BLE001 - tool fn raised mid-execution
            # The ALLOW decision is already audited; convey the class only
            # (exception text may echo raw arguments).
            return GatewayResult(
                status="error",
                tool=tool,
                actor=actor,
                audit_hash=audit_hash,
                error_class=type(exc).__name__,
            )
        finally:
            _ACTIVE_GRANT.reset(token)

        return GatewayResult(
            status="executed",
            tool=tool,
            actor=actor,
            audit_hash=audit_hash,
            result=result,
            receipt=receipt,
        )

    def _capture_before_receipt(self, record: DecisionRecord, audit_hash: str) -> None:
        """Persist configured D2 capture evidence before minting a receipt.

        Capture is intentionally an issuer-path precondition only. It does not
        feed the executor and it does not alter the DecisionReceipt schema.
        """

        config = self.capture_config
        if config is None:
            return
        if config.mode is CaptureMode.DISABLED:
            return
        capture = self._capture_record(record, audit_hash, outcome="captured")
        if config.mode is CaptureMode.REQUIRED:
            if config.store is None or config.observation_sink is None:
                raise CaptureError("required capture mode is missing a store or observation sink")
            try:
                ack = config.store.append(capture)
                ack.validate_for(capture)
                config.observation_sink.append(capture_observation("capture_persisted", capture))
            except CaptureError as exc:
                self._emit_capture_failed_observation(capture, exc)
                raise
            except Exception as exc:  # noqa: BLE001 - any required-capture failure blocks
                self._emit_capture_failed_observation(capture, exc)
                raise CaptureError("required capture failed") from exc
            return

        try:
            if config.store is None:
                raise CaptureError("best-effort capture mode has no store")
            ack = config.store.append(capture)
            ack.validate_for(capture)
            if config.observation_sink is not None:
                config.observation_sink.append(capture_observation("capture_persisted", capture))
        except Exception as exc:  # noqa: BLE001 - best-effort must not authorize by silence
            failed = self._capture_record(
                record,
                audit_hash,
                outcome="capture_failed",
                reason="best-effort-capture-failed",
            )
            if config.observation_sink is not None:
                try:
                    config.observation_sink.append(
                        capture_observation(
                            "capture_failed", failed, error_class=type(exc).__name__
                        )
                    )
                except Exception:
                    # Local/dev best-effort mode is explicitly non-authoritative:
                    # a failed observation must not be upgraded into a capture
                    # success claim, but it also must not block execution.
                    return

    def _emit_capture_failed_observation(self, capture: CaptureRecord, exc: Exception) -> None:
        config = self.capture_config
        if config is None or config.observation_sink is None:
            return
        failed = capture_record_for_decision(
            tenant_id=capture.tenant_id,
            event_id=capture.event_id,
            audit_event_hash=capture.audit_event_hash,
            policy_bundle_id=capture.policy_bundle_id,
            policy_version=capture.policy_version,
            policy_hash=capture.policy_hash,
            evaluator_version=capture.evaluator_version,
            projection_version=capture.projection_version,
            decision_time=capture.decision_time,
            field_status=capture.field_status,
            privacy_outcome=capture.privacy_outcome,
            capture_outcome="capture_failed",
            capture_reason="required-capture-failed",
        )
        try:
            config.observation_sink.append(
                capture_observation("capture_failed", failed, error_class=type(exc).__name__)
            )
        except Exception:
            # REQUIRED still blocks issuance. The secondary observation failure
            # must not hide the original capture failure or permit a receipt.
            return

    def _capture_record(
        self,
        record: DecisionRecord,
        audit_hash: str,
        *,
        outcome: str,
        reason: str = "captured-after-audit-before-receipt",
    ) -> CaptureRecord:
        config = self.capture_config
        if config is None:
            raise CaptureError("capture is not configured")
        return capture_record_for_decision(
            tenant_id=self.tenant_id,
            event_id=record.event_id,
            audit_event_hash=audit_hash,
            policy_bundle_id=self.policy_bundle_id,
            policy_version=record.policy_version,
            policy_hash=self.policy.version,
            evaluator_version=config.evaluator_version,
            projection_version=config.projection_version,
            decision_time=record.timestamp_iso,
            field_status=config.field_status,
            privacy_outcome=config.privacy_outcome,
            capture_outcome=outcome,
            capture_reason=reason,
        )

    def _human_loop_invoke(self, actor: str, tool: str, args: dict[str, Any]) -> GatewayResult:
        event_id = args.get("event_id")
        if set(args) != {"event_id"} or not isinstance(event_id, str) or not event_id.strip():
            return self._human_loop_denied(
                actor, tool, "invalid reserved-tool arguments", code="invalid_args"
            )
        if tool == MCP_APPROVE_TOOL:
            return self._approve_pending(actor, event_id)
        return self._resume_pending(actor, event_id)

    def _approve_pending(self, actor: str, event_id: str) -> GatewayResult:
        if actor not in self.approver_actors:
            return self._human_loop_denied(
                actor, MCP_APPROVE_TOOL, "caller is not a mapped approver", code="not_approver"
            )
        pending = self._pending.get(event_id)
        if pending is None:
            return self._human_loop_denied(
                actor, MCP_APPROVE_TOOL, "unknown pending event", code="unknown_pending"
            )
        if actor == pending.record.actor:
            return self._human_loop_denied(
                actor, MCP_APPROVE_TOOL, "self-approval is forbidden", code="self_approval"
            )
        try:
            receipt = approve_escalation(
                pending,
                validator=Validator(validator_id=actor, role="approver"),
                authority=self.authority,
                tenant_id=self.tenant_id,
                execution_boundary=self.execution_boundary,
                policy_bundle_id=self.policy_bundle_id,
                policy_hash=self.policy.version,
                audit=self._audit,
                expires_at=self._receipt_expires_at(),
                signer=self.profile.signer,
            )
        except (ReceiptValidationError, GoveZoneError):
            return self._human_loop_denied(
                actor, MCP_APPROVE_TOOL, "approval refused", code="approval_refused"
            )
        self._approvals[event_id] = (receipt, receipt.audit_event_hash)
        return GatewayResult(
            status="approved",
            tool=MCP_APPROVE_TOOL,
            actor=actor,
            audit_hash=receipt.audit_event_hash,
            receipt=receipt,
            envelope={"event_id": event_id, "executed": False},
        )

    def _resume_pending(self, actor: str, event_id: str) -> GatewayResult:
        pending = self._pending.get(event_id)
        if pending is None:
            return self._human_loop_denied(
                actor, MCP_RESUME_TOOL, "unknown pending event", code="unknown_pending"
            )
        if actor != pending.record.actor:
            return self._human_loop_denied(
                actor,
                MCP_RESUME_TOOL,
                "only the proposing actor may resume",
                code="not_proposer",
            )
        captured = self._approvals.get(event_id)
        if captured is None:
            return self._human_loop_denied(
                actor, MCP_RESUME_TOOL, "pending is not approved", code="not_approved"
            )
        receipt, approval_hash = captured
        # Resume is a real execution. Capture uses the parked ESCALATE record
        # (issuer-path evidence) before the sealed receipt gate runs.
        try:
            self._capture_before_receipt(pending.record, approval_hash)
        except CaptureError as exc:
            return GatewayResult(
                status="error",
                tool=MCP_RESUME_TOOL,
                actor=actor,
                error_class=type(exc).__name__,
            )
        sealed = self._tools.get(pending.record.tool)
        if sealed is None:
            return GatewayResult(
                status="error",
                tool=MCP_RESUME_TOOL,
                actor=actor,
                error_class="UnknownToolError",
            )
        grant = _GateGrant(sealed)
        token = _ACTIVE_GRANT.set(grant)
        try:
            result = execute_with_receipt(
                tool_fn=sealed,
                args=dict(pending.args),
                receipt=receipt,
                expected_tenant_id=self.tenant_id,
                expected_execution_boundary=self.execution_boundary,
                expected_action=pending.record.tool,
                expected_actor=pending.record.actor,
                expected_audit_hash=approval_hash,
                policy=self.policy,
                **self._gate_kwargs(),
            )
        except ProductionProfileError:
            raise
        except ReceiptValidationError as exc:
            return GatewayResult(
                status="error",
                tool=MCP_RESUME_TOOL,
                actor=actor,
                error_class=type(exc).__name__,
            )
        except BypassAttemptError:
            raise
        except Exception as exc:  # noqa: BLE001 — tool fn raised mid-execution
            return GatewayResult(
                status="error",
                tool=MCP_RESUME_TOOL,
                actor=actor,
                error_class=type(exc).__name__,
            )
        finally:
            _ACTIVE_GRANT.reset(token)
        del self._pending[event_id]
        self._approvals.pop(event_id, None)
        return GatewayResult(
            status="executed",
            tool=pending.record.tool,
            actor=actor,
            audit_hash=receipt.audit_event_hash,
            result=result,
            receipt=receipt,
        )

    # -- bypass detection ---------------------------------------------------- #

    def bypass_attempts(self) -> tuple[dict[str, Any], ...]:
        """Bypass attempts observed in-process (tamper-evident copy lives on
        the audit chain as synthesized DENY records with rule
        :data:`BYPASS_RULE`)."""
        return tuple(dict(entry) for entry in self._bypass_attempts)

    def _record_bypass_attempt(self, tool: str, kwargs: Mapping[str, Any]) -> None:
        call = ToolCall(name=tool, args=dict(kwargs), actor="<unattributed>")
        try:
            _, audit_hash = self._append_synthesized_deny(
                call,
                rule=BYPASS_RULE,
                reason=(f"sealed tool {tool!r} invoked outside the receipt-gated execution path"),
            )
        except AuditError:
            # The block still stands (the caller raises BypassAttemptError);
            # keep the in-process trace even when the chain is unavailable.
            audit_hash = ""
        self._bypass_attempts.append(
            {
                "tool": tool,
                "argument_hash": call.argument_hash(),
                "audit_hash": audit_hash,
                "timestamp_iso": datetime.now(UTC).isoformat(),
            }
        )

    def _human_loop_denied(self, actor: str, tool: str, reason: str, *, code: str) -> GatewayResult:
        """Audited fail-closed refusal for a reserved approve/resume call."""
        call = ToolCall(name=tool, args={}, actor=actor)
        try:
            record, audit_hash = self._append_synthesized_deny(
                call,
                rule=f"{HUMAN_LOOP_REFUSED_RULE}:{code}",
                reason=reason,
            )
        except AuditError:
            return GatewayResult(
                status="denied",
                tool=tool,
                actor=actor,
                envelope={"decision": "deny", "reason": reason, "audit_hash": None},
            )
        return GatewayResult(
            status="denied",
            tool=tool,
            actor=actor,
            audit_hash=audit_hash,
            envelope=rejection_dict(
                record, audit_hash, resumable=False, resolution=REVISE_AND_RETRY
            ),
        )

    def _enforce_pending_capacity(
        self, call: ToolCall, actor: str, tool: str
    ) -> GatewayResult | None:
        """Refuse a new park when the global or per-principal cap is full."""
        global_full = len(self._pending) >= self.max_pending
        principal_pending = sum(
            1 for pending in self._pending.values() if pending.record.actor == actor
        )
        principal_full = principal_pending >= self.max_pending_per_principal
        if not (global_full or principal_full):
            return None
        scope = "pending" if global_full else "principal"
        try:
            record, audit_hash = self._append_synthesized_deny(
                call,
                rule=f"{CAPACITY_REJECTED_RULE}:{scope}",
                reason="escalation capacity exhausted; call refused",
            )
        except AuditError:
            return GatewayResult(
                status="denied",
                tool=tool,
                actor=actor,
                envelope={
                    "decision": "deny",
                    "reason": "escalation capacity exhausted; call refused",
                    "audit_hash": None,
                },
            )
        return GatewayResult(
            status="denied",
            tool=tool,
            actor=actor,
            audit_hash=audit_hash,
            envelope=rejection_dict(
                record, audit_hash, resumable=False, resolution=REVISE_AND_RETRY
            ),
        )

    def _append_synthesized_deny(
        self, call: ToolCall, *, rule: str, reason: str
    ) -> tuple[DecisionRecord, str]:
        record = DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=_SYNTHETIC_POLICY_VERSION,
            event_id=uuid.uuid4().hex,
            matched_rules=(rule,),
            reason=reason,
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
        )
        event = self._audit.append(record)
        return record, str(event.get("event_hash", ""))

    # -- shared plumbing ------------------------------------------------------ #

    def _kernel_for(self, actor: str) -> Kernel:
        kernel = self._kernels.get(actor)
        if kernel is None:
            kernel = Kernel(policy=self.policy, audit=self._audit, actor=actor)
            self._kernels[actor] = kernel
        return kernel

    def _receipt_expires_at(self) -> str:
        if self.receipt_ttl_seconds is None:
            return ""
        return (datetime.now(UTC) + timedelta(seconds=self.receipt_ttl_seconds)).isoformat()

    def _mint_receipt(
        self, record: DecisionRecord, audit_hash: str, previous_audit_hash: str
    ) -> DecisionReceipt:
        """Mint the receipt for one decision — v2 under scoped trust, else v1."""
        common: dict[str, Any] = {
            "audit_hash": audit_hash,
            "previous_audit_hash": previous_audit_hash,
            "tenant_id": self.tenant_id,
            "execution_boundary": self.execution_boundary,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_hash": self.policy.version,
            "request_id": record.decision_request_hash or record.event_id,
            "validator": self.validator,
            "authority": self.authority,
            "expires_at": self._receipt_expires_at(),
        }
        if not self.scoped_trust:
            return DecisionReceipt.from_record(record, signer=self.profile.signer, **common)
        signer = self.profile.signer
        if signer is None or self.trust_epoch is None:  # pragma: no cover - guarded at __init__
            raise ValueError("scoped receipt-v2 minting requires a signer and a trust epoch")
        return DecisionReceipt.from_record_v2(
            record,
            project_id=self.project_id,
            environment_id=self.environment_id,
            trust_epoch=self.trust_epoch,
            signer=signer,
            **common,
        )

    def _gate_kwargs(self) -> dict[str, Any]:
        # The strict profile's as_gate_kwargs() already emits
        # consumption_ledger; __init__ guarantees self._ledger IS that ledger,
        # so this override only removes the duplicate keyword (same fix as
        # adapters.mcp_gateway._gate_kwargs).
        kwargs = dict(self.profile.as_gate_kwargs())
        kwargs["consumption_ledger"] = self._ledger
        # Threaded unconditionally (``None`` when unscoped) so the executor's
        # fail-closed v2 branch is load-bearing on this path: a receipt-v2
        # presented to a gateway with no registry is refused, never executed.
        kwargs["trust_registry"] = self.trust_registry
        if self.scoped_trust:
            kwargs["trust_purpose"] = self.trust_purpose
            kwargs["expected_project_id"] = self.project_id
            kwargs["expected_environment_id"] = self.environment_id
        return kwargs

    # -- MCP surface ---------------------------------------------------------- #

    def mcp_tools_list(self) -> dict[str, Any]:
        """MCP ``tools/list``: reserved human-loop tools plus the sealed registry."""
        reserved = [{"name": MCP_APPROVE_TOOL}, {"name": MCP_RESUME_TOOL}]
        return {"tools": reserved + [{"name": name} for name in self.tool_names()]}

    def handle_mcp_call(self, request: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
        """Route one MCP ``tools/call`` request (full JSON-RPC or bare params)
        through the strong gate. SDK-free: dict in, MCP result payload out.

        *actor* comes from the transport session (cf. the ``clientInfo``
        principal binding in :mod:`gove_zone.adapters.mcp_gateway`) — never
        from the request body.
        """
        if not isinstance(request, Mapping):
            return _mcp_error("malformed tools/call request: request is not a mapping")
        method = request.get("method")
        if method is not None and method != "tools/call":
            return _mcp_error(f"unsupported method {method!r}; this surface handles tools/call")
        params = request.get("params") if "params" in request else request
        if not isinstance(params, Mapping):
            return _mcp_error("malformed tools/call request: params is not a mapping")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return _mcp_error("malformed tools/call request: missing tool name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, Mapping):
            return _mcp_error("malformed tools/call request: arguments is not a mapping")

        # Lift path-shaped arguments into governed path context (str or
        # sequence, mirroring gove_zone.mcp's PR-5 fix).
        raw_path = arguments.get("path")
        lifted = raw_path if isinstance(raw_path, (str, list, tuple)) else None

        try:
            outcome = self.invoke(actor, name, arguments, path=lifted)
        except UnknownToolError:
            return _mcp_error(f"tool not registered: {name!r}")

        if outcome.status == "approved":
            event_id = ""
            if isinstance(outcome.envelope, Mapping):
                event_id = str(outcome.envelope.get("event_id") or "")
            return {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": f"gove-zone APPROVED {event_id}; not executed",
                    }
                ],
                "_meta": {
                    "gove_zone": {
                        "decision": "allow",
                        "executed": False,
                        "escalation_event_id": event_id,
                        **outcome.receipt_anchors(),
                    }
                },
            }
        if outcome.executed:
            return {
                "isError": False,
                "content": [{"type": "text", "text": _render(outcome.result)}],
                "_meta": {"gove_zone": {"decision": "allow", **outcome.receipt_anchors()}},
            }
        meta: dict[str, Any] = {"decision": outcome.status}
        if outcome.envelope is not None:
            meta["envelope"] = outcome.envelope
            approval = outcome.envelope.get("approval")
            if isinstance(approval, Mapping) and approval.get("event_id"):
                meta["escalation_event_id"] = approval["event_id"]
        if outcome.error_class:
            meta["error_class"] = outcome.error_class
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"gove-zone {outcome.status}: {name}"}],
            "_meta": {"gove_zone": meta},
        }

    # -- OpenAI function-calling surface --------------------------------------- #

    def openai_tools(self) -> list[dict[str, Any]]:
        """OpenAI ``tools=[...]`` specs derived from the sealed registry.

        Parameter JSON types come from the registered function's annotations,
        captured at registration time (best-effort; unannotated parameters map
        to ``"string"``). The spec list and the callable set are the same
        registry by construction.
        """
        return [dict(self._openai_specs[name]) for name in self.tool_names()]

    def handle_openai_tool_call(
        self, tool_call: Mapping[str, Any], *, actor: str
    ) -> dict[str, Any]:
        """Execute one OpenAI tool call (``{"id", "function": {"name",
        "arguments": "<json>"}}``) through the strong gate and return the
        ``role="tool"`` message to append to the conversation.

        Malformed shapes and non-object argument payloads fail closed with an
        error message — nothing executes.
        """
        call_id = str(tool_call.get("id", ""))
        function = tool_call.get("function")
        if not isinstance(function, Mapping):
            return _openai_message(call_id, {"status": "error", "error": "malformed tool_call"})
        name = function.get("name")
        if not isinstance(name, str) or not name:
            return _openai_message(call_id, {"status": "error", "error": "missing function name"})
        raw_arguments = function.get("arguments", "{}")
        if isinstance(raw_arguments, Mapping):
            arguments: Any = dict(raw_arguments)
        else:
            try:
                arguments = json.loads(raw_arguments or "{}")
            except (TypeError, ValueError):
                return _openai_message(
                    call_id, {"status": "error", "error": "arguments is not valid JSON"}
                )
        if not isinstance(arguments, dict):
            return _openai_message(
                call_id, {"status": "error", "error": "arguments must be a JSON object"}
            )

        try:
            outcome = self.invoke(actor, name, arguments)
        except UnknownToolError:
            return _openai_message(
                call_id, {"status": "error", "error": f"tool not registered: {name}"}
            )
        return _openai_message(call_id, outcome.to_dict())

    # -- LangGraph / LangChain surface ------------------------------------------ #

    def framework_run(
        self, actor: str, name: str, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> Any:
        """Shared governed execution path for framework tool wrappers.

        Positional arguments are rejected loud (``TypeError``) rather than
        silently dropped: the governance decision hashes keyword arguments, so
        an argument that bypassed the hash would be an unbound side-effect
        input. Refusals come back as the machine-readable envelope JSON so the
        calling agent can self-correct.
        """
        if args:
            raise TypeError(
                f"governed tool {name!r} accepts keyword arguments only; "
                f"got {len(args)} positional argument(s)"
            )
        outcome = self.invoke(actor, name, kwargs)
        if outcome.executed:
            return outcome.result
        return json.dumps(outcome.to_dict(), sort_keys=True, default=str)

    def langgraph_tools(self, tools: Sequence[Any], *, actor: str) -> list[Any]:
        """Wrap LangChain/LangGraph tools so every ``_run`` routes through the
        strong gate as *actor*. Requires ``langchain-core`` (lazy import).

        Unlike :mod:`gove_zone.adapters.langgraph` (which dispatches through
        the unsigned kernel loop), these wrappers execute through the signed
        receipt gate and the single-use ledger.

        Each wrapped tool registers its underlying ``_run`` on this gateway;
        wrapping the same tool name twice (e.g. rebuilding a graph against one
        shared gateway) raises the registry's duplicate-name ``ValueError``
        rather than silently replacing the sealed tool.
        """
        try:
            from langchain_core.tools import BaseTool  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError("langchain-core is required to use langgraph_tools") from exc

        gateway = self

        class GatewayGovernedTool(BaseTool):  # type: ignore[misc]
            def __init__(self, wrapped: Any) -> None:
                super().__init__(
                    name=wrapped.name,
                    description=wrapped.description,
                    args_schema=wrapped.args_schema,
                    return_direct=wrapped.return_direct,
                    verbose=wrapped.verbose,
                )
                # Register the tool's underlying callable (StructuredTool.func)
                # when it exposes one; wrapped._run needs framework-injected
                # kwargs (config/run_manager) and raises TypeError on a bare
                # keyword call. Fallback: the public invoke() entry point of
                # the ORIGINAL tool (never this governed wrapper, so no
                # recursion into the gate).
                raw = getattr(wrapped, "func", None)
                if not callable(raw):

                    def raw(**kwargs: Any) -> Any:
                        return wrapped.invoke(kwargs)

                gateway.register_tool(wrapped.name, raw)

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                return gateway.framework_run(actor, self.name, args, kwargs)

            async def _arun(self, *args: Any, **kwargs: Any) -> Any:
                return gateway.framework_run(actor, self.name, args, kwargs)

        return [GatewayGovernedTool(tool) for tool in tools]

    # -- Claude Code hook surface ------------------------------------------------ #

    def handle_claude_hook(
        self,
        payload: Mapping[str, Any],
        *,
        actor: str,
        action_kind: str = "PreToolUse",
        call_factory: Callable[..., Sequence[ToolCall]] | None = None,
    ) -> dict[str, Any]:
        """Decide one Claude Code hook event (Policy → Receipt only).

        The host runtime owns any later side effect and must honor the returned
        decision. This method does not call ``execute_with_receipt`` and must not
        be described as receipt-gated side-effect execution.

        Batch-aware, deny-wins: multi-call payloads (OpenAI Responses /
        ``tool_calls`` batches, per :func:`gove_zone.integration.
        tool_calls_from_hook_payload`) are expanded and **every** proposed call
        is evaluated and audited individually, so a denied action cannot be
        smuggled past a per-tool rule by wrapping it in a batch. The single
        returned ``permissionDecision`` is the worst individual verdict:
        any DENY → ``"deny"``; else any ESCALATE/TRANSFORM → ``"ask"`` (a hook
        cannot rewrite the runtime's arguments, so a transform requires a
        human); else ``"allow"``, minting one signed receipt per call whose
        anchors ride along under ``"gove_zone"]["receipts"]``.

        Fail-closed: an unrecordable decision (audit failure) or any
        governance error returns ``"deny"``.

        ``call_factory`` (optional) replaces the default payload → ``ToolCall``
        normalization with a caller-supplied one, called as
        ``factory(payload, action_kind=..., actor=...)``. It exists so a surface
        can classify the proposed call *structurally* before policy evaluation —
        :func:`gove_zone.execution.execution_tool_calls_from_hook_payload` maps a
        shell invocation onto its ``env.*`` execution surface this way. The
        factory only chooses how the proposed action is *named and described*;
        every decision, audit append, and receipt still runs through the same
        kernel below. It cannot choose or replace the gateway actor: a mismatch
        denies the entire batch before evaluation, audit, or receipt minting.
        ``None`` (the default) keeps the existing behavior exactly.
        """
        if not actor or not actor.strip():
            raise ValueError("actor is required for hook governance (fail-closed)")
        factory = call_factory if call_factory is not None else tool_calls_from_hook_payload
        try:
            calls = tuple(factory(dict(payload), action_kind=action_kind, actor=actor))
        except Exception as exc:  # noqa: BLE001 - a crashing normalizer must fail closed
            # A factory that raises on a malformed or unsupported payload is a
            # governance failure, not a caller contract error: direct
            # integrations rely on this method's documented fail-closed
            # response shape, so the crash must become a deny, not an escaped
            # exception that drops the response contract.
            return _hook_response(
                action_kind, "deny", f"call normalization failed: {type(exc).__name__}"
            )
        if not all(isinstance(call, ToolCall) for call in calls):
            # Result validation is part of the same boundary: a factory
            # returning a non-ToolCall would otherwise crash the actor-binding
            # check below and escape the response contract the same way.
            return _hook_response(action_kind, "deny", "call factory returned a non-ToolCall")
        if not calls:
            return _hook_response(action_kind, "deny", "no governable call in hook payload")
        if any(call.actor != actor for call in calls):
            return _hook_response(action_kind, "deny", "call factory actor mismatch")

        if self.allowed_actors is not None and actor not in self.allowed_actors:
            reason = f"actor {actor!r} is not in the gateway actor allowlist"
            # `invoke` records this condition through `_append_synthesized_deny`;
            # the hook surface must too, or repeated unauthorized-principal
            # attempts would be invisible to chain verification and incident
            # review. One record per proposed call keeps the "every call is
            # audited individually" contract; an unrecordable deny still
            # denies (the refusal never depends on the append succeeding).
            for call in calls:
                try:
                    self._append_synthesized_deny(call, rule=_ACTOR_ALLOWLIST_RULE, reason=reason)
                except AuditError:
                    break
            return _hook_response(action_kind, "deny", reason)

        decided: list[tuple[Any, str, str]] = []  # (record, audit_hash, previous_audit_hash)
        for call in calls:
            # Source previous_audit_hash from the append result, NOT a separate
            # pre-read: ``append`` computes ``previous_hash`` under the store's
            # exclusive lock against the real in-chain predecessor, so the
            # receipt's chain-linkage claim stays accurate even when another
            # writer advances the head between decisions (a lock-free
            # ``last_hash()`` pre-read could be superseded before the locked
            # write and record a stale anchor).
            try:
                audited = self._kernel_for(actor).evaluate_and_append(call)
            except GoveZoneError as exc:
                return _hook_response(
                    action_kind, "deny", f"governance decision unavailable: {type(exc).__name__}"
                )
            decided.append(
                (
                    audited.record,
                    audited.audit_hash,
                    str(audited.append_result.get("previous_hash", "")),
                )
            )

        denied = [record for record, _, _ in decided if record.decision is Decision.DENY]
        if denied:
            return _hook_response(action_kind, "deny", denied[0].reason or "denied by policy")
        needs_human = [
            record
            for record, _, _ in decided
            if record.decision in (Decision.ESCALATE, Decision.TRANSFORM)
        ]
        if needs_human:
            record = needs_human[0]
            return _hook_response(
                action_kind,
                "ask",
                record.reason or f"{record.decision.value} requires human review",
            )

        for record, audit_hash, _previous_audit_hash in decided:
            try:
                self._capture_before_receipt(record, audit_hash)
            except CaptureError as exc:
                return _hook_response(
                    action_kind,
                    "deny",
                    f"runtime capture unavailable: {type(exc).__name__}",
                )

        anchors: list[dict[str, Any]] = []
        for record, audit_hash, previous_audit_hash in decided:
            receipt = self._mint_receipt(record, audit_hash, previous_audit_hash)
            anchors.append(
                {
                    "tool": record.tool,
                    "receipt_hash": receipt.receipt_hash,
                    "audit_hash": audit_hash,
                    "policy_hash": self.policy.version,
                    "signature_algorithm": receipt.signature_algorithm,
                    "receipt_schema_version": receipt.receipt_schema_version,
                }
            )
        response = _hook_response(action_kind, "allow", "allowed by policy")
        response["gove_zone"] = {"receipts": anchors}
        return response

    # -- REST surface -------------------------------------------------------------- #

    def handle_rest_call(self, request: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
        """Handle one framework-neutral REST tool-call request.

        Request shape: ``{"tool": str, "args": {...}, "goal"?}`` — the body a
        ``POST /tools/call`` endpoint would deserialize. Returns
        ``{"status": <http status>, "body": {...}}`` for any web framework to
        project.

        *actor* is keyword-only and comes from the **authenticated request
        principal** resolved by the web layer (session, mTLS, OIDC subject) —
        exactly like every other surface. An ``"actor"`` key in the body is
        ignored: a wire payload must never be able to choose its own identity,
        or the actor allowlist and every actor-scoped policy rule would be
        spoofable with a single POST.
        """
        if not actor or not actor.strip():
            raise ValueError("actor is required for governed invocation (fail-closed)")
        if not isinstance(request, Mapping):
            return {"status": 400, "body": {"error": "request must be a JSON object"}}
        tool = request.get("tool")
        args = request.get("args") or {}
        if not isinstance(tool, str) or not tool:
            return {"status": 400, "body": {"error": "missing tool"}}
        if not isinstance(args, Mapping):
            return {"status": 400, "body": {"error": "args must be an object"}}
        goal = request.get("goal", "")
        if not isinstance(goal, str):
            return {"status": 400, "body": {"error": "goal must be a string"}}

        try:
            outcome = self.invoke(actor, tool, args, goal=goal)
        except UnknownToolError:
            return {"status": 404, "body": {"error": f"tool not registered: {tool}"}}

        status_map = {"executed": 200, "denied": 403, "escalated": 202, "error": 500}
        return {
            "status": status_map.get(outcome.status, 500),
            "body": outcome.to_dict(),
        }


# -- outbound REST tool factory ---------------------------------------------------- #


def http_json_tool(
    url: str,
    *,
    method: str = "POST",
    timeout: float = 10.0,
    headers: Mapping[str, str] | None = None,
) -> Callable[..., dict[str, Any]]:
    """Build a governed-registrable tool that calls one pinned REST endpoint.

    The URL (scheme + host + path) is pinned at construction — call arguments
    become the JSON body, never the destination, so a governed agent cannot
    redirect the side effect. HTTP redirects are refused (a 3xx raises) so the
    pinned host stays the *effective* destination even against a compromised
    or misconfigured upstream. Register the returned callable via
    :meth:`UniversalGateway.register_tool`; like any tool, it executes only
    through the receipt gate. Uses stdlib ``urllib`` (zero dependencies).
    """
    from urllib.parse import urlparse
    from urllib.request import HTTPRedirectHandler, Request, build_opener

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"http_json_tool requires an absolute http(s) URL, got {url!r}")
    pinned_headers = {"Content-Type": "application/json", **(headers or {})}

    class _RefuseRedirects(HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            # Returning None makes urllib raise HTTPError on any 3xx instead
            # of silently following it off the pinned host.
            return None

    opener = build_opener(_RefuseRedirects())

    def call_endpoint(**kwargs: Any) -> dict[str, Any]:
        body = json.dumps(kwargs, sort_keys=True).encode("utf-8")
        request = Request(url, data=body, method=method, headers=pinned_headers)
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - scheme pinned above
            text = response.read().decode("utf-8", errors="replace")
            try:
                payload: Any = json.loads(text)
            except ValueError:
                payload = text
            return {"status": int(response.status), "body": payload}

    call_endpoint.__name__ = f"http_json_tool[{parsed.netloc}{parsed.path}]"
    call_endpoint.__doc__ = f"{method} {url} with keyword arguments as the JSON body."
    return call_endpoint


# -- small shared helpers ------------------------------------------------------------ #


def _render(result: Any) -> str:
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(result)


def _mcp_error(message: str) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [{"type": "text", "text": f"gove-zone: {message}"}],
        "_meta": {"gove_zone": {"decision": "not_evaluated"}},
    }


def _openai_message(call_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "role": "tool",
        "tool_call_id": call_id,
        "content": json.dumps(payload, sort_keys=True, default=str),
    }


def _hook_response(action_kind: str, decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": action_kind,
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def _openai_function_spec(name: str, fn: Callable[..., Any]) -> dict[str, Any]:
    """OpenAI function spec for *fn*, computed once at registration time."""
    properties: dict[str, Any] = {}
    required: list[str] = []
    try:
        parameters: list[inspect.Parameter] = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        parameters = []
    for param in parameters:
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        properties[param.name] = {"type": _json_type(param.annotation)}
        if param.default is param.empty:
            required.append(param.name)
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": inspect.getdoc(fn) or "",
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


_JSON_TYPES: dict[Any, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    dict: "object",
    list: "array",
}

_JSON_TYPE_NAMES: dict[str, str] = {key.__name__: value for key, value in _JSON_TYPES.items()}


def _json_type(annotation: Any) -> str:
    if isinstance(annotation, str):
        # PEP 563 (`from __future__ import annotations`) leaves annotations as
        # source strings; match on the bare name.
        return _JSON_TYPE_NAMES.get(annotation.strip(), "string")
    return _JSON_TYPES.get(annotation, "string")
