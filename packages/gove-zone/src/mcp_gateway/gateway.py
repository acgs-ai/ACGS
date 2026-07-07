"""Governed MCP tool-call interception over the gove-zone kernel.

The gateway is deliberately a *reuse-only assembly*: policy evaluation, audit
append, receipt minting, and the signed execution gate are all the existing
sealed primitives. The only code here is request parsing, wiring, and the MCP
result envelope — nothing in this module can grant authority.

Two-step API (mirrors the receipt lifecycle)::

    decision = gateway.authorize(name, arguments, actor=...)   # policy -> receipt
    result   = gateway.execute(decision.receipt, name, arguments, actor=...)

One-step convenience for MCP ``tools/call`` payloads::

    result = gateway.handle_tools_call(request, actor=...)

Fail-closed posture, inherited from the primitives:

- No decision is recorded -> no receipt exists -> no execution
  (:func:`~gove_zone.executor.execute_with_receipt` refuses ``receipt=None``).
- DENY / ESCALATE records can never mint an executable receipt path here; the
  gateway returns them as MCP ``isError`` results carrying the structured
  envelope, and the tool callable is never looked up.
- Receipt/argument/actor/tool mismatches and expired receipts surface as
  :class:`~gove_zone.errors.ReceiptValidationError` from the gate, reported as
  ``isError`` results without echoing tool internals.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.errors import (
    AuditError,
    GoveZoneError,
    ReceiptValidationError,
    UnknownToolError,
)
from gove_zone.executor import execute_with_receipt
from gove_zone.kernel import Kernel
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.tool import ToolCall

__all__ = ["GatewayDecision", "MCPGovernanceGateway"]

#: ``_meta.gove_zone.decision`` value for requests rejected before any policy
#: evaluation (malformed shape, unregistered tool). Distinct from the kernel
#: decisions so a consumer can tell "the gate said no" apart from "the request
#: never reached the gate".
_NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True)
class GatewayDecision:
    """Outcome of :meth:`MCPGovernanceGateway.authorize` for one tool call.

    ``receipt`` is populated **only** for an ALLOW decision. For DENY and
    ESCALATE it stays ``None`` — there is deliberately no field a caller could
    use to reach execution from a non-ALLOW decision.
    """

    decision: str
    record: DecisionRecord
    audit_hash: str
    receipt: DecisionReceipt | None = None
    rejection: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.receipt is not None


class MCPGovernanceGateway:
    """Intercept MCP ``tools/call`` traffic through the gove-zone kernel.

    Every argument is required except the hardening knobs — the caller must
    state its tenant, boundary, policy bundle, authority, MACI validator, and
    signing posture explicitly. There are no silent defaults for any value
    that binds into a receipt.

    ``receipt_ttl_seconds`` (optional) stamps ``expires_at`` on every minted
    receipt so authorisations age out instead of living forever.
    ``consumption_ledger`` (optional) enforces single use — a spent receipt
    cannot authorise a second execution.
    """

    def __init__(
        self,
        kernel: Kernel,
        *,
        tenant_id: str,
        execution_boundary: str,
        policy_bundle_id: str,
        authority: str,
        validator: Validator,
        profile: GovernanceProfile,
        consumption_ledger: ReceiptConsumptionLedger | None = None,
        receipt_ttl_seconds: float | None = None,
    ) -> None:
        if consumption_ledger is not None and profile.consumption_ledger is not None:
            # Two ledgers means two sources of truth for "already spent" — an
            # ambiguity the gate must not resolve silently. Fail loud at
            # construction instead of at the first execute().
            raise ValueError(
                "ambiguous consumption ledger: both the gateway and the "
                "governance profile carry one; configure it in exactly one place"
            )
        self._kernel = kernel
        self._tenant_id = tenant_id
        self._execution_boundary = execution_boundary
        self._policy_bundle_id = policy_bundle_id
        self._authority = authority
        self._validator = validator
        self._profile = profile
        self._ledger = consumption_ledger
        self._ttl = receipt_ttl_seconds

    # -- step 1: policy check -> decision receipt -------------------------- #

    def authorize(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        actor: str,
        goal: str = "",
    ) -> GatewayDecision:
        """Evaluate one proposed tool call and, on ALLOW, mint its receipt.

        Exactly one audit event is appended; **no tool is executed** here.
        Raises :class:`~gove_zone.errors.UnknownToolError` for a tool that is
        not in the kernel registry (structural admission — nothing was
        evaluated, nothing is audited) and lets the kernel's
        :class:`~gove_zone.errors.AuditError` propagate when the decision
        cannot be recorded (no record -> no receipt -> no execution).
        """
        if not self._kernel.registry.has(name):
            raise UnknownToolError(name)
        args = dict(arguments or {})
        path = args.get("path")
        call = ToolCall(
            name=name,
            args=args,
            goal=goal,
            actor=actor,
            # Lift path-shaped values (str or segment sequence) so
            # path-boundary policies see them; the argument itself still
            # reaches the tool unchanged.
            path=_normalize_path(path),
        )
        previous_audit_hash = self._kernel.audit.last_hash()
        record, audit_hash = self._kernel.evaluate_and_record(call)

        if record.decision is not Decision.ALLOW:
            return GatewayDecision(
                decision=record.decision.value,
                record=record,
                audit_hash=audit_hash,
                rejection=_rejection_envelope(record, audit_hash),
            )

        receipt = DecisionReceipt.from_record(
            record,
            audit_hash=audit_hash,
            previous_audit_hash=previous_audit_hash,
            tenant_id=self._tenant_id,
            execution_boundary=self._execution_boundary,
            policy_bundle_id=self._policy_bundle_id,
            policy_hash=self._kernel.policy.version,
            request_id=record.decision_request_hash or record.event_id,
            validator=self._validator,
            authority=self._authority,
            expires_at=self._expires_at(),
            signer=self._profile.signer,
        )
        return GatewayDecision(
            decision=record.decision.value,
            record=record,
            audit_hash=audit_hash,
            receipt=receipt,
        )

    # -- step 2: receipt -> tool execution --------------------------------- #

    def execute(
        self,
        receipt: DecisionReceipt | None,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        actor: str,
    ) -> Any:
        """Run the registered tool iff *receipt* authorises exactly this call.

        The gate re-verifies everything before the callable runs: receipt
        integrity and signature posture, tool-name binding
        (``expected_action``), the canonical argument hash, the invoking
        principal (``expected_actor``), tenant/boundary, expiry, and — when a
        ledger is configured — single use. Any mismatch raises
        :class:`~gove_zone.errors.ReceiptValidationError` and the tool never
        executes.
        """
        try:
            tool_fn = self._kernel.registry.get(name)
        except KeyError:
            raise UnknownToolError(name) from None
        # Single kwargs dict: the strict profile's as_gate_kwargs() already
        # carries consumption_ledger, so a second explicit keyword would raise
        # TypeError at every call. __init__ rejects the both-configured case;
        # here the gateway-level ledger only fills the gap the profile left.
        gate_kwargs = dict(self._profile.as_gate_kwargs())
        if self._ledger is not None:
            gate_kwargs["consumption_ledger"] = self._ledger
        return execute_with_receipt(
            tool_fn=tool_fn,
            args=dict(arguments or {}),
            receipt=receipt,
            expected_tenant_id=self._tenant_id,
            expected_execution_boundary=self._execution_boundary,
            expected_action=name,
            expected_actor=actor,
            **gate_kwargs,
        )

    # -- one-step MCP envelope ---------------------------------------------- #

    def handle_tools_call(
        self,
        request: Mapping[str, Any],
        *,
        actor: str,
    ) -> dict[str, Any]:
        """Route one MCP ``tools/call`` request through authorize + execute.

        Accepts a full JSON-RPC request (``{"method": "tools/call", "params":
        {"name": ..., "arguments": {...}}}``) or the bare params mapping, and
        returns the MCP ``tools/call`` *result* payload. All refusals are
        ``isError: true`` results (per the MCP spec — the model should see and
        reason about them), never silent successes and never uncaught
        exceptions at the trust boundary.
        """
        if not isinstance(request, Mapping):
            return _error("malformed tools/call request: request is not a mapping")
        method = request.get("method")
        if method is not None and method != "tools/call":
            return _error(f"unsupported method {method!r}; this gateway handles tools/call")
        params = request.get("params") if "params" in request else request
        if not isinstance(params, Mapping):
            return _error("malformed tools/call request: params is not a mapping")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return _error("malformed tools/call request: missing tool name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            return _error("malformed tools/call request: arguments is not a mapping")

        try:
            decision = self.authorize(name, arguments, actor=actor)
        except UnknownToolError:
            return _error(f"tool not registered: {name!r}")
        except AuditError:
            # The decision could not be recorded -> fail closed, leak-safe.
            return _error("audit unrecordable: decision not persisted, call refused")
        except GoveZoneError:
            return _error("governance error: call refused")

        if not decision.allowed:
            return _rejection_result(decision)

        try:
            result = self.execute(decision.receipt, name, arguments, actor=actor)
        except ReceiptValidationError as exc:
            reason = exc.reason_code
            return _error(
                "receipt gate refused execution"
                + (f": {reason.value}" if reason is not None else ""),
                meta={
                    "decision": decision.decision,
                    "audit_event_hash": decision.audit_hash,
                },
            )
        except Exception:
            # The ALLOW is already audited; report a leak-safe execution
            # failure (error class stays in the audit chain, not the envelope).
            return _error(
                "tool execution failed",
                meta={
                    "decision": decision.decision,
                    "audit_event_hash": decision.audit_hash,
                },
            )

        receipt = decision.receipt
        assert receipt is not None  # allowed => receipt minted
        return {
            "content": [{"type": "text", "text": _text(result)}],
            "isError": False,
            "_meta": {
                "gove_zone": {
                    "decision": decision.decision,
                    "receipt_id": receipt.receipt_id,
                    "receipt_hash": receipt.receipt_hash,
                    "argument_hash": receipt.argument_hash,
                    "actor": receipt.actor,
                    "expires_at": receipt.expires_at,
                    "audit_event_hash": decision.audit_hash,
                }
            },
        }

    # -- receipt verification ------------------------------------------------ #

    def verify_receipt(
        self,
        receipt: DecisionReceipt,
        *,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        actor: str,
        now_iso: str | None = None,
    ) -> None:
        """Verify *receipt* against this gateway's bindings without executing.

        Raises :class:`~gove_zone.errors.ReceiptValidationError` on any
        mismatch (tool name, argument hash, actor, tenant/boundary, integrity,
        signature posture, expiry). Offline check only — it burns nothing and
        runs nothing; execution still goes through :meth:`execute`.
        """
        gate = self._profile.as_gate_kwargs()
        receipt.verify(
            expected_tenant_id=self._tenant_id,
            expected_execution_boundary=self._execution_boundary,
            expected_action=name,
            expected_args=dict(arguments or {}),
            expected_actor=actor,
            verifier=gate.get("verifier"),
            require_signature=bool(gate.get("require_signature", False)),
            require_expiry=bool(gate.get("require_expiry", False)),
            now_iso=now_iso,
        )

    # -- internals ------------------------------------------------------------ #

    def _expires_at(self) -> str:
        if self._ttl is None:
            return ""
        return (datetime.now(UTC) + timedelta(seconds=self._ttl)).isoformat()


def _normalize_path(path: Any) -> tuple[str, ...]:
    from gove_zone.tool import normalize_path_context

    if isinstance(path, (str, list, tuple)):
        return normalize_path_context(path)
    return ()


def _rejection_envelope(record: DecisionRecord, audit_hash: str) -> dict[str, Any]:
    return {
        "decision": record.decision.value,
        "reason": record.reason,
        "matched_rules": list(record.matched_rules),
        "policy_version": record.policy_version,
        "event_id": record.event_id,
        "audit_event_hash": audit_hash,
    }


def _rejection_result(decision: GatewayDecision) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": f"call rejected by governance: {decision.decision}",
            }
        ],
        "isError": True,
        "_meta": {"gove_zone": decision.rejection},
    }


def _error(message: str, *, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    gove_meta: dict[str, Any] = {"decision": _NOT_EVALUATED}
    if meta:
        gove_meta.update(meta)
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
        "_meta": {"gove_zone": gove_meta},
    }


def _text(result: Any) -> str:
    import json

    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return repr(result)
