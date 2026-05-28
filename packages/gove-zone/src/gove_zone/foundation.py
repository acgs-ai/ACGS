"""Receipt-first governed execution foundation.

This module is intentionally stdlib-only. It layers a canonical Decision
Receipt, tenant-bound policy lookup, receipt verification, and an independent
executor guard on top of the existing low-level kernel primitives.
"""

from __future__ import annotations

import copy
import dataclasses
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from gove_zone.audit import GENESIS_HASH, ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import AuditError, ReceiptVerificationError
from gove_zone.policy import Policy, new_event_id
from gove_zone.tool import ToolCall, ToolRegistry

SIGNATURE_PLACEHOLDER = {
    "type": "unsigned-local-dev",
    "status": "verification-placeholder",
    "algorithm": "sha256-canonical-json",
}


class GovernanceMetricsSink(Protocol):
    def record_decision(self, receipt: DecisionReceipt) -> None: ...

    def record_receipt_verification_failed(self, reason: str) -> None: ...

    def record_audit_write_failed(
        self, request_id: str, tenant_id: str, policy_bundle_id: str
    ) -> None: ...


@dataclass(frozen=True)
class GovernanceRequest:
    """Pre-execution request submitted to the governance plane."""

    request_id: str
    tenant_id: str
    actor: Mapping[str, Any] | str
    subject: Mapping[str, Any] | str
    proposed_action: Mapping[str, Any]
    declared_goal: str
    execution_boundary: Mapping[str, Any]
    policy_bundle_id: str

    def __post_init__(self) -> None:
        for field_name in ("request_id", "tenant_id", "declared_goal", "policy_bundle_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"GovernanceRequest.{field_name} is required")
        if not isinstance(self.proposed_action, Mapping):
            raise ValueError("GovernanceRequest.proposed_action must be a mapping")
        if not isinstance(self.execution_boundary, Mapping):
            raise ValueError("GovernanceRequest.execution_boundary must be a mapping")

    @property
    def tool_name(self) -> str:
        tool = self.proposed_action.get("tool")
        if not isinstance(tool, str) or not tool:
            raise ValueError("proposed_action.tool is required")
        return tool

    @property
    def action_args(self) -> dict[str, Any]:
        args = self.proposed_action.get("args", {})
        if not isinstance(args, Mapping):
            raise ValueError("proposed_action.args must be a mapping when present")
        return dict(args)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "actor": _plain(self.actor),
            "subject": _plain(self.subject),
            "proposed_action": dict(self.proposed_action),
            "declared_goal": self.declared_goal,
            "execution_boundary": dict(self.execution_boundary),
            "policy_bundle_id": self.policy_bundle_id,
        }


@dataclass(frozen=True)
class PolicyBundleBinding:
    """Tenant-scoped binding from a policy bundle id to a concrete policy."""

    tenant_id: str
    policy_bundle_id: str
    policy_version: str
    constitutional_hash: str
    policy: Policy

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "policy_bundle_id",
            "policy_version",
            "constitutional_hash",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"PolicyBundleBinding.{field_name} is required")


class StaticPolicyBundleRegistry:
    """Deterministic tenant-aware policy bundle registry for the hot path."""

    def __init__(self, bindings: Sequence[PolicyBundleBinding]) -> None:
        self._bindings: dict[tuple[str, str], PolicyBundleBinding] = {}
        self._bundle_ids: set[str] = set()
        for binding in bindings:
            key = (binding.tenant_id, binding.policy_bundle_id)
            if key in self._bindings:
                raise ValueError(f"duplicate policy bundle binding: {key!r}")
            self._bindings[key] = binding
            self._bundle_ids.add(binding.policy_bundle_id)

    def active_binding(self, tenant_id: str, policy_bundle_id: str) -> PolicyBundleBinding | None:
        return self._bindings.get((tenant_id, policy_bundle_id))

    def knows_bundle_id(self, policy_bundle_id: str) -> bool:
        return policy_bundle_id in self._bundle_ids


@dataclass(frozen=True)
class DecisionReceipt:
    """Canonical receipt proving one pre-execution governance decision."""

    receipt_id: str
    request_id: str
    tenant_id: str
    actor: Any
    subject: Any
    proposed_action: dict[str, Any]
    declared_goal: str
    execution_boundary: dict[str, Any]
    policy_bundle_id: str
    policy_version: str
    constitutional_hash: str
    decision: Decision
    matched_rules: tuple[str, ...]
    constraints: tuple[str, ...]
    transformations: dict[str, Any] | None
    approval_chain_summary: tuple[dict[str, Any], ...]
    timestamp: str
    previous_audit_hash: str
    audit_event_hash: str
    receipt_hash: str
    signature: dict[str, Any] = field(default_factory=lambda: dict(SIGNATURE_PLACEHOLDER))

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "actor": copy.deepcopy(self.actor),
            "subject": copy.deepcopy(self.subject),
            "proposed_action": copy.deepcopy(self.proposed_action),
            "declared_goal": self.declared_goal,
            "execution_boundary": copy.deepcopy(self.execution_boundary),
            "policy_bundle_id": self.policy_bundle_id,
            "policy_version": self.policy_version,
            "constitutional_hash": self.constitutional_hash,
            "decision": self.decision.name,
            "matched_rules": list(self.matched_rules),
            "constraints": list(self.constraints),
            "transformations": copy.deepcopy(self.transformations),
            "approval_chain_summary": copy.deepcopy(list(self.approval_chain_summary)),
            "timestamp": self.timestamp,
            "previous_audit_hash": self.previous_audit_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.unsigned_payload(),
            "audit_event_hash": self.audit_event_hash,
            "receipt_hash": self.receipt_hash,
            "signature": dict(self.signature),
        }


class InMemoryGovernanceMetrics:
    """Low-dependency metric sink for tests, demos, and future OTel bridging."""

    def __init__(self) -> None:
        self._decisions_total: dict[str, int] = {}
        self._denied_total = 0
        self._receipt_verification_failed_total = 0
        self._audit_write_failed_total = 0
        self._events: list[dict[str, str]] = []

    def record_decision(self, receipt: DecisionReceipt) -> None:
        decision = receipt.decision.name
        self._decisions_total[decision] = self._decisions_total.get(decision, 0) + 1
        if receipt.decision is Decision.DENY:
            self._denied_total += 1
        self._events.append(
            {
                "metric": "decisions_total",
                "decision": decision,
                "tenant_id": receipt.tenant_id,
                "policy_bundle_id": receipt.policy_bundle_id,
                "request_id": receipt.request_id,
            }
        )

    def record_receipt_verification_failed(self, reason: str) -> None:
        self._receipt_verification_failed_total += 1
        self._events.append({"metric": "receipt_verification_failed_total", "reason": reason})

    def record_audit_write_failed(
        self, request_id: str, tenant_id: str, policy_bundle_id: str
    ) -> None:
        self._audit_write_failed_total += 1
        self._events.append(
            {
                "metric": "audit_write_failed_total",
                "request_id": request_id,
                "tenant_id": tenant_id,
                "policy_bundle_id": policy_bundle_id,
            }
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "decisions_total": dict(self._decisions_total),
            "denied_total": self._denied_total,
            "receipt_verification_failed_total": self._receipt_verification_failed_total,
            "audit_write_failed_total": self._audit_write_failed_total,
            "events": list(self._events),
        }


class GovernanceEngine:
    """Pre-execution governance check that emits a canonical receipt."""

    def __init__(
        self,
        *,
        policy_registry: StaticPolicyBundleRegistry,
        audit: ChainHashAuditStore,
        metrics: GovernanceMetricsSink | None = None,
    ) -> None:
        self.policy_registry = policy_registry
        self.audit = audit
        self.metrics = metrics

    def precheck(self, request: GovernanceRequest) -> DecisionReceipt:
        binding = self.policy_registry.active_binding(request.tenant_id, request.policy_bundle_id)
        call = ToolCall(
            name=request.tool_name,
            args=request.action_args,
            goal=request.declared_goal,
        )
        record = self._decide(request, call, binding)

        try:
            event, receipt = self.audit.append_prepared(
                lambda previous_hash: self._prepare_audit_record(
                    request=request,
                    binding=binding,
                    record=record,
                    previous_hash=previous_hash,
                )
            )
        except Exception as exc:
            if self.metrics is not None:
                self.metrics.record_audit_write_failed(
                    request.request_id,
                    request.tenant_id,
                    request.policy_bundle_id,
                )
            msg = f"audit append failed for request {request.request_id}: {exc}"
            raise AuditError(msg) from exc

        receipt = dataclasses.replace(receipt, audit_event_hash=str(event.get("event_hash", "")))
        if event.get("receipt_hash") != receipt.receipt_hash:
            raise AuditError("audit append did not persist the receipt hash")
        if self.metrics is not None:
            self.metrics.record_decision(receipt)
        return receipt

    def _decide(
        self,
        request: GovernanceRequest,
        call: ToolCall,
        binding: PolicyBundleBinding | None,
    ) -> DecisionRecord:
        if binding is None:
            known_elsewhere = self.policy_registry.knows_bundle_id(request.policy_bundle_id)
            matched_rule = (
                "TENANT_POLICY_BUNDLE_MISMATCH" if known_elsewhere else "MISSING_POLICY_BUNDLE"
            )
            return DecisionRecord(
                decision=Decision.DENY,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version="fail-closed/no-active-policy",
                event_id=new_event_id(),
                matched_rules=(matched_rule,),
                reason="no active policy bundle is bound to this tenant and request",
                goal=request.declared_goal,
            )
        try:
            record = binding.policy.evaluate(call)
        except Exception as exc:
            return DecisionRecord(
                decision=Decision.DENY,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version=binding.policy_version,
                event_id=new_event_id(),
                matched_rules=(f"POLICY_ERROR:{type(exc).__name__}",),
                reason=f"policy evaluation raised: {exc}",
                goal=request.declared_goal,
            )
        return dataclasses.replace(
            record,
            policy_version=binding.policy_version,
            goal=request.declared_goal,
        )

    def _prepare_audit_record(
        self,
        *,
        request: GovernanceRequest,
        binding: PolicyBundleBinding | None,
        record: DecisionRecord,
        previous_hash: str,
    ) -> tuple[DecisionRecord, DecisionReceipt]:
        policy_bundle_id = (
            binding.policy_bundle_id if binding is not None else request.policy_bundle_id
        )
        policy_version = binding.policy_version if binding is not None else record.policy_version
        constitutional_hash = (
            binding.constitutional_hash
            if binding is not None
            else sha256_json({"missing_policy_bundle": request.policy_bundle_id})
        )
        receipt = make_decision_receipt(
            request=request,
            record=record,
            policy_bundle_id=policy_bundle_id,
            policy_version=policy_version,
            constitutional_hash=constitutional_hash,
            previous_audit_hash=previous_hash,
        )
        enriched = dataclasses.replace(
            record,
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            actor=_plain(request.actor),
            subject=_plain(request.subject),
            proposed_action=dict(request.proposed_action),
            execution_boundary=dict(request.execution_boundary),
            policy_bundle_id=policy_bundle_id,
            policy_version=policy_version,
            constitutional_hash=constitutional_hash,
            receipt_hash=receipt.receipt_hash,
        )
        return enriched, receipt


class GovernedExecutor:
    """Executor guard that refuses side effects without a valid receipt."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or ToolRegistry()

    def tool(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.registry.register(name, fn)
            return fn

        return decorator

    def execute(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        receipt: DecisionReceipt | Mapping[str, Any] | None,
        tenant_id: str | None = None,
        execution_boundary: Mapping[str, Any] | None = None,
        policy_bundle_id: str | None = None,
        constitutional_hash: str | None = None,
        audit: ChainHashAuditStore | None = None,
    ) -> Any:
        if receipt is None:
            raise ReceiptVerificationError("missing receipt")
        verified = parse_and_verify_decision_receipt(receipt, audit=audit)
        if tenant_id is not None and verified.tenant_id != tenant_id:
            raise ReceiptVerificationError(
                "tenant mismatch: receipt does not authorize this tenant"
            )
        if execution_boundary is not None and (
            verified.execution_boundary != dict(execution_boundary)
        ):
            raise ReceiptVerificationError("execution boundary mismatch")
        if policy_bundle_id is not None and verified.policy_bundle_id != policy_bundle_id:
            raise ReceiptVerificationError("policy bundle mismatch")
        if constitutional_hash is not None and verified.constitutional_hash != constitutional_hash:
            raise ReceiptVerificationError("policy hash mismatch")
        if verified.decision not in {Decision.ALLOW, Decision.TRANSFORM}:
            raise ReceiptVerificationError(
                f"receipt decision {verified.decision.name} is not executable"
            )

        expected = executable_action_from_receipt(verified)
        actual = {"tool": tool_name, "args": dict(args or {})}
        if actual != expected:
            raise ReceiptVerificationError(
                "action mismatch: receipt does not authorize this tool and args"
            )
        if not self.registry.has(tool_name):
            raise ReceiptVerificationError(f"tool not registered: {tool_name!r}")
        return self.registry.get(tool_name)(**dict(args or {}))


def make_decision_receipt(
    *,
    request: GovernanceRequest,
    record: DecisionRecord,
    policy_bundle_id: str,
    policy_version: str,
    constitutional_hash: str,
    previous_audit_hash: str,
    now: str | None = None,
    receipt_id: str | None = None,
) -> DecisionReceipt:
    transformations = None
    if record.decision is Decision.TRANSFORM:
        transformations = {
            "proposed_action": {
                "tool": request.tool_name,
                "args": dict(record.transformed_args or {}),
            }
        }
    draft = DecisionReceipt(
        receipt_id=receipt_id or _new_receipt_id(),
        request_id=request.request_id,
        tenant_id=request.tenant_id,
        actor=_plain(request.actor),
        subject=_plain(request.subject),
        proposed_action={"tool": request.tool_name, "args": request.action_args},
        declared_goal=request.declared_goal,
        execution_boundary=dict(request.execution_boundary),
        policy_bundle_id=policy_bundle_id,
        policy_version=policy_version,
        constitutional_hash=constitutional_hash,
        decision=record.decision,
        matched_rules=tuple(record.matched_rules),
        constraints=tuple(record.matched_rules),
        transformations=transformations,
        approval_chain_summary=(),
        timestamp=now or datetime.now(UTC).isoformat(),
        previous_audit_hash=previous_audit_hash,
        audit_event_hash=GENESIS_HASH,
        receipt_hash="",
        signature=dict(SIGNATURE_PLACEHOLDER),
    )
    return dataclasses.replace(draft, receipt_hash=sha256_json(draft.unsigned_payload()))


def verify_decision_receipt(
    receipt: DecisionReceipt | Mapping[str, Any],
    *,
    audit: ChainHashAuditStore | None = None,
    metrics: GovernanceMetricsSink | None = None,
) -> bool:
    parse_and_verify_decision_receipt(receipt, audit=audit, metrics=metrics)
    return True


def parse_and_verify_decision_receipt(
    receipt: DecisionReceipt | Mapping[str, Any],
    *,
    audit: ChainHashAuditStore | None = None,
    metrics: GovernanceMetricsSink | None = None,
) -> DecisionReceipt:
    try:
        parsed = receipt if isinstance(receipt, DecisionReceipt) else _receipt_from_mapping(receipt)
        if parsed.signature != SIGNATURE_PLACEHOLDER:
            raise ReceiptVerificationError("receipt signature placeholder is invalid")
        recomputed = sha256_json(parsed.unsigned_payload())
        if parsed.receipt_hash != recomputed:
            raise ReceiptVerificationError("receipt_hash mismatch")
        if parsed.decision is Decision.TRANSFORM:
            executable_action_from_receipt(parsed)
        if audit is not None:
            _verify_audit_link(parsed, audit)
    except ReceiptVerificationError as exc:
        if metrics is not None:
            metrics.record_receipt_verification_failed(str(exc))
        raise
    return parsed


def executable_action_from_receipt(receipt: DecisionReceipt) -> dict[str, Any]:
    if receipt.decision is Decision.TRANSFORM:
        if not isinstance(receipt.transformations, Mapping):
            raise ReceiptVerificationError("transform receipt missing transformations")
        action = receipt.transformations.get("proposed_action")
        if not isinstance(action, Mapping):
            raise ReceiptVerificationError("transform receipt missing transformed proposed_action")
        tool = action.get("tool")
        args = action.get("args")
        if not isinstance(tool, str) or not isinstance(args, Mapping):
            raise ReceiptVerificationError("transform receipt has malformed transformed action")
        return {"tool": tool, "args": dict(args)}
    return {
        "tool": str(receipt.proposed_action["tool"]),
        "args": dict(receipt.proposed_action.get("args", {})),
    }


def _receipt_from_mapping(raw: Mapping[str, Any]) -> DecisionReceipt:
    required = (
        "receipt_id",
        "request_id",
        "tenant_id",
        "actor",
        "subject",
        "proposed_action",
        "declared_goal",
        "execution_boundary",
        "policy_bundle_id",
        "policy_version",
        "constitutional_hash",
        "decision",
        "matched_rules",
        "constraints",
        "transformations",
        "approval_chain_summary",
        "timestamp",
        "previous_audit_hash",
        "audit_event_hash",
        "receipt_hash",
        "signature",
    )
    missing = [key for key in required if key not in raw]
    if missing:
        raise ReceiptVerificationError(f"receipt missing required fields: {missing}")
    try:
        decision = Decision[str(raw["decision"])]
    except KeyError as exc:
        raise ReceiptVerificationError(f"unknown receipt decision: {raw['decision']!r}") from exc
    proposed_action = raw["proposed_action"]
    execution_boundary = raw["execution_boundary"]
    signature = raw["signature"]
    if not isinstance(proposed_action, Mapping):
        raise ReceiptVerificationError("receipt proposed_action is malformed")
    if not isinstance(execution_boundary, Mapping):
        raise ReceiptVerificationError("receipt execution_boundary is malformed")
    if not isinstance(signature, Mapping):
        raise ReceiptVerificationError("receipt signature is malformed")
    return DecisionReceipt(
        receipt_id=_required_str(raw, "receipt_id"),
        request_id=_required_str(raw, "request_id"),
        tenant_id=_required_str(raw, "tenant_id"),
        actor=raw["actor"],
        subject=raw["subject"],
        proposed_action=dict(proposed_action),
        declared_goal=_required_str(raw, "declared_goal"),
        execution_boundary=dict(execution_boundary),
        policy_bundle_id=_required_str(raw, "policy_bundle_id"),
        policy_version=_required_str(raw, "policy_version"),
        constitutional_hash=_required_str(raw, "constitutional_hash"),
        decision=decision,
        matched_rules=tuple(str(rule) for rule in _required_sequence(raw, "matched_rules")),
        constraints=tuple(str(rule) for rule in _required_sequence(raw, "constraints")),
        transformations=(
            None
            if raw["transformations"] is None
            else dict(_required_mapping(raw, "transformations"))
        ),
        approval_chain_summary=tuple(
            dict(item) for item in _required_sequence(raw, "approval_chain_summary")
        ),
        timestamp=_required_str(raw, "timestamp"),
        previous_audit_hash=_required_str(raw, "previous_audit_hash"),
        audit_event_hash=_required_str(raw, "audit_event_hash"),
        receipt_hash=_required_str(raw, "receipt_hash"),
        signature=dict(signature),
    )


def _verify_audit_link(receipt: DecisionReceipt, audit: ChainHashAuditStore) -> None:
    chain = audit.verify_chain()
    if not chain["valid"]:
        raise ReceiptVerificationError("audit chain is invalid")
    for event in audit.iter_events():
        if event.get("event_hash") != receipt.audit_event_hash:
            continue
        if event.get("receipt_hash") != receipt.receipt_hash:
            raise ReceiptVerificationError("audit receipt_hash mismatch")
        if event.get("previous_hash") != receipt.previous_audit_hash:
            raise ReceiptVerificationError("audit previous_audit_hash mismatch")
        if event.get("tenant_id") != receipt.tenant_id:
            raise ReceiptVerificationError("audit tenant mismatch")
        if event.get("policy_bundle_id") != receipt.policy_bundle_id:
            raise ReceiptVerificationError("audit policy bundle mismatch")
        return
    raise ReceiptVerificationError("audit_event_hash not found in audit chain")


def _required_str(raw: Mapping[str, Any], key: str) -> str:
    value = raw[key]
    if not isinstance(value, str) or not value:
        raise ReceiptVerificationError(f"receipt field {key!r} must be a non-empty string")
    return value


def _required_sequence(raw: Mapping[str, Any], key: str) -> Sequence[Any]:
    value = raw[key]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ReceiptVerificationError(f"receipt field {key!r} must be a sequence")
    return value


def _required_mapping(raw: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = raw[key]
    if not isinstance(value, Mapping):
        raise ReceiptVerificationError(f"receipt field {key!r} must be a mapping")
    return value


def _plain(value: Mapping[str, Any] | str | Any) -> Any:
    if isinstance(value, Mapping):
        return dict(value)
    return value


def _new_receipt_id() -> str:
    return f"rcpt_{uuid.uuid4().hex[:20]}"
