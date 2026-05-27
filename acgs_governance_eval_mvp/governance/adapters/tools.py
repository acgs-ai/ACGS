from __future__ import annotations

from collections.abc import Callable
from typing import Any

from governance.audit.jsonl_chain import ChainHashAuditStore
from governance.gates import AuthorityGate, GovernanceRecallGate, PolicyRecallGate
from governance.metrics.otel import GovernanceMetrics
from governance.models import (
    DECISION_SCHEMA_VERSION,
    ActionRequest,
    DecisionRecord,
    GateResult,
    GovernanceDeniedError,
    sha256_json,
)


class GovernedToolAdapter:
    """Single pre-execution adapter for tool/API/DB/write actions.

    Call validate() before any external side effect.
    Execute the tool only when decision.allow is True.
    """

    def __init__(
        self,
        *,
        roles_bundle: dict[str, Any],
        policy_bundle: dict[str, Any],
        audit_store: ChainHashAuditStore | None = None,
        metrics: GovernanceMetrics | None = None,
    ):
        self.roles_bundle = roles_bundle
        self.policy_bundle = policy_bundle
        # Stable per-instance bundle hashes. replay compares these against the
        # hashes stored in the audit event to detect policy drift.
        self.policy_bundle_hash = sha256_json(policy_bundle)
        self.role_bundle_hash = sha256_json(roles_bundle)
        self.audit_store = audit_store
        self.metrics = metrics or GovernanceMetrics.disabled()
        self.authority_gate = AuthorityGate(roles_bundle)
        self.policy_recall_gate = PolicyRecallGate(policy_bundle)
        self.governance_recall_gate = GovernanceRecallGate()

    def validate(self, request: ActionRequest | dict[str, Any]) -> DecisionRecord:
        action_request = request if isinstance(request, ActionRequest) else ActionRequest.from_dict(request)

        checks: list[GateResult] = []
        authority = self.authority_gate.validate(action_request)
        checks.append(authority)
        self.metrics.record_gate(authority)

        policy = self.policy_recall_gate.validate(action_request)
        checks.append(policy)
        self.metrics.record_gate(policy)

        governance = self.governance_recall_gate.validate(
            action_request,
            checks,
            role_version=str(self.roles_bundle.get("version", "unknown")),
            policy_version=str(self.policy_bundle.get("version", "unknown")),
        )
        checks.append(governance)
        self.metrics.record_gate(governance)

        allow = all(check.allowed for check in checks)
        decision_state = "allow" if allow else "deny"
        # For "allow", the validated executor binding equals request.tool_input.
        # Future "rewrite" gates will set effective_tool_input to a sanitized
        # version. None is used for "deny" or when the caller supplied no
        # tool_input (validate-only path; guard() will refuse to execute).
        effective_tool_input = action_request.tool_input if allow else None

        decision = DecisionRecord(
            event_id=action_request.event_id,
            tenant=action_request.tenant,
            allow=allow,
            reasons=[reason for check in checks for reason in check.reasons],
            reason_codes=[code for check in checks for code in check.reason_codes],
            rule_ids=sorted({rule_id for check in checks for rule_id in check.rule_ids}),
            checks=checks,
            request=action_request,
            policy_version=str(self.policy_bundle.get("version", "unknown")),
            role_version=str(self.roles_bundle.get("version", "unknown")),
            decision_state=decision_state,
            effective_tool_input=effective_tool_input,
            policy_bundle_hash=self.policy_bundle_hash,
            role_bundle_hash=self.role_bundle_hash,
            decision_schema_version=DECISION_SCHEMA_VERSION,
        )

        if self.audit_store is not None:
            stored = self.audit_store.append(decision)
            self.metrics.record_decision(stored)
            # Return an immutable record reflecting the persisted hashes.
            return DecisionRecord(
                **{
                    **decision.to_dict(),
                    "checks": checks,
                    "request": action_request,
                    "previous_hash": stored["previous_hash"],
                    "event_hash": stored["event_hash"],
                }
            )

        self.metrics.record_decision(decision.to_dict())
        return decision

    def guard(
        self,
        request: ActionRequest | dict[str, Any],
        fn: Callable[[dict[str, Any]], Any],
    ) -> Any:
        """Validate, then execute fn(decision.effective_tool_input) when allowed.

        fn must accept exactly one argument: the validated effective_tool_input
        dict. This binds execution to the validated input; arbitrary caller
        args cannot bypass the gate (TOCTOU defense).

        Refuses execution when audit_store is missing (allowed side effects
        must be persisted before running) or when request.tool_input is unset
        (executor cannot be bound to validated input). Use validate() directly
        for input-less or replay paths.

        On denial raises GovernanceDeniedError, which subclasses
        PermissionError (existing ``except PermissionError`` catches still
        work). The exception carries the full DecisionRecord on
        ``.decision`` — inspect ``.decision.reason_codes`` and
        ``.decision.checks[i].remediation`` for actionable hints.
        """
        if self.audit_store is None:
            raise RuntimeError(
                "GovernedToolAdapter.guard() requires an audit_store; "
                "allowed side effects must be persisted before execution"
            )
        decision = self.validate(request)
        if not decision.allow:
            raise GovernanceDeniedError(decision)
        if decision.effective_tool_input is None:
            raise RuntimeError(
                "GovernedToolAdapter.guard() requires request.tool_input to be "
                "set so the executor is bound to the validated input. Use "
                "validate() directly when no tool input is involved."
            )
        return fn(decision.effective_tool_input)
