from __future__ import annotations

from time import perf_counter
from typing import Any

from governance.models import ActionRequest, GateResult


class GovernanceRecallGate:
    """Produces a verifiable explanation of why a decision is allowed or denied."""

    name = "governance_recall"
    mandatory_gates = {"authority", "policy_recall"}

    def validate(
        self,
        request: ActionRequest,
        prior_results: list[GateResult],
        *,
        role_version: str,
        policy_version: str,
    ) -> GateResult:
        started = perf_counter()

        seen = {result.gate for result in prior_results}
        missing = sorted(self.mandatory_gates - seen)
        if missing:
            return GateResult(
                gate=self.name,
                allowed=False,
                reason_codes=["GOVERNANCE_RECALL_INCOMPLETE"],
                reasons=[f"Missing mandatory gate result(s): {', '.join(missing)}."],
                rule_ids=[],
                evidence={"missing_gates": missing},
                latency_ms=self._elapsed_ms(started),
            )

        denied = [result for result in prior_results if not result.allowed]
        explanation = {
            "event_id": request.event_id,
            "actor": {
                "id": request.actor.id,
                "role": request.actor.role,
                "tenant": request.actor.tenant,
            },
            "action": {
                "type": request.action_type,
                "resource": request.resource,
                "intent": request.intent,
                "inputs_hash": request.inputs_hash,
            },
            "versions": {
                "role_version": role_version,
                "policy_version": policy_version,
            },
            "checks": [
                {
                    "gate": result.gate,
                    "allowed": result.allowed,
                    "reason_codes": result.reason_codes,
                    "rule_ids": result.rule_ids,
                }
                for result in prior_results
            ],
            "conflict_resolution": "deny_overrides_allow" if denied else "all_required_gates_allow",
        }

        if denied:
            return GateResult(
                gate=self.name,
                allowed=False,
                reason_codes=["GOVERNANCE_RECALL_DENY"],
                reasons=["Governance recall explains denial path; at least one mandatory gate denied."],
                rule_ids=sorted({rule_id for result in prior_results for rule_id in result.rule_ids}),
                evidence=explanation,
                latency_ms=self._elapsed_ms(started),
            )

        return GateResult(
            gate=self.name,
            allowed=True,
            reason_codes=["GOVERNANCE_RECALL_OK"],
            reasons=["Governance recall explanation is complete and verifiable."],
            rule_ids=sorted({rule_id for result in prior_results for rule_id in result.rule_ids}),
            evidence=explanation,
            latency_ms=self._elapsed_ms(started),
        )

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((perf_counter() - started) * 1000, 3)
