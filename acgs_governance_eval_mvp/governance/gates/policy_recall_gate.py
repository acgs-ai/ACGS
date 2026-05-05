from __future__ import annotations

from fnmatch import fnmatchcase
from time import perf_counter
from typing import Any

from governance.models import ActionRequest, GateResult


class PolicyRecallGate:
    """Requires the agent to cite applicable policies before sensitive actions.

    A request can satisfy recall by including policy IDs or obligation IDs in:
    request.metadata["policy_citations"].

    Deny policies are enforced directly when their conditions match.
    """

    name = "policy_recall"

    def __init__(
        self,
        policy_bundle: dict[str, Any],
        *,
        critical_actions: set[str] | None = None,
    ):
        self.policy_bundle = policy_bundle
        self.policies = list(policy_bundle.get("policies", []))
        self.version = str(policy_bundle.get("version", "unknown"))
        self.critical_actions = critical_actions or {
            "contract.approve",
            "contract.redline",
            "email.send",
            "marketing.publish",
            "payment.send",
            "tool.external_api.call",
        }

    def validate(self, request: ActionRequest) -> GateResult:
        started = perf_counter()
        applicable = [policy for policy in self.policies if self._policy_applies(policy, request)]
        citations = set(map(str, request.metadata.get("policy_citations", [])))

        if not applicable:
            if request.action_type in self.critical_actions or request.metadata.get("requires_policy") is True:
                return self._deny(
                    started,
                    "POLICY_NOT_FOUND",
                    f"No applicable policy found for critical action '{request.action_type}'.",
                    [],
                    {"policy_version": self.version},
                )
            return GateResult(
                gate=self.name,
                allowed=True,
                reason_codes=["POLICY_NOT_REQUIRED"],
                reasons=["No applicable policy was required for this action."],
                rule_ids=[],
                evidence={"policy_version": self.version},
                latency_ms=self._elapsed_ms(started),
            )

        deny_hits = [p for p in applicable if str(p.get("effect", "allow")).lower() == "deny"]
        if deny_hits:
            ids = [str(p["id"]) for p in deny_hits]
            return self._deny(
                started,
                "POLICY_DENY_MATCH",
                f"Deny policy matched: {', '.join(ids)}.",
                ids,
                {"policy_version": self.version, "matched_policies": self._summaries(deny_hits)},
            )

        missing: list[str] = []
        accepted: list[str] = []
        for policy in applicable:
            if not bool(policy.get("require_citation", True)):
                accepted.append(str(policy["id"]))
                continue
            references = self._valid_references(policy)
            matched = sorted(references.intersection(citations))
            if matched:
                accepted.extend(matched)
            else:
                missing.append(str(policy["id"]))

        if missing:
            return self._deny(
                started,
                "POLICY_CITATION_MISSING",
                f"Missing required policy citation(s): {', '.join(missing)}.",
                [str(p["id"]) for p in applicable],
                {
                    "policy_version": self.version,
                    "missing_policy_ids": missing,
                    "provided_citations": sorted(citations),
                    "matched_policies": self._summaries(applicable),
                },
            )

        rule_ids = sorted(set([str(p["id"]) for p in applicable] + accepted))
        return GateResult(
            gate=self.name,
            allowed=True,
            reason_codes=["POLICY_RECALL_OK"],
            reasons=["Applicable policy citations were provided and matched."],
            rule_ids=rule_ids,
            evidence={
                "policy_version": self.version,
                "provided_citations": sorted(citations),
                "matched_policies": self._summaries(applicable),
            },
            latency_ms=self._elapsed_ms(started),
        )

    def _policy_applies(self, policy: dict[str, Any], request: ActionRequest) -> bool:
        applies_when = policy.get("applies_when", {})
        actions = list(applies_when.get("action_types", ["*"]))
        resources = list(applies_when.get("resources", ["*"]))

        action_match = "*" in actions or request.action_type in actions
        resource_match = any(pattern == "*" or fnmatchcase(request.resource, pattern) for pattern in resources)
        if not action_match or not resource_match:
            return False

        return self._conditions_match(policy.get("conditions", {}), request)

    @staticmethod
    def _conditions_match(conditions: dict[str, Any], request: ActionRequest) -> bool:
        if not conditions:
            return True

        amount_gte = conditions.get("amount_cents_gte")
        if amount_gte is not None and (request.amount_cents is None or request.amount_cents < int(amount_gte)):
            return False

        metadata_flags_any = conditions.get("metadata_flags_any")
        if metadata_flags_any is not None:
            flags = set(map(str, request.metadata.get("content_flags", [])))
            if not flags.intersection(set(map(str, metadata_flags_any))):
                return False

        metadata_equals = conditions.get("metadata_equals", {})
        for key, expected in metadata_equals.items():
            if request.metadata.get(key) != expected:
                return False

        return True

    @staticmethod
    def _valid_references(policy: dict[str, Any]) -> set[str]:
        refs = {str(policy["id"])}
        for obligation in policy.get("obligations", []):
            if "id" in obligation:
                refs.add(str(obligation["id"]))
        return refs

    @staticmethod
    def _summaries(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": str(policy.get("id")),
                "title": str(policy.get("title", "")),
                "effect": str(policy.get("effect", "allow")),
            }
            for policy in policies
        ]

    def _deny(
        self,
        started: float,
        code: str,
        reason: str,
        rule_ids: list[str],
        evidence: dict[str, Any],
    ) -> GateResult:
        return GateResult(
            gate=self.name,
            allowed=False,
            reason_codes=[code],
            reasons=[reason],
            rule_ids=rule_ids,
            evidence=evidence,
            latency_ms=self._elapsed_ms(started),
        )

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((perf_counter() - started) * 1000, 3)
