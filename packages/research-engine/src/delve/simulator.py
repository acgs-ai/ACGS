"""Policy stress simulator, loophole critic, and compliance reporter for delve."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


class PolicyStressSimulator:
    """Mocks agent actions and feeds mutated inputs to gove-zone policies to find loops."""

    def __init__(self, policy: Any) -> None:
        self.policy = policy

    def stress_test_tool(
        self,
        tool_name: str,
        base_args: dict[str, Any],
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Run mutations of tool arguments and state against the policy to find bypass vectors."""
        results = []
        try:
            from gove_zone.tool import ToolCall
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "PolicyStressSimulator requires the optional gove-zone integration. "
                "Install it with: pip install gove-zone."
            ) from exc

        for idx, mutation in enumerate(mutations):
            args = {**base_args, **mutation.get("args", {})}
            state = mutation.get("state", {})
            call = ToolCall(
                name=tool_name,
                args=args,
                goal=f"Stress test mutation {idx}",
                actor=mutation.get("actor", "anonymous"),
                state=state,
            )

            record = self.policy.evaluate(call)
            results.append(
                {
                    "mutation_index": idx,
                    "args": args,
                    "state": state,
                    "decision": record.decision.value,
                    "reason": record.reason,
                    "matched_rules": record.matched_rules,
                }
            )
        return results


class LoopholeIdentificationCritic:
    """LLM or heuristic critic agent scanning rulesets for security vulnerabilities."""

    def find_loopholes(self, policy_dict: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze policy dictionaries for permissive actors and broad rule matches.

        Flags rules that permit anonymous or wildcard actors and rules without a
        path or state constraint. It does not establish coverage for privileged tools.
        """
        loopholes = []
        rules = policy_dict.get("rules", [])

        for rule in rules:
            rule_id = rule.get("id", "unknown")
            allow = rule.get("allow", {})
            state_equals = rule.get("state_equals", {})
            state_contains = rule.get("state_contains", {})

            # Vulnerability: Permissive allowed actors (e.g. wildcard or anonymous)
            actors = allow.get("actors", [])
            if "anonymous" in actors or "*" in actors:
                loopholes.append(
                    {
                        "severity": "CRITICAL",
                        "rule_id": rule_id,
                        "type": "PERMISSIVE_ACTOR",
                        "description": f"Rule {rule_id} allows 'anonymous' or wildcard actors.",
                    }
                )

            # Vulnerability: Tool matching is too broad with empty state checks
            if not rule.get("path_prefix") and not state_equals and not state_contains:
                loopholes.append(
                    {
                        "severity": "WARNING",
                        "rule_id": rule_id,
                        "type": "BROAD_MATCH",
                        "description": (
                            f"Rule {rule_id} matches tools without state or path constraints."
                        ),
                    }
                )

        return loopholes


class LivingComplianceReporter:
    """Generates living briefs and writes patch recommendations to git-managed
    policy repositories.
    """

    def generate_brief(
        self,
        loopholes: list[dict[str, Any]],
        sim_results: list[dict[str, Any]],
    ) -> str:
        """Create a markdown compliance brief."""
        timestamp = datetime.now(UTC).isoformat()
        brief_lines = [
            f"# GPA-Control Living Compliance Brief ({timestamp})",
            "",
            "## 1. Loophole Critic Findings",
        ]

        if not loopholes:
            brief_lines.append("No vulnerabilities found.")
        else:
            for lh in loopholes:
                brief_lines.append(
                    f"- **[{lh['severity']}]** {lh['type']}: {lh['description']} "
                    f"(Rule: {lh['rule_id']})"
                )

        brief_lines.append("")
        brief_lines.append("## 2. Policy Stress Test Execution")
        brief_lines.append(f"Total mutations simulated: {len(sim_results)}")

        bypasses = [r for r in sim_results if r["decision"] == "allow"]
        brief_lines.append(f"Successful bypasses: {len(bypasses)}")
        for bp in bypasses:
            brief_lines.append(
                f"- Mutation index {bp['mutation_index']} "
                f"(Args: {bp['args']}, State: {bp['state']}) was ALLOWED."
            )

        return "\n".join(brief_lines)

    def suggest_patch(self, loophole: dict[str, Any]) -> dict[str, Any]:
        """Generate a patch recommendation to fix a loophole."""
        if loophole["type"] == "PERMISSIVE_ACTOR":
            return {
                "action": "modify_rule",
                "rule_id": loophole["rule_id"],
                "patch": {"allow": {"actors": ["authorized-agent"]}},
            }
        return {}
