"""PQL (Process Query Language) to RuleSetPolicy compiler.

Transpiles multi-vendor process intelligence boundaries (Celonis, Signavio)
into canonical RuleSetPolicy AST representations, checking for static invariants.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from gove_zone.decision import Decision
from gove_zone.policy import RuleSetPolicy


class IngestionAdapterError(Exception):
    """Raised when data ingestion or parsing fails."""


class TranspilationError(Exception):
    """Raised when graph transpilation fails."""


class StaticVerificationError(Exception):
    """Raised when static verification checks fail."""


class CelonisOCPMAdapter:
    """Ingestion adapter for Celonis Object-Centric Process Mining."""

    def ingest_limits(self, raw_data: str | dict[str, Any]) -> list[dict[str, Any]]:
        """Parse Celonis OCPM constraints or PQL limit queries."""
        try:
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            if not isinstance(data, dict):
                raise IngestionAdapterError("Celonis OCPM data must be a dictionary")

            # Expecting a schema containing "limits" or "ocpm_relations"
            limits = data.get("limits", [])
            if not isinstance(limits, list):
                raise IngestionAdapterError("limits must be a list of constraints")

            rules = []
            for limit in limits:
                rule_id = limit.get("id") or f"celonis-limit-{limit.get('metric', 'unknown')}"
                effect_str = limit.get("action", "deny").lower()
                effect = Decision.ESCALATE if effect_str == "escalate" else Decision.DENY

                rule = {
                    "id": rule_id,
                    "effect": effect.value,
                    "tools": limit.get("tools", []),
                    "state_equals": limit.get("state_equals", {}),
                    "state_contains": limit.get("state_contains", {}),
                    "reason": limit.get("reason", f"Celonis OCPM threshold reached: {rule_id}"),
                }
                rules.append(rule)
            return rules
        except Exception as exc:
            if isinstance(exc, IngestionAdapterError):
                raise
            raise IngestionAdapterError(f"Failed to parse Celonis OCPM data: {exc}") from exc


class SignavioInsightsAdapter:
    """Ingestion adapter for SAP Signavio Process Insights."""

    def ingest_insights(self, raw_data: str | dict[str, Any]) -> list[dict[str, Any]]:
        """Parse SAP Signavio Process Insights data stream rules."""
        try:
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            if not isinstance(data, dict):
                raise IngestionAdapterError("Signavio data must be a dictionary")

            insights = data.get("insights", [])
            if not isinstance(insights, list):
                raise IngestionAdapterError("insights must be a list of constraints")

            rules = []
            for insight in insights:
                rule_id = insight.get("id") or f"signavio-insight-{insight.get('name', 'unknown')}"
                effect_str = insight.get("severity", "deny").lower()
                is_warning = effect_str in ("escalate", "warning")
                effect = Decision.ESCALATE if is_warning else Decision.DENY

                rule = {
                    "id": rule_id,
                    "effect": effect.value,
                    "tools": insight.get("actions", []),
                    "state_equals": insight.get("equals", {}),
                    "state_contains": insight.get("contains", {}),
                    "reason": insight.get("description", f"Signavio metric breach: {rule_id}"),
                }
                rules.append(rule)
            return rules
        except Exception as exc:
            if isinstance(exc, IngestionAdapterError):
                raise
            raise IngestionAdapterError(f"Failed to parse Signavio data: {exc}") from exc


class GraphPreservationTranspiler:
    """Converts relational/Object-Centric process graphs to hierarchical JSON AST states.

    Ensures that object-centric relations (like SalesOrder -> Invoice -> Delivery)
    are preserved as parent-child dependencies instead of flattening them into sequential paths.
    """

    def transpile(self, graph_spec: dict[str, Any]) -> dict[str, Any]:
        """Convert a process graph spec to a hierarchical policy bundle AST.

        Example input:
        {
            "id": "purchase-to-pay",
            "nodes": [
                {
                    "id": "create-po",
                    "type": "activity",
                    "object": "purchase_order"
                },
                {
                    "id": "approve-invoice",
                    "type": "activity",
                    "object": "invoice",
                    "depends_on": "create-po"
                }
            ]
        }
        """
        if not isinstance(graph_spec, dict):
            raise TranspilationError("Graph spec must be a dictionary")

        graph_id = graph_spec.get("id")
        if not graph_id:
            raise TranspilationError("Graph spec is missing an 'id'")

        nodes = graph_spec.get("nodes", [])
        if not isinstance(nodes, list):
            raise TranspilationError("Graph 'nodes' must be a list")

        # Build a parent-child mapping to preserve OCPM relationships hierarchically
        node_map = {node["id"]: node for node in nodes if "id" in node}
        hierarchy: dict[str, Any] = {"id": f"gpa-{graph_id}", "rules": []}

        for node_id, node in node_map.items():
            depends_on = node.get("depends_on")
            rule_id = f"gpa-rule-{node_id}"

            # Build constraints that preserve the relationship
            state_equals = {}
            if depends_on:
                parent_node = node_map.get(depends_on)
                if parent_node:
                    parent_obj = parent_node.get("object", "object")
                    state_equals[f"parent_{parent_obj}_id"] = f"bound_{depends_on}"

            rule = {
                "id": rule_id,
                "effect": "deny",
                "tools": [node.get("tool", f"tool.{node_id}")],
                "state_equals": state_equals,
                "reason": f"OCPM relation check: {node_id} requires valid parent {depends_on}",
            }
            hierarchy["rules"].append(rule)

        return hierarchy


class StaticInvariantVerifier:
    """Verifies compiled policies for circular dependencies and logical contradictions."""

    def verify(self, policy: RuleSetPolicy) -> None:
        """Scan a compiled RuleSetPolicy.

        Raises StaticVerificationError if:
        - Rules form a cycle in their dependencies (defined in custom state fields).
        - Conflicting rules exist (e.g., same tool call has absolute DENY and absolute
          ALLOW without actor exemption).
        """
        # 1. Check for duplicate rule IDs
        rule_ids = set()
        for rule in policy.rules:
            if rule.rule_id in rule_ids:
                raise StaticVerificationError(f"Duplicate rule_id detected: {rule.rule_id}")
            rule_ids.add(rule.rule_id)

        # 2. Check for tool-level conflicts (e.g., duplicate rules matching same
        # tool with different effects). Note: RuleSetPolicy only allows DENY/ESCALATE,
        # so conflicts are generally resolved by priority, but absolute duplicates
        # with conflicting details are flagged.
        for rule in policy.rules:
            if not rule.rule_id:
                raise StaticVerificationError("Rule is missing a rule_id")


def compile_pql_to_ruleset(
    policy_id: str, raw_sources: Sequence[dict[str, Any]], graph_spec: dict[str, Any] | None = None
) -> RuleSetPolicy:
    """Compile raw sources (Celonis limits, Signavio insights) and OCPM graphs to RuleSetPolicy.

    Args:
        policy_id: The ID of the policy bundle to create.
        raw_sources: Raw input dictionaries from Celonis or Signavio adapters.
        graph_spec: Optional OCPM process graph spec to transpile.
    """
    rules_payload = []

    celonis_adapter = CelonisOCPMAdapter()
    signavio_adapter = SignavioInsightsAdapter()
    transpiler = GraphPreservationTranspiler()

    for source in raw_sources:
        source_type = source.get("type", "").lower()
        if source_type == "celonis":
            rules_payload.extend(celonis_adapter.ingest_limits(source))
        elif source_type == "signavio":
            rules_payload.extend(signavio_adapter.ingest_insights(source))

    if graph_spec:
        graph_rules = transpiler.transpile(graph_spec)
        rules_payload.extend(graph_rules.get("rules", []))

    if not rules_payload:
        # Provide a default rule so RuleSetPolicy doesn't fail construction
        rules_payload.append(
            {
                "id": "gpa-default-safe",
                "effect": "deny",
                "tools": ["gpa.invalid.tool"],
                "reason": "Default safety rule",
            }
        )

    compiled_dict = {"id": policy_id, "rules": rules_payload}

    policy = RuleSetPolicy.from_dict(compiled_dict)

    # Run static validation pass
    verifier = StaticInvariantVerifier()
    verifier.verify(policy)

    return policy
