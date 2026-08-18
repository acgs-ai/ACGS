"""One-way DecisionReceipt → Semantica-shaped payload.

This module imports nothing from Semantica at module scope. Semantica is an
optional observation sink, never a gate. ACGS does not emit ``confidence`` or
free-text ``reasoning``; those Semantica-required parameters are documented
placeholders used only by the lazy emit path.
"""

from __future__ import annotations

from typing import Any

from gove_zone.receipt import DecisionReceipt

# Semantica's record_decision() requires non-empty reasoning and a 0..1
# confidence. ACGS DecisionReceipt has neither field (receipt.py to_dict).
# These constants are adapter-protocol padding, not ACGS evidence.
SEMANTICA_REQUIRED_REASONING_PLACEHOLDER = "ACGS_NO_REASONING_FIELD"
SEMANTICA_REQUIRED_CONFIDENCE_PLACEHOLDER = 0.0

_MAPPED_KEYS = (
    "receipt_id",
    "proposed_action",
    "declared_goal",
    "decision",
    "actor",
    "expires_at",
)
_METADATA_ONLY_KEYS = (
    "request_id",
    "tenant_id",
    "subject",
    "execution_boundary",
    "policy_bundle_id",
    "policy_version",
    "policy_hash",
    "matched_rules",
    "constraints",
    "transformations",
    "approval_chain_summary",
    "timestamp",
    "authority",
    "validator_id",
    "validator_role",
    "argument_hash",
    "action_tier",
    "previous_audit_hash",
    "audit_event_hash",
    "signature_algorithm",
    "signing_key_id",
    "receipt_hash",
    "signature",
    "receipt_schema_version",
    "project_id",
    "environment_id",
    "trust_epoch",
)
_NOT_IN_ACGS = ("reasoning", "confidence")


def receipt_to_semantica(receipt: DecisionReceipt) -> dict[str, Any]:
    """Project a receipt into a plain dict. No Semantica import."""
    data = receipt.to_dict()
    scenario = str(data.get("declared_goal") or "").strip() or str(
        data.get("proposed_action") or ""
    )
    metadata = {
        "source": "acgs.DecisionReceipt",
        "semantica_is_not_a_gate": True,
    }
    for key in _METADATA_ONLY_KEYS:
        metadata[key] = data.get(key)
    metadata["receipt_id"] = data.get("receipt_id")
    expires = str(data.get("expires_at") or "").strip()
    return {
        "decision_id": data.get("receipt_id"),
        "category": data.get("proposed_action"),
        "scenario": scenario,
        "outcome": data.get("decision"),
        "decision_maker": data.get("actor"),
        "valid_until": expires or None,
        "entities": [],
        "metadata": metadata,
        "field_map": {
            "mapped": list(_MAPPED_KEYS),
            "metadata_only": list(_METADATA_ONLY_KEYS),
            "dropped": [],
            "not_in_acgs": list(_NOT_IN_ACGS),
        },
        "semantica_is_not_a_gate": True,
    }


def emit_to_semantica(payload: dict[str, Any], graph: Any = None) -> dict[str, Any]:
    """Best-effort write to a Semantica ContextGraph. Never raises into a gate.

    Lazy-imports Semantica inside this function. Missing package, missing graph,
    or an upstream write error skips emission and leaves the ACGS decision
    unchanged.
    """
    try:
        from semantica.context import ContextGraph
    except ImportError:
        return {"emitted": False, "reason": "semantica_not_installed"}

    target = graph if graph is not None else ContextGraph(advanced_analytics=False)
    try:
        minted_id = target.record_decision(
            category=str(payload.get("category") or "acgs.unknown"),
            scenario=str(payload.get("scenario") or payload.get("decision_id") or "acgs"),
            reasoning=SEMANTICA_REQUIRED_REASONING_PLACEHOLDER,
            outcome=str(payload.get("outcome") or "unknown"),
            confidence=SEMANTICA_REQUIRED_CONFIDENCE_PLACEHOLDER,
            entities=list(payload.get("entities") or []),
            decision_maker=payload.get("decision_maker"),
            metadata=dict(payload.get("metadata") or {}),
            valid_until=payload.get("valid_until"),
        )
    except Exception as exc:
        return {
            "emitted": False,
            "reason": "semantica_write_failed",
            "error_class": type(exc).__name__,
        }
    return {
        "emitted": True,
        "receipt_id": payload.get("decision_id"),
        "semantica_node_id": minted_id,
        "id_map": {str(payload.get("decision_id")): minted_id},
        "used_reasoning_placeholder": True,
        "used_confidence_placeholder": True,
    }
