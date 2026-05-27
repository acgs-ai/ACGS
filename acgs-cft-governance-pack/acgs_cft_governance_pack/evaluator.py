from __future__ import annotations

from typing import Any

from acgs_cft_governance_pack.controls import evaluate_control
from acgs_cft_governance_pack.evidence import build_evidence_event
from acgs_cft_governance_pack.hashing import hash_json
from acgs_cft_governance_pack.policy_io import (
    load_policies as load_policies,
    write_evidence_jsonl as write_evidence_jsonl,
)

JsonDict = dict[str, Any]

__all__ = ["evaluate_plan", "load_policies", "write_evidence_jsonl"]


def evaluate_plan(
    plan: JsonDict,
    policies: list[JsonDict],
    *,
    actor_id: str,
    actor_role: str,
    tenant: str = "default",
) -> JsonDict:
    plan_hash = f"sha256:{hash_json(plan)}"
    control_results: list[JsonDict] = []

    for policy in policies:
        policy_id = _required_string(policy, "id")
        for control in policy.get("controls", []):
            control_results.append(evaluate_control(plan, policy_id, control))

    return build_evidence_event(
        plan_hash=plan_hash,
        policies=[_required_string(policy, "id") for policy in policies],
        control_results=control_results,
        actor_id=actor_id,
        actor_role=actor_role,
        tenant=tenant,
    )


def _required_string(mapping: JsonDict, key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Expected non-empty string field: {key}")
    return value
