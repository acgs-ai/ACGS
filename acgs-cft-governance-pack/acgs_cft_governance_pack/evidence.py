from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from acgs_cft_governance_pack.hashing import merkle_root

JsonDict = dict[str, Any]


def build_evidence_event(
    *,
    plan_hash: str,
    policies: list[str],
    control_results: list[JsonDict],
    actor_id: str,
    actor_role: str,
    tenant: str,
    now: datetime | None = None,
) -> JsonDict:
    failures = [result for result in control_results if result["status"] == "fail"]
    decision = "deny" if failures else "allow"
    reason = (
        f"Denied by {len(failures)} governance controls" if failures else "All applicable governance controls passed"
    )
    timestamp = now or datetime.now(timezone.utc)
    event = {
        "schema": "acgs.cft.evidence.v1",
        "event_type": "terraform_plan_evaluation",
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "tenant": tenant,
        "actor": {"id": actor_id, "role": actor_role},
        "decision": decision,
        "reason": reason,
        "plan_hash": plan_hash,
        "policies": policies,
        "control_results": control_results,
    }
    event["merkle_root"] = f"sha256:{merkle_root([plan_hash, event['actor'], control_results, decision])}"
    return event
