from __future__ import annotations

from typing import Any

from governance.adapters.tools import GovernedToolAdapter
from governance.models import ActionRequest, sha256_json


def replay_event(
    event: dict[str, Any],
    *,
    roles_bundle: dict[str, Any],
    policy_bundle: dict[str, Any],
) -> dict[str, Any]:
    """Replay an audit event without appending a new audit record.

    Detects policy/role drift by hashing the supplied bundles and comparing
    against the hashes recorded at original-decision time. Drift does NOT
    refuse the replay (the caller may want to see how the decision changed);
    it is reported via policy_drift / role_drift booleans. Events written by
    older versions without bundle_hash fields produce drift=False (graceful
    pass-through; drift cannot be evaluated without an anchor).
    """
    request = ActionRequest.from_dict(event["request"])

    replay_policy_hash = sha256_json(policy_bundle)
    replay_role_hash = sha256_json(roles_bundle)
    original_policy_hash = str(event.get("policy_bundle_hash", ""))
    original_role_hash = str(event.get("role_bundle_hash", ""))
    policy_drift = bool(original_policy_hash) and original_policy_hash != replay_policy_hash
    role_drift = bool(original_role_hash) and original_role_hash != replay_role_hash

    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=None)
    replayed = adapter.validate(request).to_dict()

    return {
        "event_id": event.get("event_id"),
        "same_allow": bool(replayed.get("allow")) == bool(event.get("allow")),
        "original_allow": bool(event.get("allow")),
        "replayed_allow": bool(replayed.get("allow")),
        "same_reason_codes": replayed.get("reason_codes") == event.get("reason_codes"),
        "original_reason_codes": event.get("reason_codes"),
        "replayed_reason_codes": replayed.get("reason_codes"),
        "policy_version": event.get("policy_version"),
        "role_version": event.get("role_version"),
        "policy_drift": policy_drift,
        "role_drift": role_drift,
        "original_policy_bundle_hash": original_policy_hash,
        "replay_policy_bundle_hash": replay_policy_hash,
        "original_role_bundle_hash": original_role_hash,
        "replay_role_bundle_hash": replay_role_hash,
    }
