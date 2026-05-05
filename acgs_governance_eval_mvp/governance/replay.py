from __future__ import annotations

from typing import Any

from governance.adapters.tools import GovernedToolAdapter
from governance.models import ActionRequest


def replay_event(
    event: dict[str, Any],
    *,
    roles_bundle: dict[str, Any],
    policy_bundle: dict[str, Any],
) -> dict[str, Any]:
    """Replay an audit event without appending a new audit record."""
    request = ActionRequest.from_dict(event["request"])
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
    }
