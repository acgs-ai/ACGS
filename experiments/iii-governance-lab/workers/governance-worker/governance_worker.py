from __future__ import annotations

import os
from typing import Any

from iii import InitOptions, Logger, register_worker


worker = register_worker(
    address=os.environ.get("III_URL", "ws://localhost:49134"),
    options=InitOptions(worker_name="governance-worker"),
)
logger = Logger()


request_schema = {
    "type": "object",
    "required": ["subject", "action", "resource"],
    "properties": {
        "subject": {"type": "string"},
        "action": {"type": "string"},
        "resource": {"type": "string"},
    },
    "additionalProperties": False,
}

response_schema = {
    "type": "object",
    "required": ["decision", "reason", "mode"],
    "properties": {
        "decision": {"enum": ["allow", "deny"]},
        "reason": {"type": "string"},
        "mode": {"const": "experimental"},
    },
    "additionalProperties": False,
}


def evaluate_policy(payload: dict[str, Any]) -> dict[str, str]:
    subject = str(payload.get("subject", ""))
    action = str(payload.get("action", ""))
    resource = str(payload.get("resource", ""))

    default_deny = {
        "decision": "deny",
        "reason": "local lab policy only allows read access to policy resources",
        "mode": "experimental",
    }

    if not subject:
        return {
            "decision": "deny",
            "reason": "subject is required for local lab evaluation",
            "mode": "experimental",
        }

    if action == "read" and resource.startswith("policy/"):
        return {
            "decision": "allow",
            "reason": "read access to policy resources is allowed in the local lab",
            "mode": "experimental",
        }

    return default_deny


worker.register_function(
    "governance::evaluate_policy",
    evaluate_policy,
    request_format=request_schema,
    response_format=response_schema,
)
