"""HTTP governance bridge for the front-end copilot — Phase 2 (no LLM needed).

Contract (matches `acgi-ai/src/copilot/governance.ts` `admitAction`):

    POST /admit  {"action": str, "args": object}
      -> {"decision": "allow"|"deny"|"escalate", "receiptAuditHash"?: str, "reason"?: str}

It maps the copilot's "may I run this tool call?" question to a real gove-zone
policy decision and, on ALLOW, issues a Decision Receipt anchored in a real
hash-chained audit store. **Fail closed**: only ALLOW returns a receipt hash;
DENY, ESCALATE, or any internal error returns no hash, so the client never
executes a side effect without one. This is the server half of the invariant
proven at the kernel level in `demo.py`.

Run the service (local only):

    uv run --package gove-zone uvicorn \
      examples.copilotkit_governed.governance_bridge:app --port 8787

Production hardening (not this spike): execute the side-effectful tool
SERVER-SIDE behind `execute_with_receipt`, rather than trusting the client to
honour the decision. Here the client executes after an ALLOW; the receipt is
the audit anchor, not yet an executor gate.
"""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    Validator,
    sha256_json,
)
from gove_zone.policy import Policy, new_event_id
from gove_zone.tool import ToolCall

ACTOR = "copilotkit-copilot"
TENANT = "tenant-A"
BOUNDARY = "copilotkit-bridge/local"

# One audit chain per process; each ALLOW appends and chains from the previous.
_AUDIT_PATH = Path(tempfile.mkdtemp(prefix="copilot-bridge-")) / "admit-audit.jsonl"
_AUDIT_LOCK = threading.Lock()


class BridgePolicy(Policy):
    """Illustrative policy (same shape as demo.py): DENY forbidden args,
    ESCALATE human-in-the-loop tools, ALLOW otherwise. Real deployments compose
    the shipped policies (BoundaryPolicy / PathBoundaryPolicy / RuleSetPolicy).
    """

    HUMAN_IN_THE_LOOP_TOOLS = frozenset({"runtime.payment.send"})
    FORBIDDEN = ("/.ssh/", "id_rsa", "secrets/")

    @property
    def version(self) -> str:
        return "copilotkit-bridge-policy/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        blob = sha256_json(dict(call.args))
        lowered = str(sorted(dict(call.args).items())).lower()
        matched = [kw for kw in self.FORBIDDEN if kw in lowered]
        if matched:
            decision, reason = Decision.DENY, f"forbidden arg: {matched[0]}"
        elif call.name in self.HUMAN_IN_THE_LOOP_TOOLS:
            decision, reason = Decision.ESCALATE, "human-in-the-loop approval required"
        else:
            decision, reason = Decision.ALLOW, "within copilot tool boundary"
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=blob,
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(matched),
            reason=reason,
        )


_POLICY = BridgePolicy()


def admit_action(action: str, args: dict[str, Any]) -> dict[str, Any]:
    """Decide whether *action* may run. Fail closed: anything other than a
    clean ALLOW returns no ``receiptAuditHash``."""
    try:
        call = ToolCall(name=action, args=dict(args), actor=ACTOR)
        record = _POLICY.evaluate(call)

        if record.decision is Decision.ALLOW:
            with _AUDIT_LOCK:
                event = ChainHashAuditStore(_AUDIT_PATH).append(record)
                audit_hash = str(event["event_hash"])
                # Issuing the receipt proves it is well-formed; we return the same
                # anchored hash the client checks for.
                DecisionReceipt.from_record(
                    record=record,
                    audit_hash=audit_hash,
                    previous_audit_hash=str(event["previous_hash"]),
                    tenant_id=TENANT,
                    execution_boundary=BOUNDARY,
                    policy_bundle_id="copilotkit-bridge-policy",
                    policy_hash=record.policy_version,
                    request_id=f"req-{record.event_id}",
                    validator=Validator("governance-bridge"),
                    authority="tenant-A/copilot-tool-grant",
                )
            return {"decision": "allow", "receiptAuditHash": audit_hash, "reason": record.reason}

        if record.decision is Decision.ESCALATE:
            return {"decision": "escalate", "reason": record.reason}

        # DENY or any non-ALLOW decision.
        return {"decision": "deny", "reason": record.reason}
    except Exception as exc:
        return {"decision": "deny", "reason": f"governance bridge error: {exc}"}


def build_app() -> Any:
    """Thin ASGI wrapper. Imported lazily so the module (and its tests) load
    without FastAPI installed."""
    from fastapi import FastAPI

    app = FastAPI(title="ACGS copilot governance bridge")

    @app.post("/admit")
    async def admit(payload: dict[str, Any]) -> dict[str, Any]:
        action = str(payload.get("action", ""))
        args = payload.get("args") or {}
        if not isinstance(args, dict):
            return {"decision": "deny", "reason": "args must be an object"}
        return admit_action(action, args)

    return app


app = build_app()
