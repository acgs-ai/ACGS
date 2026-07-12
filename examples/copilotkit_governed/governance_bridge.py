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

import dataclasses
import os
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

# One shared local audit chain; each ALLOW appends and chains from the previous.
# COPILOT_AUDIT_PATH lets tests/operators isolate the local proof file without
# creating import-time temp directories or split per-worker chains.
_AUDIT_ENV = os.getenv("COPILOT_AUDIT_PATH")
_AUDIT_PATH = (
    Path(_AUDIT_ENV) if _AUDIT_ENV else Path(tempfile.gettempdir()) / "copilot-bridge-audit.jsonl"
)
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

    def _first_forbidden_value(self, value: Any) -> str | None:
        if isinstance(value, str):
            lowered = value.lower()
            return next((kw for kw in self.FORBIDDEN if kw in lowered), None)
        if isinstance(value, dict):
            for child in value.values():
                matched = self._first_forbidden_value(child)
                if matched:
                    return matched
        elif isinstance(value, (list, tuple, set)):
            for child in value:
                matched = self._first_forbidden_value(child)
                if matched:
                    return matched
        return None

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        args = dict(call.args)
        blob = sha256_json(args)
        matched_kw = self._first_forbidden_value(args)
        matched = [matched_kw] if matched_kw else []
        if matched_kw:
            decision, reason = Decision.DENY, f"forbidden arg: {matched_kw}"
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


def admit_action(action: Any, args: Any) -> dict[str, Any]:
    """Decide whether *action* may run. Fail closed: anything other than a
    clean ALLOW returns no ``receiptAuditHash``.

    Input is validated here, not only at the HTTP edge, so a malformed call can
    never fall through to ALLOW: ``action`` must be a non-empty string and
    ``args`` must be an object. ``action``/``args`` are typed ``Any`` precisely
    because callers (and the network) may pass anything; this function is the
    single fail-closed gate that rejects it.
    """
    try:
        if not isinstance(action, str) or not action.strip():
            return {"decision": "deny", "reason": "action must be a non-empty string"}
        if not isinstance(args, dict):
            return {"decision": "deny", "reason": "args must be an object"}

        call = ToolCall(name=action, args=dict(args), actor=ACTOR)
        record = _POLICY.evaluate(call)
        # The policy returns a bare record; inject caller context the way the
        # kernel's _attach_context does, so the minted receipt is bound to ACTOR
        # rather than the "anonymous" default and can be verified for this caller.
        record = dataclasses.replace(
            record,
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
        )

        if record.decision is Decision.ALLOW:
            with _AUDIT_LOCK:
                event = ChainHashAuditStore(_AUDIT_PATH).append(record)
                audit_hash = str(event["event_hash"])
                receipt = DecisionReceipt.from_record(
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
                # Prove the receipt is well-formed AND issued for this caller before
                # returning its anchor hash. A verify failure raises and is caught
                # below, so the client fails closed (no hash).
                receipt.verify(expected_actor=ACTOR, expected_action=action)
            return {"decision": "allow", "receiptAuditHash": audit_hash, "reason": record.reason}

        if record.decision is Decision.ESCALATE:
            return {"decision": "escalate", "reason": record.reason}

        # DENY or any non-ALLOW decision.
        return {"decision": "deny", "reason": record.reason}
    except Exception as exc:
        return {"decision": "deny", "reason": f"governance bridge error: {exc}"}


def build_app() -> Any:
    """Thin ASGI wrapper. FastAPI is imported lazily, and the module-level
    ``app`` is built lazily via module ``__getattr__`` (below), so a plain
    ``import governance_bridge`` — and the module's pure tests — load without
    FastAPI installed; the FastAPI route tests skip when it is absent."""
    from fastapi import FastAPI

    app = FastAPI(title="ACGS copilot governance bridge")

    @app.post("/admit")
    async def admit(payload: dict[str, Any]) -> dict[str, Any]:
        # Delegate all validation to admit_action (the single fail-closed gate).
        # Do not coerce here: str(payload.get("action", "")) would turn a
        # non-string action into a passable string and bypass the guard.
        return admit_action(payload.get("action"), payload.get("args"))

    return app


_app: Any = None


def __getattr__(name: str) -> Any:
    # PEP 562: build the served ASGI app on first access only — e.g. uvicorn's
    # ``governance_bridge:app`` or ``from governance_bridge import app`` — so a
    # plain ``import governance_bridge`` never imports FastAPI. Cached so the
    # served object is a stable singleton (uvicorn and tests see the same app).
    if name == "app":
        global _app
        if _app is None:
            _app = build_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
