"""Dependency-free HTTP/API adapter for the Gove Zone console.

This is intentionally small: it exposes the same JSON contract consumed by
``acgi-ai`` without introducing FastAPI or another web dependency into the
minimal runtime package. Production gateways can wrap ``handle_api_request``;
local demos can run ``python -m gove_zone.api``.
"""

from __future__ import annotations

import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import DeniedError
from gove_zone.frontend_contract import receipt_to_governed_action, record_to_governed_action
from gove_zone.kernel import Kernel
from gove_zone.policy import BoundaryPolicy, Policy, new_event_id
from gove_zone.tool import ToolCall


class EscalatePolicy(Policy):
    """Demo policy that escalates every call without executing the tool."""

    @property
    def version(self) -> str:
        return "demo-escalate/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("P-1214:HUMAN_DELIBERATION",),
            reason="production governance changes require human deliberation",
        )


class TransformPolicy(Policy):
    """Demo policy that transforms every call before execution."""

    @property
    def version(self) -> str:
        return "demo-transform/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        transformed = dict(call.args)
        message = str(transformed.get("message", ""))
        transformed["message"] = message.replace("Jane Doe, DOB 1972-04-18, ", "")
        transformed["redaction"] = "safe-harbor"
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("P-1212:PHI_REDACTION",),
            reason="direct identifiers removed before delivery",
            transformed_args=transformed,
        )


def _demo_audit_path() -> Path:
    return Path(tempfile.mkdtemp(prefix="gove-zone-api-")) / "audit.jsonl"


def build_demo_actions() -> list[dict[str, Any]]:
    """Create live governed-action JSON by running real kernel dispatches."""
    actions: list[dict[str, Any]] = []

    allow_kernel = Kernel(
        policy=TransformPolicy(),
        audit=ChainHashAuditStore(_demo_audit_path()),
        actor="redactor-03",
    )

    @allow_kernel.tool("message.send")
    def send(message: str, redaction: str = "") -> dict[str, str]:
        return {"delivered": message, "redaction": redaction}

    allow_args = {"message": "Jane Doe, DOB 1972-04-18, The patient is ready for discharge."}
    _, receipt = allow_kernel.dispatch(
        "message.send",
        allow_args,
        goal="Patient update channel",
    )
    actions.append(receipt_to_governed_action(receipt, args_before=allow_args))

    deny_kernel = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["matter_id"], rule_id="P-1207"),
        audit=ChainHashAuditStore(_demo_audit_path()),
        actor="analyst-12",
    )

    @deny_kernel.tool("matter.fetch")
    def fetch(matter_id: str) -> str:
        return matter_id

    deny_args = {"matter_id": "Matter-9821", "field": "private-notes"}
    try:
        deny_kernel.dispatch(
            "matter.fetch",
            deny_args,
            goal="Matter-9821/private-notes",
        )
    except DeniedError as exc:
        actions.append(
            record_to_governed_action(
                exc.record,
                audit_hash=exc.audit_hash,
                args_before=deny_args,
                actor="analyst-12",
            )
        )

    escalate_kernel = Kernel(
        policy=EscalatePolicy(),
        audit=ChainHashAuditStore(_demo_audit_path()),
        actor="executor-01",
    )

    @escalate_kernel.tool("policy.promote")
    def promote(policy_id: str) -> str:
        return policy_id

    escalate_args = {"policy": "P-1502", "change": "promote", "reviewers": 1}
    try:
        escalate_kernel.dispatch(
            "policy.promote",
            escalate_args,
            goal="Policy P-1502",
        )
    except Exception as exc:
        if hasattr(exc, "record") and hasattr(exc, "audit_hash"):
            actions.append(
                record_to_governed_action(
                    exc.record,
                    audit_hash=exc.audit_hash,
                    args_before=escalate_args,
                    actor="executor-01",
                )
            )
        else:
            raise

    return actions


def test_action(payload: dict[str, Any]) -> dict[str, Any]:
    """Dry-run a proposed action and return a receipt-like response."""
    body = str(payload.get("payload") or "")
    policy = BoundaryPolicy(forbidden_keywords=["secret", "matter_id"], rule_id="DRY-RUN")
    call = ToolCall(name=str(payload.get("actionId") or "unknown"), args={"payload": body})
    record = policy.evaluate(call)
    outcome = "denied" if record.decision is Decision.DENY else "allowed"
    return {
        "title": "Pre-execution test receipt",
        "body": (
            f"Policy dry-run predicts {outcome.upper()} for {call.name}. "
            "No production tool was executed."
        ),
        "meta": f"{record.event_id} · {record.policy_version}",
        "outcome": outcome,
        "receiptId": record.event_id,
        "traceId": record.event_id,
    }


def handle_api_request(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | list[dict[str, Any]]]:
    """Return ``(status, json_payload)`` for the console API subset."""
    if method == "GET" and path == "/api/v1/console-summary":
        return 200, {
            "constitutionHash": "608508a9bd224290",
            "agentsOnline": 3,
            "agentsTotal": 3,
            "checks": 3,
            "runtimeLabel": "live",
            "driftBytes": 0,
            "auditAnchorSeconds": 0,
            "nextRefreshSeconds": 10,
            "medianLatencyMs": 12,
            "refusals24h": 1,
            "humanReview": 1,
            "appeals": 0,
            "retryBackoff": 0,
            "recentEvents": [
                {
                    "id": "live-action-api",
                    "body": "Live gove-zone API served governed actions.",
                    "ts": "now",
                }
            ],
            "coverage": [{"label": "Gove Zone", "posture": "confirmed", "value": "Live"}],
        }
    if method == "GET" and path == "/api/v1/agents":
        return 200, [
            {
                "id": "analyst-12",
                "name": "analyst-12",
                "role": "Analyst",
                "lane": "Proposer",
                "model": "governed-agent",
                "refusals24h": 1,
                "health": "confirmed",
                "lastSeen": "now",
            },
            {
                "id": "ca-legal-01",
                "name": "ca-legal-01",
                "role": "Canadian legal AI agent",
                "lane": "Executor",
                "model": "sonnet 4.6",
                "refusals24h": 0,
                "health": "confirmed",
                "lastSeen": "now",
            },
        ]
    if method == "GET" and path == "/api/v1/overview":
        return 200, {
            "stats": [
                {"label": "Actions", "value": "3", "sub": "live adapter"},
                {"label": "Denied", "value": "1", "sub": "tool did not execute"},
                {"label": "Receipts", "value": "3", "sub": "audit anchored"},
            ],
            "activeCases": [],
            "queues": [],
            "refusalsByArticle": [
                {
                    "article": "P-1207",
                    "citation": "Matter boundary",
                    "refusals": 1,
                    "trend": "live",
                    "posture": "blocked",
                }
            ],
        }
    if method == "GET" and path == "/api/v1/policies":
        return 200, [
            {
                "id": "P-1207",
                "name": "matter.disclosure",
                "citation": "Gove Zone boundary",
                "posture": "blocked",
                "prose": "Matter-scoped private data is denied unless the agent is authorized.",
            }
        ]
    if method == "GET" and path == "/api/v1/compile/draft":
        return 200, {
            "currentHash": "608508a9bd224290",
            "proposedHash": "608508a9bd224290",
            "changes": [],
        }
    if method == "GET" and path == "/api/v1/deliberations":
        return 200, []
    if method == "GET" and path == "/api/v1/incidents":
        return 200, []
    if method == "GET" and path == "/api/v1/tenants":
        return 200, []
    if method == "GET" and path == "/api/v1/audit":
        return 200, [
            {
                "ts": "now",
                "posture": "confirmed",
                "ev": "Live action API returned audit-backed decisions",
                "src": "gove-zone-api",
                "hash": "608508a9 · live",
            }
        ]
    if method == "GET" and path == "/api/v1/settings":
        return 200, []
    if method == "GET" and path == "/api/v1/account":
        return 200, {"identity": [], "sessions": [], "actions": []}
    if method == "GET" and path == "/api/v1/actions":
        return 200, build_demo_actions()
    if method == "POST" and path == "/api/v1/actions/test":
        return 200, test_action(body or {})
    return 404, {"error": "not_found", "path": path}


class GoveZoneHandler(BaseHTTPRequestHandler):
    """Tiny local HTTP bridge for the console contract."""

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib hook name
        status, _payload = handle_api_request("GET", self.path, {})
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        self._dispatch()

    def _dispatch(self) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            body = {}
        status, payload = handle_api_request(self.command, self.path, body)
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> None:
    port = int(os.environ.get("GOVE_ZONE_API_PORT", "8080"))
    server = ThreadingHTTPServer(("127.0.0.1", port), GoveZoneHandler)
    print(f"gove-zone API listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
