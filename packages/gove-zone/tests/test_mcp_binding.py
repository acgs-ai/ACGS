"""Tests for the first-class MCP binding (``gove_zone.mcp``, audit R5 / PR-5).

Every assertion drives the *binding entry points* (``mcp_tools_call`` /
``mcp_tools_list``) with MCP-shaped request dicts — not unit calls into the
kernel — per the handler-wiring rubric. The properties under test:

- **Structural admission**: the callable set IS the kernel registry. A tool
  registered at runtime is gated with zero binding changes; an unregistered
  tool cannot run and produces no audit event; there is no safe-tool bypass.
- **Envelope consumption**: DENY/ESCALATE surface the full machine-readable
  rejection envelope in ``_meta.gove_zone`` (the production consumer of
  ``to_rejection_dict``).
- **Fail-closed error surface**: malformed requests, audit failures, and
  tool-raised exceptions are ``isError: true`` results; tool exception text is
  never echoed.
"""

from __future__ import annotations

import json

from gove_zone import (
    AllowAllPolicy,
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    Kernel,
    Policy,
    mcp_tools_call,
    mcp_tools_list,
    new_event_id,
    sha256_json,
)
from gove_zone.tool import ToolCall


class _EscalatePolicy(Policy):
    @property
    def version(self) -> str:
        return "test-escalate/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("ESCALATE:needs-human",),
            reason="needs human approval",
        )


def _kernel(policy: Policy, tmp_path) -> tuple[Kernel, list[dict]]:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    ran: list[dict] = []
    kernel = Kernel(policy=policy, audit=audit, actor="mcp-agent")

    @kernel.tool("notes.write")
    def write_note(**kwargs: object) -> dict:
        ran.append(dict(kwargs))
        return {"written": True}

    return kernel, ran


def _call(name: str, arguments: dict | None = None) -> dict:
    return {
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


# ------------------------------------------------------------------ allow


def test_allow_path_executes_and_anchors_receipt(tmp_path) -> None:
    kernel, ran = _kernel(AllowAllPolicy(), tmp_path)
    before = kernel.audit.last_hash()

    result = mcp_tools_call(kernel, _call("notes.write", {"text": "hi"}))

    assert result["isError"] is False
    assert ran == [{"text": "hi"}]  # executed exactly once
    meta = result["_meta"]["gove_zone"]
    assert meta["decision"] == "allow"
    assert meta["audit_hash"] != before  # decision is anchored in the chain
    assert meta["result_hash"]
    assert json.loads(result["content"][0]["text"]) == {"written": True}


def test_bare_params_shape_is_accepted(tmp_path) -> None:
    kernel, ran = _kernel(AllowAllPolicy(), tmp_path)
    result = mcp_tools_call(kernel, {"name": "notes.write", "arguments": {"x": 1}})
    assert result["isError"] is False
    assert ran == [{"x": 1}]


# ---------------------------------------------------------- deny/escalate


def test_deny_returns_rejection_envelope_and_never_executes(tmp_path) -> None:
    kernel, ran = _kernel(
        BoundaryPolicy(forbidden_keywords=["forbidden"], rule_id="P-MCP"), tmp_path
    )
    before = kernel.audit.last_hash()

    result = mcp_tools_call(kernel, _call("notes.write", {"text": "this is forbidden"}))

    assert result["isError"] is True
    assert ran == []  # the deny happened BEFORE any side effect
    envelope = result["_meta"]["gove_zone"]
    # The full machine-readable envelope, not a prose-only error.
    assert envelope["status"] == "deny"
    assert envelope["outcome"] == "denied"
    assert envelope["resolution"] == "revise_and_retry"
    assert envelope["resumable"] is False
    assert envelope["matched_rules"]
    assert envelope["audit_hash"] != before  # the DENY itself is audited
    assert "denied notes.write" in result["content"][0]["text"]


def test_escalate_envelope_advertises_resume_affordance(tmp_path) -> None:
    kernel, ran = _kernel(_EscalatePolicy(), tmp_path)
    result = mcp_tools_call(kernel, _call("notes.write", {"text": "hi"}))
    assert result["isError"] is True
    assert ran == []
    envelope = result["_meta"]["gove_zone"]
    assert envelope["status"] == "escalate"
    assert envelope["resolution"] == "human_approval"
    # Kernel attaches PendingApproval on every ESCALATE dispatch.
    assert envelope["resumable"] is True
    assert envelope["approval"] == {"via": "approve_escalation", "pending": True}


# ------------------------------------------------------ structural admission


def test_unregistered_tool_cannot_run_and_is_not_audited(tmp_path) -> None:
    kernel, ran = _kernel(AllowAllPolicy(), tmp_path)
    before = kernel.audit.last_hash()

    result = mcp_tools_call(kernel, _call("shell.exec", {"cmd": "rm -rf /"}))

    assert result["isError"] is True
    assert "not registered" in result["content"][0]["text"]
    assert result["_meta"]["gove_zone"]["decision"] == "not_evaluated"
    assert ran == []
    assert kernel.audit.last_hash() == before  # nothing was evaluated


def test_runtime_registered_tool_is_gated_with_zero_binding_changes(tmp_path) -> None:
    # THE structural-admission proof: register a brand-new tool on the kernel
    # and it is immediately (a) advertised, (b) policy-gated, (c) audited —
    # without touching gove_zone.mcp. Forgetting to register means
    # "unavailable", never "silently allowed".
    kernel, _ = _kernel(BoundaryPolicy(forbidden_keywords=["secret"], rule_id="P-NEW"), tmp_path)
    executed: list[dict] = []

    @kernel.tool("mail.send")
    def send_mail(**kwargs: object) -> str:
        executed.append(dict(kwargs))
        return "sent"

    assert {"name": "mail.send"} in mcp_tools_list(kernel)["tools"]

    denied = mcp_tools_call(kernel, _call("mail.send", {"body": "the secret plans"}))
    assert denied["isError"] is True
    assert denied["_meta"]["gove_zone"]["status"] == "deny"
    assert executed == []

    allowed = mcp_tools_call(kernel, _call("mail.send", {"body": "hello"}))
    assert allowed["isError"] is False
    assert executed == [{"body": "hello"}]


def test_tools_list_is_exactly_the_registry(tmp_path) -> None:
    kernel, _ = _kernel(AllowAllPolicy(), tmp_path)
    assert mcp_tools_list(kernel) == {"tools": [{"name": "notes.write"}]}


# ------------------------------------------------------------- error surface


def test_malformed_requests_are_rejected_without_dispatch(tmp_path) -> None:
    kernel, ran = _kernel(AllowAllPolicy(), tmp_path)
    before = kernel.audit.last_hash()
    for bad in (
        ["tools/call"],  # JSON-RPC batch (top-level array)
        "tools/call",
        None,
        {"method": "resources/read", "params": {"name": "notes.write"}},
        {"method": "tools/call", "params": "nope"},
        {"method": "tools/call", "params": {"arguments": {}}},
        {"method": "tools/call", "params": {"name": ""}},
        {"method": "tools/call", "params": {"name": "notes.write", "arguments": [1]}},
        {"method": "tools/call", "params": {"name": "notes.write", "arguments": []}},
        {"method": "tools/call", "params": {"name": "notes.write", "arguments": 0}},
    ):
        result = mcp_tools_call(kernel, bad)
        assert result["isError"] is True, bad
        assert result["_meta"]["gove_zone"]["decision"] == "not_evaluated"
    assert ran == []
    assert kernel.audit.last_hash() == before


def test_tool_exception_is_error_result_without_echoing_message(tmp_path) -> None:
    kernel, _ = _kernel(AllowAllPolicy(), tmp_path)

    @kernel.tool("boom.run")
    def boom(**kwargs: object) -> str:
        raise RuntimeError("raw secret argument leaked in message")

    result = mcp_tools_call(kernel, _call("boom.run", {"x": 1}))
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "RuntimeError" in text  # the class is conveyed
    assert "secret" not in text  # the tool-authored message is NOT echoed


def test_path_argument_reaches_path_policies(tmp_path) -> None:
    from gove_zone import PathBoundaryPolicy

    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(
        policy=PathBoundaryPolicy(blocked_prefixes=["/etc"]),
        audit=audit,
        actor="mcp-agent",
    )
    ran: list[dict] = []

    @kernel.tool("file.write")
    def write_file(**kwargs: object) -> str:
        ran.append(dict(kwargs))
        return "ok"

    denied = mcp_tools_call(kernel, _call("file.write", {"path": "/etc/passwd", "data": "x"}))
    assert denied["isError"] is True
    assert ran == []

    allowed = mcp_tools_call(kernel, _call("file.write", {"path": "/tmp/ok", "data": "x"}))
    assert allowed["isError"] is False
    # The lifted path context did not mutate the tool's actual arguments.
    assert ran == [{"path": "/tmp/ok", "data": "x"}]


def test_list_segmented_path_cannot_evade_path_policy(tmp_path) -> None:
    # Security-review finding: lifting only str paths would let
    # {"path": ["etc", "passwd"]} reach the tool while PathBoundaryPolicy saw
    # an empty path context. Sequences must be lifted too.
    from gove_zone import PathBoundaryPolicy

    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(
        policy=PathBoundaryPolicy(blocked_prefixes=["/etc"]),
        audit=audit,
        actor="mcp-agent",
    )
    ran: list[dict] = []

    @kernel.tool("file.write")
    def write_file(**kwargs: object) -> str:
        ran.append(dict(kwargs))
        return "ok"

    denied = mcp_tools_call(kernel, _call("file.write", {"path": ["etc", "passwd"], "data": "x"}))
    assert denied["isError"] is True
    assert denied["_meta"]["gove_zone"]["status"] == "deny"
    assert ran == []


class _RedactPolicy(Policy):
    @property
    def version(self) -> str:
        return "test-transform/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        transformed = dict(call.args)
        transformed["text"] = "[REDACTED]"
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("T:redact",),
            reason="redacted before execution",
            transformed_args=transformed,
        )


def test_transform_executes_with_transformed_args(tmp_path) -> None:
    kernel, ran = _kernel(_RedactPolicy(), tmp_path)
    result = mcp_tools_call(kernel, _call("notes.write", {"text": "raw secret"}))
    assert result["isError"] is False
    assert result["_meta"]["gove_zone"]["decision"] == "transform"
    # The tool received the TRANSFORMED args, not the originals.
    assert ran == [{"text": "[REDACTED]"}]
