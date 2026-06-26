"""Principal authorization enforcement tests (B13, first slice).

Covers the fail-closed ``AUTHZ_ENFORCE`` kill-switch on the kernel:

- OFF (default) is a byte-for-byte no-op — an unregistered actor still runs.
- ON denies unregistered / tool-unauthorized principals BEFORE policy + tool.
- Denials surface through the production MCP dispatcher (the wiring proof, per
  ~/.claude/rules/review-handler-wiring.md — a direct ``dispatch`` unit call is
  not sufficient to prove the gate sits in the real request path).
- Misconfiguration (enforce on, no registry / bad registry) fails closed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import (
    AllowAllPolicy,
    ChainHashAuditStore,
    Decision,
    Kernel,
    PrincipalEntry,
    PrincipalRegistry,
)
from gove_zone.authz import AuthzRegistryError, authz_enforce_from_env
from gove_zone.mcp import mcp_tools_call


def _registry(*entries: PrincipalEntry) -> PrincipalRegistry:
    reg = PrincipalRegistry()
    for entry in entries:
        reg.add(entry)
    return reg


def _kernel(
    tmp_path: Path,
    *,
    actor: str = "anonymous",
    enforce: bool = False,
    registry: PrincipalRegistry | None = None,
) -> Kernel:
    return Kernel(
        policy=AllowAllPolicy(),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor=actor,
        authz_enforce=enforce,
        principal_registry=registry,
    )


def test_kill_switch_off_is_noop_for_unregistered_actor(tmp_path: Path) -> None:
    """Default OFF: an unregistered actor dispatches exactly as before."""
    k = _kernel(tmp_path, actor="nobody", enforce=False)

    @k.tool("echo")
    def echo(msg: str) -> str:
        return msg.upper()

    result, receipt = k.dispatch("echo", {"msg": "hi"})

    assert result == "HI"
    assert receipt.record.decision is Decision.ALLOW


def test_enforce_allows_registered_principal_through_dispatcher(tmp_path: Path) -> None:
    """ON + authorized principal: the MCP dispatcher runs the tool normally."""
    k = _kernel(
        tmp_path,
        actor="agent-1",
        enforce=True,
        registry=_registry(PrincipalEntry("agent-1", frozenset({"echo"}))),
    )
    ran: list[str] = []

    @k.tool("echo")
    def echo(msg: str) -> str:
        ran.append("ran")
        return msg.upper()

    result = mcp_tools_call(k, {"name": "echo", "arguments": {"msg": "hi"}})

    assert result.get("isError") is not True
    assert ran == ["ran"]


def test_enforce_denies_unregistered_actor_through_dispatcher(tmp_path: Path) -> None:
    """Wiring proof: an unregistered actor is denied at the MCP boundary,
    fail-closed, and the tool never executes."""
    k = _kernel(
        tmp_path,
        actor="intruder",
        enforce=True,
        registry=_registry(PrincipalEntry("agent-1", None)),
    )
    ran: list[str] = []

    @k.tool("echo")
    def echo(msg: str) -> str:
        ran.append("ran")
        return msg.upper()

    result = mcp_tools_call(k, {"name": "echo", "arguments": {"msg": "hi"}})

    assert result["isError"] is True
    assert result["_meta"]["gove_zone"]["outcome"] == "denied"
    assert ran == []  # fail-closed: the side effect never ran


def test_registered_actor_denied_for_tool_not_permitted(tmp_path: Path) -> None:
    """A known principal acting outside its allowed_tools is denied with the
    specific reason code (asserted via ``simulate``, which shares the seam)."""
    k = _kernel(
        tmp_path,
        actor="agent-1",
        enforce=True,
        registry=_registry(PrincipalEntry("agent-1", frozenset({"read"}))),
    )

    @k.tool("write")
    def write(path: str) -> None:
        return None

    record = k.simulate("write", {"path": "/tmp/x"})

    assert record.decision is Decision.DENY
    assert record.matched_rules == ("AUTHZ_DENY:TOOL_NOT_PERMITTED",)
    assert record.policy_version == "fail-closed/authz"


def test_default_anonymous_actor_denied_when_unregistered(tmp_path: Path) -> None:
    """With enforcement on, the default ``anonymous`` actor is denied unless it
    is explicitly registered — no implicit trust of the default identity."""
    k = _kernel(
        tmp_path,
        enforce=True,
        registry=_registry(PrincipalEntry("agent-1", None)),
    )

    @k.tool("echo")
    def echo(msg: str) -> str:
        return msg.upper()

    record = k.simulate("echo", {"msg": "hi"})

    assert record.decision is Decision.DENY
    assert record.matched_rules == ("AUTHZ_DENY:UNREGISTERED_PRINCIPAL",)


def test_enforce_without_registry_fails_closed_at_construction(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires a principal_registry"):
        Kernel(
            policy=AllowAllPolicy(),
            audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
            authz_enforce=True,
        )


def test_registry_from_json_roundtrip_and_failclosed(tmp_path: Path) -> None:
    good = tmp_path / "principals.json"
    good.write_text(
        '[{"principal_id": "agent-1", "allowed_tools": ["echo"]},'
        ' {"principal_id": "admin", "allowed_tools": null}]',
        encoding="utf-8",
    )
    reg = PrincipalRegistry.from_json(good)
    assert reg.authorize("agent-1", "echo") is None
    assert reg.authorize("agent-1", "write") is not None  # tool not permitted
    assert reg.authorize("admin", "anything") is None  # null => all tools
    assert reg.authorize("ghost", "echo") is not None  # unregistered

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(AuthzRegistryError):
        PrincipalRegistry.from_json(bad)

    with pytest.raises(AuthzRegistryError):
        PrincipalRegistry.from_json(tmp_path / "does-not-exist.json")

    # Every shape error fails closed as AuthzRegistryError — not a bare
    # ValueError/TypeError that a config loader catching AuthzRegistryError
    # would miss, and not a silently-coerced wrong registry.
    for name, content in (
        ("dup", '[{"principal_id": "a"}, {"principal_id": "a"}]'),  # duplicate id
        ("noniter", '[{"principal_id": "a", "allowed_tools": 5}]'),  # not a list
        ("nonstr", '[{"principal_id": "a", "allowed_tools": [1, 2]}]'),  # not strings
    ):
        path = tmp_path / f"{name}.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(AuthzRegistryError):
            PrincipalRegistry.from_json(path)


def test_authz_deny_is_persisted_in_audit_chain(tmp_path: Path) -> None:
    """The fail-closed AUTHZ DENY is anchored in the audit chain exactly once,
    carrying the reason code — proof the denial is auditable, not just raised."""
    k = _kernel(
        tmp_path,
        actor="intruder",
        enforce=True,
        registry=_registry(PrincipalEntry("agent-1", None)),
    )

    @k.tool("echo")
    def echo(msg: str) -> str:
        return msg.upper()

    result = mcp_tools_call(k, {"name": "echo", "arguments": {"msg": "hi"}})
    assert result["isError"] is True

    events = list(k.audit.iter_events())
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert events[0]["policy_version"] == "fail-closed/authz"
    assert events[0]["matched_rules"] == ["AUTHZ_DENY:UNREGISTERED_PRINCIPAL"]
    assert k.audit.verify_chain()["valid"] is True


def test_authz_enforce_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTHZ_ENFORCE", raising=False)
    assert authz_enforce_from_env() is False
    monkeypatch.setenv("AUTHZ_ENFORCE", "1")
    assert authz_enforce_from_env() is True
    monkeypatch.setenv("AUTHZ_ENFORCE", "off")
    assert authz_enforce_from_env() is False
