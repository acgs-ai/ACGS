"""Fail-closed tests for the copilot governance bridge.

Covers both the pure `admit_action()` and the wired `/admit` HTTP route (via
FastAPI TestClient), per ~/.claude/rules/review-handler-wiring.md: a unit test
of the function is not enough — the dispatcher path must be exercised too.

Invariant under test: only a clean ALLOW returns a `receiptAuditHash`; DENY,
ESCALATE, malformed input, and internal errors return none.
"""

from __future__ import annotations

import re

from examples.copilotkit_governed.governance_bridge import admit_action, app, build_app

HEX64 = re.compile(r"^[0-9a-f]{64}$")


# --- pure admit_action() ----------------------------------------------------


def test_allow_returns_receipt() -> None:
    # Doubles as the actor-binding regression guard: admit_action mints the
    # receipt and calls receipt.verify(expected_actor=ACTOR) before returning.
    # If the caller context (actor) stops being injected into the record, that
    # verify raises and this ALLOW collapses to DENY — so a green assert here
    # proves the receipt is bound to ACTOR, not the "anonymous" default.
    out = admit_action("runtime.file.write", {"path": "evidence/report.json", "content": "ok"})
    assert out["decision"] == "allow"
    assert HEX64.match(out["receiptAuditHash"])


def test_deny_has_no_receipt() -> None:
    out = admit_action(
        "runtime.file.write", {"path": "/home/u/.ssh/authorized_keys", "content": "x"}
    )
    assert out["decision"] == "deny"
    assert "receiptAuditHash" not in out


def test_escalate_has_no_receipt() -> None:
    out = admit_action("runtime.payment.send", {"to": "vendor-x", "amount": 5000})
    assert out["decision"] == "escalate"
    assert "receiptAuditHash" not in out


def test_default_audit_path_is_shared_temp_file() -> None:
    import tempfile
    from pathlib import Path

    from examples.copilotkit_governed import governance_bridge

    expected = Path(tempfile.gettempdir()) / "copilot-bridge-audit.jsonl"
    assert governance_bridge._AUDIT_PATH == expected


def test_forbidden_matching_ignores_dict_keys() -> None:
    out = admit_action(
        "runtime.file.write",
        {"secrets/path_label": "public/report.json", "content": "ok"},
    )
    assert out["decision"] == "allow"
    assert HEX64.match(out["receiptAuditHash"])


def test_forbidden_matching_checks_nested_string_values() -> None:
    out = admit_action(
        "runtime.file.write",
        {"paths": ["public/report.json", {"target": "/home/u/.ssh/authorized_keys"}]},
    )
    assert out["decision"] == "deny"
    assert "receiptAuditHash" not in out


# --- wired /admit route (dispatcher-level) ----------------------------------


def _client():
    from fastapi.testclient import TestClient

    return TestClient(build_app())


def test_route_allow_returns_receipt() -> None:
    res = _client().post(
        "/admit", json={"action": "runtime.file.write", "args": {"path": "a", "content": "b"}}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "allow"
    assert HEX64.match(body["receiptAuditHash"])


def test_route_deny_fails_closed() -> None:
    res = _client().post(
        "/admit",
        json={"action": "runtime.file.write", "args": {"path": "secrets/key", "content": "x"}},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "deny"
    assert "receiptAuditHash" not in body


def test_route_escalate_fails_closed() -> None:
    res = _client().post(
        "/admit",
        json={"action": "runtime.payment.send", "args": {"to": "x", "amount": 1}},
    )
    assert res.json()["decision"] == "escalate"
    assert "receiptAuditHash" not in res.json()


def test_route_malformed_args_fail_closed() -> None:
    res = _client().post("/admit", json={"action": "runtime.file.write", "args": "not-an-object"})
    body = res.json()
    assert body["decision"] == "deny"
    assert "receiptAuditHash" not in body


# --- BLOCKER regression: malformed/empty input must never become ALLOW -------


def test_empty_action_denied() -> None:
    out = admit_action("", {})
    assert out["decision"] == "deny"
    assert "receiptAuditHash" not in out


def test_whitespace_action_denied() -> None:
    out = admit_action("   ", {"path": "a"})
    assert out["decision"] == "deny"
    assert "receiptAuditHash" not in out


def test_none_action_denied() -> None:
    out = admit_action(None, {"path": "a"})
    assert out["decision"] == "deny"
    assert "receiptAuditHash" not in out


def test_non_string_action_denied() -> None:
    # str(123) used to coerce to a passable action; the guard must reject it.
    out = admit_action(123, {"path": "a"})
    assert out["decision"] == "deny"
    assert "receiptAuditHash" not in out


def test_non_dict_args_denied() -> None:
    # A pair-list is dict()-coercible; admit_action must still fail closed.
    out = admit_action("runtime.file.write", [("path", "ok"), ("content", "z")])
    assert out["decision"] == "deny"
    assert "receiptAuditHash" not in out


def test_route_missing_action_fails_closed() -> None:
    res = _client().post("/admit", json={"args": {"path": "a"}})
    body = res.json()
    assert body["decision"] == "deny"
    assert "receiptAuditHash" not in body


def test_route_null_action_fails_closed() -> None:
    res = _client().post("/admit", json={"action": None, "args": {}})
    body = res.json()
    assert body["decision"] == "deny"
    assert "receiptAuditHash" not in body


def test_route_empty_action_fails_closed() -> None:
    res = _client().post("/admit", json={"action": "", "args": {"path": "a"}})
    body = res.json()
    assert body["decision"] == "deny"
    assert "receiptAuditHash" not in body


def test_route_null_args_fails_closed() -> None:
    res = _client().post("/admit", json={"action": "runtime.file.write", "args": None})
    body = res.json()
    assert body["decision"] == "deny"
    assert "receiptAuditHash" not in body


def test_route_non_string_action_fails_closed() -> None:
    res = _client().post("/admit", json={"action": 123, "args": {"path": "a"}})
    body = res.json()
    assert body["decision"] == "deny"
    assert "receiptAuditHash" not in body


def test_served_app_object_is_wired() -> None:
    # Exercise the module-level `app = build_app()` that uvicorn actually serves,
    # not just a fresh build_app() (per ~/.claude/rules/review-handler-wiring.md).
    from fastapi.testclient import TestClient

    res = TestClient(app).post(
        "/admit", json={"action": "runtime.file.write", "args": {"path": "a", "content": "b"}}
    )
    assert res.status_code == 200
    assert res.json()["decision"] == "allow"
