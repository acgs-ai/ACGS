"""Fail-closed tests for the copilot governance bridge.

Covers both the pure `admit_action()` and the wired `/admit` HTTP route (via
FastAPI TestClient), per ~/.claude/rules/review-handler-wiring.md: a unit test
of the function is not enough — the dispatcher path must be exercised too.

Invariant under test: only a clean ALLOW returns a `receiptAuditHash`; DENY,
ESCALATE, malformed input, and internal errors return none.
"""

from __future__ import annotations

import re

from examples.copilotkit_governed.governance_bridge import admit_action, build_app

HEX64 = re.compile(r"^[0-9a-f]{64}$")


# --- pure admit_action() ----------------------------------------------------


def test_allow_returns_receipt() -> None:
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


def test_allow_path_uses_audit_lock(monkeypatch) -> None:
    from examples.copilotkit_governed import governance_bridge

    class RecordingLock:
        def __init__(self) -> None:
            self.entries = 0

        def __enter__(self):
            self.entries += 1
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    lock = RecordingLock()
    monkeypatch.setattr(governance_bridge, "_AUDIT_LOCK", lock, raising=False)

    out = governance_bridge.admit_action(
        "runtime.file.write", {"path": "evidence/locked.json", "content": "ok"}
    )

    assert out["decision"] == "allow"
    assert lock.entries == 1


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
