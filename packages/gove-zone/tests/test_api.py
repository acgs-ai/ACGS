"""Dependency-free console API adapter tests."""

from __future__ import annotations

from gove_zone.api import handle_api_request


def test_actions_endpoint_returns_live_governed_action_contract() -> None:
    status, payload = handle_api_request("GET", "/api/v1/actions")

    assert status == 200
    assert isinstance(payload, list)
    assert len(payload) >= 3
    outcomes = {row["outcome"] for row in payload}
    assert {"denied", "transformed", "escalated"}.issubset(outcomes)
    for row in payload:
        assert row["agent"]
        assert row["action"]
        assert row["plainReason"]
        assert row["receiptHash"]
        assert row["traceId"]
        assert row["replayCommand"].startswith("gove-zone replay")
        assert row["auditEventId"]
        assert row["checks"]


def test_action_test_endpoint_dry_runs_without_execution() -> None:
    status, payload = handle_api_request(
        "POST",
        "/api/v1/actions/test",
        {"actionId": "matter.fetch", "payload": '{"matter_id":"Matter-9821"}'},
    )

    assert status == 200
    assert isinstance(payload, dict)
    assert payload["outcome"] == "denied"
    assert payload["receiptId"] == payload["traceId"]
    assert "No production tool was executed" in payload["body"]


def test_console_shell_support_endpoints_avoid_background_404s() -> None:
    for path in (
        "/api/v1/console-summary",
        "/api/v1/agents",
        "/api/v1/overview",
        "/api/v1/policies",
        "/api/v1/compile/draft",
        "/api/v1/deliberations",
        "/api/v1/incidents",
        "/api/v1/tenants",
        "/api/v1/audit",
        "/api/v1/settings",
        "/api/v1/account",
    ):
        status, payload = handle_api_request("GET", path)
        assert status == 200, path
        assert payload is not None
