"""gove-zone audit-tail compatibility tests.

These tests lock the deployment bridge between the runtime kernel's canonical
audit JSONL records and the bus analyzer's receipt-proof API. The analyzer must
not require fixture-only ``tool_name``/``args`` shapes once it tails a real
``gove-zone`` audit file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_bus_analyzer.api import create_app
from agent_bus_analyzer.auth import set_validator
from agent_bus_analyzer.cli import main
from agent_bus_analyzer.observer import project_audit_record, project_bus_event
from agent_bus_analyzer.store import TraceStore


def _canonical_gove_zone_audit_record() -> dict[str, object]:
    return {
        "decision": "deny",
        "tool": "runtime.Write",
        "argument_hash": "a" * 64,
        "policy_version": "hook-observer/v0",
        "event_id": "rcpt-live-audit-0001",
        "matched_rules": ["protected-path:console"],
        "reason": "path matched protected boundary",
        "timestamp_iso": "2026-05-25T13:00:00+00:00",
        "transformed_args": None,
        "goal": "Edit console deployment policy",
        "actor": "codex:leader",
        "path": ["acgi-ai", "infra", "cloudrun", "service.yaml"],
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "span_id": "53995c3f42cd8ad8",
        "state_hash": "b" * 64,
        "decision_request_hash": "c" * 64,
        "previous_hash": "0" * 64,
        "event_hash": "d" * 64,
    }


def test_project_canonical_gove_zone_audit_record_preserves_live_receipt_fields() -> None:
    projected = project_audit_record(
        _canonical_gove_zone_audit_record(),
        "608508a9bd224290",
    )

    assert projected["event_id"] == "rcpt-live-audit-0001"
    assert projected["correlation_id"] == "rcpt-live-audit-0001"
    assert projected["recorded_at"] == "2026-05-25T13:00:00+00:00"
    assert projected["source_agent"] == "codex:leader"
    assert projected["target_handler_declared"] == "runtime.Write"
    assert projected["target_handler_resolved"] == "runtime.Write"
    assert projected["payload_ref"] == f"sha256:{'a' * 64}"
    assert projected["decision"] == "deny"
    assert projected["flagged_rule"] == "protected-path:console"
    assert projected["audit_receipt_hash"] == "d" * 64
    assert projected["phoenix_trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert projected["phoenix_span_id"] == "53995c3f42cd8ad8"
    assert projected["phoenix_parent_span_id"] == "00f067aa0ba902b7"
    assert projected["status"] == "policy-violation"


def test_project_bus_event_preserves_nested_phoenix_trace_context() -> None:
    projected = project_bus_event(
        {
            "message_id": "msg-traced-0001",
            "conversation_id": "conv-traced-0001",
            "from_agent": "codex:leader",
            "to_agent": "runtime.Write",
            "payload": {
                "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
                "span_id": "cccccccccccccccc",
            },
        },
        "608508a9bd224290",
    )

    assert projected["phoenix_trace_id"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert projected["phoenix_span_id"] == "cccccccccccccccc"
    assert projected["phoenix_parent_span_id"] == "bbbbbbbbbbbbbbbb"


def test_import_audit_cli_backfills_receipt_proof_from_gove_zone_jsonl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ACGS_EVIDENCE_SIGNING_KEY_ID", raising=False)
    monkeypatch.delenv("ACGS_EVIDENCE_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("ACGS_EVIDENCE_SIGNING_REQUIRED", raising=False)
    audit_file = tmp_path / "gove-zone-audit.jsonl"
    audit_file.write_text(
        json.dumps(
            _canonical_gove_zone_audit_record(),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    store_dir = tmp_path / "bus-store"

    assert (
        main(
            [
                "import-audit",
                "--audit-file",
                str(audit_file),
                "--store-dir",
                str(store_dir),
                "--constitutional-hash",
                "608508a9bd224290",
            ]
        )
        == 0
    )

    set_validator(lambda _t: frozenset({"governance-reviewer"}))
    client = TestClient(create_app(store=TraceStore(store_dir)))
    response = client.get(
        "/api/bus/receipts/rcpt-live-audit-0001",
        headers={"Authorization": "Bearer reviewer"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["kind"] == "receipt-proof"
    assert body["receipt_hash"] == "d" * 64
    assert body["policy_path"] == ["runtime.Write", "protected-path:console"]
    assert body["hash_chain_verified"] is True
    packet = json.loads(body["signed_evidence_packet"])
    assert packet["receipt_hash"] == "d" * 64
    assert packet["source_audit_hash"] == "d" * 64
    assert packet["export_signature"]["algorithm"] == "SHA256-CANONICAL-JSON"


def test_receipt_proof_marks_deployment_managed_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_KEY_ID", "bus-signer-v1")
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_SECRET", "deploy-secret-material")
    store = TraceStore(tmp_path / "store")
    store.append(project_audit_record(_canonical_gove_zone_audit_record(), "608508a9bd224290"))
    set_validator(lambda _t: frozenset({"governance-reviewer"}))
    client = TestClient(create_app(store=store))

    response = client.get(
        "/api/bus/receipts/rcpt-live-audit-0001",
        headers={"Authorization": "Bearer reviewer"},
    )

    assert response.status_code == 200, response.text
    packet = json.loads(response.json()["signed_evidence_packet"])
    assert packet["export_signature"]["status"] == "signed"
    assert packet["export_signature"]["algorithm"] == "HMAC-SHA256-CANONICAL-JSON"
    assert packet["export_signature"]["key_id"] == "bus-signer-v1"
