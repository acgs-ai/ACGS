"""CLI tests for audit-only process evidence commands."""

from __future__ import annotations

import json
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agent_bus_analyzer.cli import build_parser, main
from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.collectors.api_collector import APIEventCollector
from agent_bus_analyzer.process_mining.schemas.process_event import ProcessEvent
from agent_bus_analyzer.process_mining.storage.event_store import EventStore


def test_package_declares_and_loads_production_verifier_crypto_dependency() -> None:
    manifest_path = Path(__file__).parents[1] / "pyproject.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    assert "gove-zone[crypto]>=0.1.0a1" in manifest["project"]["dependencies"]

    gove_zone = pytest.importorskip("gove_zone")
    Ed25519Signer = gove_zone.Ed25519Signer
    ReceiptVerifier = gove_zone.ReceiptVerifier

    signer = Ed25519Signer.generate(key_id="process-intelligence-test")
    verifier = ReceiptVerifier(
        expected_tenant_id="tenant-a",
        expected_execution_boundary="executor-gate-1",
        expected_actor="agent-1",
        verifier=signer,
        require_signature=True,
        require_expiry=True,
    )
    assert verifier.require_signature is True
    assert verifier.require_expiry is True


def _event(
    event_id: str,
    *,
    kind: str = "agent",
    side_effect: bool = False,
    sequence: int = 0,
    activity: str | None = None,
) -> ProcessEvent:
    record: dict[str, object] = {
        "event_id": event_id,
        "tenant_id": "tenant-a",
        "case_id": "case-1",
        "process_id": "workflow-v1",
        "process_name": "Observed Workflow",
        "sequence": sequence,
        "kind": kind,
        "activity": activity or ("payment.execute" if side_effect else "analyze"),
        "occurred_at": (
            datetime(2026, 7, 9, 15, tzinfo=UTC) + timedelta(seconds=sequence)
        ).isoformat(),
        "actor_kind": "agent",
        "agent_id": "agent-1",
        "side_effect": side_effect,
        "previous_hash": "0" * 64,
    }
    if side_effect:
        record["tool_name"] = activity or "payment.execute"
    record["event_hash"] = sha256_canonical(record)
    return APIEventCollector().collect(record, tenant_id="tenant-a")


def _write_events(path: Path, events: tuple[ProcessEvent, ...]) -> None:
    path.write_text(
        "".join(event.model_dump_json() + "\n" for event in events),
        encoding="utf-8",
    )


def _audit_record(event_id: str, previous_hash: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "tenant_id": "tenant-a",
        "decision": "allow",
        "tool": "runtime.Write",
        "argument_hash": "a" * 64,
        "actor_authority_id": "authority-1",
        "policy_id": "policy-1",
        "policy_version": "policy-v1",
        "policy_bundle_id": "policy-bundle-v1",
        "policy_hash": "b" * 64,
        "execution_boundary": "runtime-production",
        "event_id": event_id,
        "timestamp_iso": "2026-07-09T15:00:00+00:00",
        "actor": "agent-1",
        "decision_request_hash": "d" * 64,
        "evidence_bundle_ids": ["bundle-1"],
        "previous_hash": previous_hash,
    }
    payload["event_hash"] = sha256_canonical(payload)
    return payload


def test_parser_preserves_existing_commands_and_registers_process_group() -> None:
    parser = build_parser()
    assert parser.parse_args(["verify", "case-1", "--store-dir", "/tmp/store"]).cmd == "verify"
    dev_args = parser.parse_args(["dev-traffic", "--store-dir", "/tmp/s", "--target", "x"])
    assert dev_args.cmd == "dev-traffic"

    common = ["--input", "events.jsonl", "--tenant-id", "tenant-a"]
    invocations = {
        "ingest": [*common, "--event-store-dir", "/tmp/events"],
        "discover": common,
        "conform": common,
        "verify": ["--tenant-id", "tenant-a", "--event-store-dir", "/tmp/events"],
    }
    for command, options in invocations.items():
        process = parser.parse_args(["process", command, *options])
        assert process.process_cmd == command

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["process", "ingest", *common, "--event-store-dir", "/tmp/events", "--source", "api"]
        )


def test_discover_is_deterministic_and_tenant_mismatch_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "events.jsonl"
    _write_events(source, (_event("event-1"), _event("event-2", sequence=1)))
    command = [
        "process",
        "discover",
        "--input",
        str(source),
        "--tenant-id",
        "tenant-a",
    ]

    assert main(command) == 0
    first = capsys.readouterr().out
    assert main(command) == 0
    second = capsys.readouterr().out
    assert first == second
    assert json.loads(first)["summary"]["process_id"] == "workflow-v1"

    mismatch = [*command[:-1], "tenant-b"]
    assert main(mismatch) == 1
    assert "fail-closed" in capsys.readouterr().err


def test_conform_returns_nonclean_for_deny_and_investigate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "governance-events.jsonl"
    _write_events(
        source,
        (
            _event("executed", kind="tool_result", side_effect=True),
            _event("attempted", kind="tool_call", side_effect=True, sequence=1),
        ),
    )

    assert (
        main(
            [
                "process",
                "conform",
                "--input",
                str(source),
                "--tenant-id",
                "tenant-a",
            ]
        )
        == 2
    )
    body = json.loads(capsys.readouterr().out)
    assert body["deny_count"] == 1
    assert body["investigate_count"] == 1
    assert body["executable_authority"] is False


def test_ingest_audit_chain_and_verify_requires_records(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = _audit_record("raw-effect", "0" * 64)
    second = _audit_record("raw-effect-2", str(first["event_hash"]))
    source = tmp_path / "raw.jsonl"
    source.write_text(
        json.dumps(first) + "\n" + json.dumps(second) + "\n",
        encoding="utf-8",
    )
    store_dir = tmp_path / "event-store"
    base = [
        "process",
        "ingest",
        "--input",
        str(source),
        "--tenant-id",
        "tenant-a",
        "--event-store-dir",
        str(store_dir),
    ]

    assert main(base) == 0
    assert json.loads(capsys.readouterr().out)["appended"] == 2
    assert EventStore(store_dir).verify_chain("tenant-a").checked == 2
    assert (
        main(
            [
                "process",
                "verify",
                "--tenant-id",
                "tenant-a",
                "--event-store-dir",
                str(store_dir),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["verification"]["checked"] == 2

    tampered = tmp_path / "tampered.jsonl"
    broken = dict(first)
    broken["tool"] = "runtime.Delete"
    tampered.write_text(json.dumps(broken) + "\n", encoding="utf-8")
    assert (
        main(
            [
                "process",
                "ingest",
                "--input",
                str(tampered),
                "--tenant-id",
                "tenant-a",
                "--event-store-dir",
                str(tmp_path / "other-store"),
            ]
        )
        == 1
    )
    assert "fail-closed" in capsys.readouterr().err

    empty = tmp_path / "empty-store"
    assert (
        main(
            [
                "process",
                "verify",
                "--tenant-id",
                "tenant-a",
                "--event-store-dir",
                str(empty),
            ]
        )
        == 1
    )


def test_invalid_input_and_malformed_jsonl_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text("{not-json}\n", encoding="utf-8")
    assert (
        main(
            [
                "process",
                "discover",
                "--input",
                str(malformed),
                "--tenant-id",
                "tenant-a",
            ]
        )
        == 1
    )
    assert "malformed JSONL" in capsys.readouterr().err


def test_process_jsonl_boundary_rejects_symlinks_and_enforces_all_limits(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "events.jsonl"
    _write_events(source, (_event("event-1"), _event("event-2", sequence=1)))
    base = ["process", "discover", "--tenant-id", "tenant-a"]

    symlink = tmp_path / "events-link.jsonl"
    symlink.symlink_to(source)
    assert main([*base, "--input", str(symlink)]) == 1
    assert "non-symlink regular file" in capsys.readouterr().err

    assert (
        main(
            [
                *base,
                "--input",
                str(source),
                "--max-input-line-bytes",
                "64",
            ]
        )
        == 1
    )
    assert "input line exceeds 64 bytes" in capsys.readouterr().err

    assert (
        main(
            [
                *base,
                "--input",
                str(source),
                "--max-input-records",
                "1",
            ]
        )
        == 1
    )
    assert "input exceeds 1 records" in capsys.readouterr().err

    assert (
        main(
            [
                *base,
                "--input",
                str(source),
                "--max-input-total-bytes",
                str(len(source.read_bytes()) - 1),
            ]
        )
        == 1
    )
    assert "total bytes" in capsys.readouterr().err
