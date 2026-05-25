"""Tests for the implemented CLI surface."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, ClassVar

import pytest

from agent_bus_analyzer.cli import build_parser, main


def test_parser_lists_implemented_subcommands() -> None:
    parser = build_parser()
    args = parser.parse_args(["serve", "--host", "0.0.0.0", "--port", "1234"])
    assert args.cmd == "serve"
    assert args.host == "0.0.0.0"
    assert args.port == 1234


def test_serve_command_wires_store_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_run(app: Any, **kwargs: Any) -> None:
        calls.append({"app": app, **kwargs})

    monkeypatch.setattr("uvicorn.run", fake_run)

    assert main(["serve", "--store-dir", str(tmp_path / "store")]) == 0

    assert len(calls) == 1
    app = calls[0]["app"]
    assert getattr(app.state, "store", None) is not None
    assert calls[0]["factory"] is False
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8042
    app.state.store.close()


def test_serve_command_reads_store_dir_from_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_run(app: Any, **kwargs: Any) -> None:
        calls.append({"app": app, **kwargs})

    monkeypatch.setattr("uvicorn.run", fake_run)
    monkeypatch.setenv("AGENT_BUS_ANALYZER_STORE_DIR", str(tmp_path / "store"))

    assert main(["serve"]) == 0

    app = calls[0]["app"]
    assert calls[0]["factory"] is False
    assert getattr(app.state, "store", None) is not None
    app.state.store.close()


def test_export_openapi_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["export-openapi", "--output", "-"]) == 0
    body = capsys.readouterr().out
    assert '"title": "agent-bus-analyzer"' in body
    assert '"/api/bus/traces"' in body


@pytest.mark.parametrize("name", ["verify", "dev-traffic"])
def test_unimplemented_subcommands_are_not_advertised(name: str) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([name])


def test_observer_subcommand_requires_args() -> None:
    with pytest.raises(SystemExit):
        main(["observer"])


def test_no_subcommand_errors() -> None:
    with pytest.raises(SystemExit):
        main([])


class _SmokeHandlerBase(BaseHTTPRequestHandler):
    seen_authorization: ClassVar[list[str | None]] = []


def _make_smoke_handler(
    *,
    signature_status: str = "signed",
    hash_chain_verified: bool = True,
) -> type[_SmokeHandlerBase]:
    class Handler(_SmokeHandlerBase):
        seen_authorization: ClassVar[list[str | None]] = []

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _write_json(self, payload: dict[str, Any], status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/api/bus/healthz":
                self._write_json({"status": "ok"})
                return

            if self.path == "/api/bus/receipts/rcpt-live-audit-0001":
                self.__class__.seen_authorization.append(self.headers.get("Authorization"))
                self._write_json(
                    {
                        "kind": "receipt-proof",
                        "hash_chain_verified": hash_chain_verified,
                        "signed_evidence_packet": json.dumps(
                            {
                                "export_signature": {
                                    "status": signature_status,
                                    "algorithm": "HMAC-SHA256-CANONICAL-JSON",
                                    "key_id": "bus-signer-v1",
                                }
                            }
                        ),
                    }
                )
                return

            self._write_json({"error": "not found"}, status=404)

    return Handler


@contextmanager
def _smoke_server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_postdeploy_smoke_verifies_health_receipt_and_signed_packet(
    capsys: pytest.CaptureFixture[str],
) -> None:
    handler = _make_smoke_handler()

    with _smoke_server(handler) as base_url:
        assert (
            main(
                [
                    "postdeploy-smoke",
                    "--base-url",
                    base_url,
                    "--receipt-id",
                    "rcpt-live-audit-0001",
                    "--token",
                    "reviewer-token",
                ]
            )
            == 0
        )

    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "ok"
    assert body["receipt_id"] == "rcpt-live-audit-0001"
    assert body["hash_chain_verified"] is True
    assert body["signature_status"] == "signed"
    assert body["signature_key_id"] == "bus-signer-v1"
    assert handler.seen_authorization == ["Bearer reviewer-token"]


def test_postdeploy_smoke_fails_closed_without_deployment_signature(
    capsys: pytest.CaptureFixture[str],
) -> None:
    handler = _make_smoke_handler(signature_status="unsigned-local-digest")

    with _smoke_server(handler) as base_url:
        assert (
            main(
                [
                    "postdeploy-smoke",
                    "--base-url",
                    base_url,
                    "--receipt-id",
                    "rcpt-live-audit-0001",
                    "--token",
                    "reviewer-token",
                ]
            )
            == 1
        )

    assert "signature status is not deployment signed" in capsys.readouterr().err


def test_postdeploy_smoke_can_explicitly_allow_unsigned_local_digest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    handler = _make_smoke_handler(signature_status="unsigned-local-digest")

    with _smoke_server(handler) as base_url:
        assert (
            main(
                [
                    "postdeploy-smoke",
                    "--base-url",
                    base_url,
                    "--receipt-id",
                    "rcpt-live-audit-0001",
                    "--token",
                    "reviewer-token",
                    "--allow-unsigned-local",
                ]
            )
            == 0
        )

    body = json.loads(capsys.readouterr().out)
    assert body["signature_status"] == "unsigned-local-digest"
