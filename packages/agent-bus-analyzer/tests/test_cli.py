"""Tests for the implemented CLI surface."""

from __future__ import annotations

import pytest

from agent_bus_analyzer.cli import build_parser, main


def test_parser_lists_implemented_subcommands() -> None:
    parser = build_parser()
    args = parser.parse_args(["serve", "--host", "0.0.0.0", "--port", "1234"])
    assert args.cmd == "serve"
    assert args.host == "0.0.0.0"
    assert args.port == 1234


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
