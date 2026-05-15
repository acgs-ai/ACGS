"""Tests for the CLI surface (T069 — serve only; others stubbed)."""

from __future__ import annotations

import pytest

from agent_bus_analyzer.cli import build_parser, main


def test_parser_lists_planned_subcommands() -> None:
    parser = build_parser()
    args = parser.parse_args(["serve", "--host", "0.0.0.0", "--port", "1234"])
    assert args.cmd == "serve"
    assert args.host == "0.0.0.0"
    assert args.port == 1234


@pytest.mark.parametrize("name", ["verify", "dev-traffic"])
def test_planned_subcommand_exits_with_non_zero(name: str) -> None:
    # `observer` is implemented in US1 (T072); only verify/dev-traffic remain stubs.
    assert main([name]) == 2


def test_observer_subcommand_requires_args() -> None:
    with pytest.raises(SystemExit):
        main(["observer"])


def test_no_subcommand_errors() -> None:
    with pytest.raises(SystemExit):
        main([])
