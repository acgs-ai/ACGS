"""EVAL-ONLY: this package is the benchmark/eval-scenario harness, not the
production MCP surface. Its admission is hand-wired per tool method
(``GovernedMCPServer.admit``) with a static safe-tool list — adequate for
deterministic eval fixtures, but omission of an ``admit`` call would mean a
silent allow. The production binding is ``gove_zone.mcp`` (audit R5 / PR-5):
tools register on a ``gove_zone.Kernel`` and every MCP ``tools/call`` routes
through ``Kernel.dispatch``'s structural gating — an unregistered tool cannot
run and a registered one cannot skip policy + audit. New production MCP tools
go there, not here.
"""

from __future__ import annotations

from governed_mcp_v0.mcp_server import (
    AdmissionDecision,
    GovernanceDenied,
    GovernanceStorageError,
    GovernedMCPServer,
    ReplayResult,
    RuntimeTargets,
    create_fixture_environment,
    verify_replay_bundle,
)

__all__ = [
    "AdmissionDecision",
    "GovernanceDenied",
    "GovernanceStorageError",
    "GovernedMCPServer",
    "ReplayResult",
    "RuntimeTargets",
    "create_fixture_environment",
    "verify_replay_bundle",
]
