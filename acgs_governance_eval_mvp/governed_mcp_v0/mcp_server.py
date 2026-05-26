"""Public surface + FastMCP entrypoint for governed MCP v0.

After the step 1-10 refactor this module is intentionally thin:
- re-exports the public types and helpers from their new homes so
  ``from governed_mcp_v0.mcp_server import X`` keeps working for
  callers that pre-date the split (``eval_gate.py``, the package
  ``__init__``, external tests);
- holds ``build_fastmcp_server`` because the FastMCP binding is the
  ``mcp_server`` module's reason to exist (vs. just owning the class);
- runs the FastMCP stdio loop when invoked directly.

New code should import from the dedicated modules:
    governed_mcp_v0.models       (AdmissionDecision, ReplayResult, RuntimeTargets)
    governed_mcp_v0.errors       (GovernanceDenied, GovernanceStorageError)
    governed_mcp_v0.policy       (DeterministicPolicyEngine)
    governed_mcp_v0.server       (GovernedMCPServer)
    governed_mcp_v0.fixtures     (create_fixture_environment)
    governed_mcp_v0.verify       (verify_replay_bundle)
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import GovernanceDenied, GovernanceStorageError
from .fixtures import create_fixture_environment
from .models import AdmissionDecision, ReplayResult, RuntimeTargets
from .policy import DeterministicPolicyEngine
from .server import GovernedMCPServer
from .verify import verify_replay_bundle


def build_fastmcp_server(targets: RuntimeTargets | None = None) -> Any:
    try:  # pragma: no cover - optional MCP runtime integration.
        from mcp.server.fastmcp import FastMCP
    except Exception:  # pragma: no cover
        try:
            from fastmcp import FastMCP  # type: ignore
        except Exception:
            FastMCP = None  # type: ignore[assignment]
    if FastMCP is None:
        return None
    server = FastMCP("governed-mcp-v0")
    facade = GovernedMCPServer(
        targets or create_fixture_environment(Path.cwd() / ".governed_mcp_v0")
    )

    server.tool()(facade.read_file)
    server.tool()(facade.list_files)
    server.tool()(facade.query_sql_select)
    server.tool()(facade.github_read_issue)
    server.tool()(facade.write_file)
    server.tool()(facade.execute_sql)
    server.tool()(facade.send_email)
    server.tool()(facade.deploy_service)
    server.tool()(facade.mutate_github)
    server.tool()(facade.run_shell)
    return server


mcp = None

if __name__ == "__main__":  # pragma: no cover - manual MCP stdio launch path.
    mcp = build_fastmcp_server(create_fixture_environment(Path.cwd() / ".governed_mcp_v0"))
    if mcp is None:
        raise SystemExit("FastMCP runtime is not installed")
    mcp.run()


__all__ = [
    "AdmissionDecision",
    "DeterministicPolicyEngine",
    "GovernanceDenied",
    "GovernanceStorageError",
    "GovernedMCPServer",
    "ReplayResult",
    "RuntimeTargets",
    "build_fastmcp_server",
    "create_fixture_environment",
    "verify_replay_bundle",
]
