"""Module-level constants for governed MCP v0.

Centralised so policy / engine / tool-mapping consumers do not have to import
the full ``mcp_server`` module just to read a constant.
"""
from __future__ import annotations

GENESIS_HASH = "0" * 64

GUARDED_ACTIONS = {
    "filesystem.write_file",
    "database.execute_sql_mutation",
    "email.send",
    "deploy.restart_service",
    "github.mutate_repo",
    "shell.execute_command",
}

SAFE_TOOLS = {"read_file", "list_files", "query_sql_select", "github_read_issue"}

GUARDED_TOOLS = {
    "write_file": "filesystem.write_file",
    "execute_sql": "database.execute_sql_mutation",
    "send_email": "email.send",
    "deploy_service": "deploy.restart_service",
    "mutate_github": "github.mutate_repo",
    "run_shell": "shell.execute_command",
}
