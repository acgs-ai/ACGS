"""Deterministic policy engine for governed MCP v0.

Pure decision logic — no IO, no side effects.  Returns a ``(decision,
reason, policy_ids)`` triple that the ``GovernedMCPServer`` wraps into an
``AdmissionDecision`` with the audit chain attached.
"""

from __future__ import annotations

from typing import Any

from ._io import _resolve_fixture_path
from .constants import GUARDED_ACTIONS
from .models import AdmissionDecision, RuntimeTargets


class DeterministicPolicyEngine:
    def evaluate(self, action_id: str, args: dict[str, Any], targets: RuntimeTargets) -> AdmissionDecision:
        raise NotImplementedError("use evaluate_policy for normalized policy output")

    def evaluate_policy(
        self, action_id: str, args: dict[str, Any], targets: RuntimeTargets
    ) -> tuple[str, str, list[str]]:
        policy_ids = ["governed-mcp-v0-side-effect-policy"]
        if action_id not in GUARDED_ACTIONS:
            return "deny", f"unknown guarded action: {action_id}", policy_ids

        if action_id == "filesystem.write_file":
            raw_path = args.get("path")
            if not isinstance(raw_path, str):
                return "deny", "filesystem write path must be a string", policy_ids
            try:
                _resolve_fixture_path(targets.fs_dir, raw_path)
            except ValueError:
                return (
                    "deny",
                    "filesystem writes are limited to fixtures/fs",
                    policy_ids,
                )
            return "allow", "sandbox file write allowed", policy_ids

        if action_id == "database.execute_sql_mutation":
            sql = args.get("sql")
            if not isinstance(sql, str):
                return "deny", "sql mutation requires a string statement", policy_ids
            first = sql.strip().split(None, 1)[0].upper() if sql.strip() else ""
            if first in {"DELETE", "DROP", "ALTER", "TRUNCATE", "CREATE"}:
                return (
                    "deny",
                    f"sql mutation verb {first or '<empty>'} is denied",
                    policy_ids,
                )
            if first not in {"INSERT", "UPDATE"}:
                return (
                    "deny",
                    "only INSERT and UPDATE fixture mutations are allowed",
                    policy_ids,
                )
            return "allow", "fixture sql mutation allowed", policy_ids

        if action_id == "email.send":
            recipient = args.get("to")
            if not isinstance(recipient, str):
                return "deny", "email recipient must be a string", policy_ids
            if not recipient.endswith("@example.test"):
                return (
                    "deny",
                    "email sends are limited to example.test fixture recipients",
                    policy_ids,
                )
            return "allow", "fixture email send allowed", policy_ids

        if action_id == "deploy.restart_service":
            service = args.get("service")
            environment = args.get("environment")
            if service != "sandbox-api" or environment != "sandbox":
                return (
                    "deny",
                    "deploy restarts are limited to sandbox-api in sandbox",
                    policy_ids,
                )
            return "allow", "sandbox deploy restart allowed", policy_ids

        if action_id == "github.mutate_repo":
            repo = args.get("repo")
            mutation = args.get("mutation")
            if repo != "sandbox/repo" or mutation not in {
                "label_issue",
                "comment_issue",
            }:
                return (
                    "deny",
                    "github mutations are limited to sandbox/repo issue metadata",
                    policy_ids,
                )
            return "allow", "sandbox github mutation allowed", policy_ids

        command = args.get("command")
        if command not in {"pwd", "echo sandbox"}:
            return "deny", "shell command is not in the fixture allowlist", policy_ids
        return "allow", "allowlisted fixture shell command", policy_ids
