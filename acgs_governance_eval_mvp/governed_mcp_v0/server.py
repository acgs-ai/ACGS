"""GovernedMCPServer — the deterministic, audit-chained MCP facade.

Wraps the bare side-effect operations (filesystem write, sql mutation,
email send, deploy restart, github mutate, shell exec) with:
  - admission: tool-to-action mapping + policy engine
  - audit chain: hash-linked JSONL of every decision, with a per-event
    on-disk receipt (fail-closed on persistence failure)
  - safe-read tools: read_file, list_files, query_sql_select,
    github_read_issue (no admission required)
"""

from __future__ import annotations

import shlex
import sqlite3
import subprocess
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from ._io import (
    _append_jsonl,
    _constitution_hash_or_missing,
    _evidence_lock,
    _last_audit_hash,
    _load_constitution,
    _next_receipt_index,
    _read_json,
    _resolve_fixture_path,
    _write_json,
    sha256_json,
)
from .constants import GUARDED_TOOLS, SAFE_TOOLS
from .errors import GovernanceDenied, GovernanceStorageError
from .models import AdmissionDecision, RuntimeTargets
from .policy import DeterministicPolicyEngine


class GovernedMCPServer:
    def __init__(
        self,
        targets: RuntimeTargets,
        *,
        policy_engine: DeterministicPolicyEngine | None = None,
    ) -> None:
        self.targets = targets
        self.policy_engine = policy_engine or DeterministicPolicyEngine()

    def admit(self, action_id: str, tool_name: str, args: dict[str, Any]) -> AdmissionDecision:
        if tool_name in SAFE_TOOLS:
            raise GovernanceDenied("safe tools do not require side-effect admission")
        if not isinstance(args, dict):
            recorded = self._record_decision(action_id, tool_name, {}, "deny", "malformed args", ["fail-closed"])
            raise GovernanceDenied(recorded.reason)
        expected_action = GUARDED_TOOLS.get(tool_name)
        if expected_action is None:
            recorded = self._record_decision(
                action_id,
                tool_name,
                args,
                "deny",
                f"unknown tool: {tool_name}",
                ["fail-closed"],
            )
            raise GovernanceDenied(recorded.reason)
        if expected_action != action_id:
            recorded = self._record_decision(
                action_id,
                tool_name,
                args,
                "deny",
                f"tool {tool_name} cannot perform action {action_id}",
                ["fail-closed"],
            )
            raise GovernanceDenied(recorded.reason)
        try:
            normalized_args_hash = sha256_json(args)
            _constitution, constitution_hash = _load_constitution(self.targets)
            if hasattr(self.policy_engine, "evaluate_policy"):
                decision, reason, policy_ids = self.policy_engine.evaluate_policy(action_id, args, self.targets)
            else:
                raw = self.policy_engine.evaluate(action_id, args, self.targets)
                decision, reason, policy_ids = raw.decision, raw.reason, raw.policy_ids
        except Exception as exc:
            normalized_args_hash = (
                sha256_json({"args": args}) if isinstance(args, dict) else sha256_json({"malformed": True})
            )
            constitution_hash = _constitution_hash_or_missing(self.targets)
            decision, reason, policy_ids = (
                "deny",
                f"fail closed: {exc.__class__.__name__}",
                ["fail-closed"],
            )
        recorded = self._record_decision(
            action_id,
            tool_name,
            args,
            decision,
            reason,
            policy_ids,
            normalized_args_hash=normalized_args_hash,
            constitution_hash=constitution_hash,
        )
        if not recorded.allowed:
            raise GovernanceDenied(recorded.reason)
        return recorded

    def _record_decision(
        self,
        action_id: str,
        tool_name: str,
        args: dict[str, Any],
        decision: str,
        reason: str,
        policy_ids: list[str],
        *,
        normalized_args_hash: str | None = None,
        constitution_hash: str | None = None,
    ) -> AdmissionDecision:
        """Persist one decision receipt and audit event, failing closed on IO errors.

        The receipt index, previous audit hash, receipt write, and audit append
        are serialized under one sidecar evidence lock. Receipt creation is
        exclusive; if a receipt path already exists, no audit event is appended
        and storage fails closed as a corruption signal. Audit append failures
        after receipt creation are raised to the caller and never swallowed.
        """
        normalized_args_hash = normalized_args_hash or sha256_json(args)
        constitution_hash = constitution_hash or _constitution_hash_or_missing(self.targets)
        try:
            with _evidence_lock(self.targets.audit_path):
                index = _next_receipt_index(self.targets.receipts_dir, self.targets.audit_path)
                receipt_path = self.targets.receipts_dir / f"{index:04d}-{action_id.replace('.', '-')}.json"
                receipt_core = {
                    "action_id": action_id,
                    "tool_name": tool_name,
                    "normalized_args_hash": normalized_args_hash,
                    "normalized_args": args,
                    "policy_ids": policy_ids,
                    "decision": decision,
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    "constitution_hash": constitution_hash,
                }
                previous_hash = _last_audit_hash(self.targets.audit_path)
                audit_core = {
                    "action_id": action_id,
                    "tool_name": tool_name,
                    "receipt_path": str(receipt_path.relative_to(self.targets.evidence_dir)),
                    "receipt_hash": sha256_json(receipt_core),
                    "decision": decision,
                    "previous_hash": previous_hash,
                }
                event_hash = sha256_json(audit_core)
                receipt = {**receipt_core, "event_hash": event_hash}
                audit_event = {**audit_core, "event_hash": event_hash}
                try:
                    _write_json(receipt_path, receipt, exclusive=True)
                except FileExistsError as exc:
                    raise GovernanceStorageError(
                        f"fail closed: receipt already exists at {receipt_path}; audit event was not written"
                    ) from exc
                _append_jsonl(self.targets.audit_path, audit_event)
        except GovernanceStorageError:
            raise
        except Exception as exc:  # pragma: no cover - covered through failure mode helpers if platform permits.
            raise GovernanceStorageError(f"fail closed while persisting governance evidence: {exc}") from exc
        return AdmissionDecision(receipt_path=receipt_path, **receipt)

    def read_file(self, path: str) -> str:
        target = _resolve_fixture_path(self.targets.fs_dir, path)
        return target.read_text(encoding="utf-8")

    def list_files(self) -> list[str]:
        base = self.targets.fs_dir.resolve()
        return sorted(str(path.resolve().relative_to(base)) for path in base.rglob("*") if path.is_file())

    def query_sql_select(self, sql: str) -> list[dict[str, Any]]:
        if sql.strip().split(None, 1)[0].upper() != "SELECT":
            raise ValueError("query_sql_select accepts SELECT only")
        with sqlite3.connect(self.targets.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(sql).fetchall()]

    def github_read_issue(self, repo: str, issue_number: int) -> dict[str, Any]:
        state = _read_json(self.targets.github_state_path)
        issues = state.get("issues", {})
        return dict(
            issues.get(
                f"{repo}#{issue_number}",
                {"repo": repo, "issue_number": issue_number, "title": "fixture"},
            )
        )

    def write_file(self, path: str, content: str) -> Path:
        args = {
            "path": path,
            "content_hash": sha256(content.encode("utf-8")).hexdigest(),
        }
        self.admit("filesystem.write_file", "write_file", args)
        target = _resolve_fixture_path(self.targets.fs_dir, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def execute_sql(self, sql: str) -> int:
        self.admit("database.execute_sql_mutation", "execute_sql", {"sql": sql})
        with sqlite3.connect(self.targets.sqlite_path) as connection:
            cursor = connection.execute(sql)
            connection.commit()
            return int(cursor.rowcount)

    def send_email(self, to: str, subject: str, body: str) -> None:
        self.admit(
            "email.send",
            "send_email",
            {
                "to": to,
                "subject": subject,
                "body_hash": sha256(body.encode()).hexdigest(),
            },
        )
        _append_jsonl(self.targets.outbox_path, {"to": to, "subject": subject, "body": body})

    def deploy_service(self, service: str, environment: str) -> None:
        self.admit(
            "deploy.restart_service",
            "deploy_service",
            {"service": service, "environment": environment},
        )
        _write_json(
            self.targets.deploy_state_path,
            {"service": service, "environment": environment, "status": "restarted"},
        )

    def mutate_github(self, repo: str, mutation: str, payload: dict[str, Any]) -> None:
        self.admit(
            "github.mutate_repo",
            "mutate_github",
            {"repo": repo, "mutation": mutation, "payload_hash": sha256_json(payload)},
        )
        state = _read_json(self.targets.github_state_path)
        state.setdefault("mutations", []).append({"repo": repo, "mutation": mutation, "payload": payload})
        _write_json(self.targets.github_state_path, state)

    def run_shell(self, command: str) -> str:
        self.admit("shell.execute_command", "run_shell", {"command": command})
        argv = shlex.split(command)
        completed = subprocess.run(argv, cwd=self.targets.fs_dir, check=True, capture_output=True, text=True)
        return completed.stdout.strip()
