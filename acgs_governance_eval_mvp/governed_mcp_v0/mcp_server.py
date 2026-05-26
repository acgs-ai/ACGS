from __future__ import annotations

import json
import shlex
import sqlite3
import subprocess
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from ._io import (
    _append_jsonl,
    _contains,
    _last_audit_hash,
    _load_constitution,
    _read_json,
    _resolve_fixture_path,
    _write_json,
    sha256_json,
)
from .constants import GENESIS_HASH, GUARDED_TOOLS, SAFE_TOOLS
from .errors import GovernanceDenied, GovernanceStorageError
from .models import AdmissionDecision, ReplayResult, RuntimeTargets
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
        normalized_args_hash = normalized_args_hash or sha256_json(args)
        constitution_hash = constitution_hash or _constitution_hash_or_missing(self.targets)
        index = _next_receipt_index(self.targets.audit_path)
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
            _write_json(receipt_path, receipt)
            _append_jsonl(self.targets.audit_path, audit_event)
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


def _constitution_hash_or_missing(targets: RuntimeTargets) -> str:
    try:
        _constitution, constitution_hash = _load_constitution(targets)
    except Exception:
        return "missing"
    return constitution_hash


def _next_receipt_index(audit_path: Path) -> int:
    if not audit_path.exists():
        return 1
    with audit_path.open("r", encoding="utf-8") as handle:
        return 1 + sum(1 for line in handle if line.strip())


def create_fixture_environment(root: Path) -> RuntimeTargets:
    targets = RuntimeTargets(root=root)
    targets.fs_dir.mkdir(parents=True, exist_ok=True)
    targets.receipts_dir.mkdir(parents=True, exist_ok=True)
    (targets.fs_dir / "readme.txt").write_text("sandbox fixture\n", encoding="utf-8")
    _write_json(
        targets.constitution_path,
        {
            "id": "governed-mcp-v0",
            "policies": [
                "guard-side-effects",
                "fixture-only-targets",
                "deterministic-replay",
            ],
        },
    )
    with sqlite3.connect(targets.sqlite_path) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT OR IGNORE INTO records (id, value) VALUES (1, 'fixture')")
        connection.commit()
    _write_json(
        targets.deploy_state_path,
        {"service": "sandbox-api", "environment": "sandbox", "status": "ready"},
    )
    _write_json(
        targets.github_state_path,
        {"issues": {"sandbox/repo#1": {"title": "fixture issue"}}, "mutations": []},
    )
    return targets


def _iter_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _verify_allowed_effect(
    targets: RuntimeTargets,
    receipt: dict[str, Any],
    line_number: int,
    failures: list[str],
) -> None:
    if receipt.get("decision") != "allow":
        return
    action_id = receipt.get("action_id")
    args = receipt.get("normalized_args")
    if not isinstance(args, dict):
        failures.append(f"audit line {line_number}: missing_normalized_args")
        return

    if action_id == "filesystem.write_file":
        raw_path = args.get("path")
        content_hash = args.get("content_hash")
        if not isinstance(raw_path, str) or not isinstance(content_hash, str):
            failures.append(f"audit line {line_number}: filesystem_effect_args_invalid")
            return
        try:
            target = _resolve_fixture_path(targets.fs_dir, raw_path)
        except ValueError:
            failures.append(f"audit line {line_number}: filesystem_effect_path_escape")
            return
        if not target.exists():
            failures.append(f"audit line {line_number}: filesystem_effect_missing")
        elif sha256(target.read_bytes()).hexdigest() != content_hash:
            failures.append(f"audit line {line_number}: filesystem_effect_hash_mismatch")
        return

    if action_id == "email.send":
        try:
            outbox_rows = _iter_jsonl(targets.outbox_path)
        except Exception:
            failures.append(f"audit line {line_number}: email_effect_malformed")
            return
        expected_to = args.get("to")
        expected_subject = args.get("subject")
        expected_body_hash = args.get("body_hash")
        matched = any(
            row.get("to") == expected_to
            and row.get("subject") == expected_subject
            and isinstance(row.get("body"), str)
            and sha256(str(row.get("body")).encode("utf-8")).hexdigest() == expected_body_hash
            for row in outbox_rows
        )
        if not matched:
            failures.append(f"audit line {line_number}: email_effect_missing_or_mismatched")
        return

    if action_id == "deploy.restart_service":
        try:
            state = _read_json(targets.deploy_state_path) if targets.deploy_state_path.exists() else {}
        except Exception:
            failures.append(f"audit line {line_number}: deploy_effect_malformed")
            return
        if state != {
            "service": args.get("service"),
            "environment": args.get("environment"),
            "status": "restarted",
        }:
            failures.append(f"audit line {line_number}: deploy_effect_mismatch")
        return

    if action_id == "github.mutate_repo":
        try:
            state = _read_json(targets.github_state_path) if targets.github_state_path.exists() else {}
        except Exception:
            failures.append(f"audit line {line_number}: github_effect_malformed")
            return
        mutations = state.get("mutations", [])
        matched = any(
            isinstance(row, dict)
            and row.get("repo") == args.get("repo")
            and row.get("mutation") == args.get("mutation")
            and sha256_json(row.get("payload")) == args.get("payload_hash")
            for row in mutations
        )
        if not matched:
            failures.append(f"audit line {line_number}: github_effect_missing_or_mismatched")


def verify_replay_bundle(targets: RuntimeTargets) -> ReplayResult:
    failures: list[str] = []
    previous_hash = GENESIS_HASH
    checked = 0
    if not targets.audit_path.exists():
        return ReplayResult(valid=False, checked_events=0, failures=["missing audit.jsonl"])
    with targets.audit_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            checked += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                failures.append(f"audit line {line_number}: malformed json")
                continue
            if event.get("previous_hash") != previous_hash:
                failures.append(f"audit line {line_number}: previous_hash_mismatch")
            claimed_hash = event.get("event_hash")
            event_core = dict(event)
            event_core.pop("event_hash", None)
            recomputed_hash = sha256_json(event_core)
            if claimed_hash != recomputed_hash:
                failures.append(f"audit line {line_number}: event_hash_mismatch")
            receipt_ref = event.get("receipt_path")
            if not isinstance(receipt_ref, str):
                failures.append(f"audit line {line_number}: missing receipt_path")
                previous_hash = str(claimed_hash)
                continue
            receipt_path = (targets.evidence_dir / receipt_ref).resolve()
            if not _contains(targets.evidence_dir, receipt_path):
                failures.append(f"audit line {line_number}: receipt_path_escape")
            elif not receipt_path.exists():
                failures.append(f"audit line {line_number}: missing_receipt")
            else:
                receipt = _read_json(receipt_path)
                required = {
                    "action_id",
                    "tool_name",
                    "normalized_args_hash",
                    "normalized_args",
                    "policy_ids",
                    "decision",
                    "reason",
                    "timestamp",
                    "constitution_hash",
                    "event_hash",
                }
                missing = sorted(required.difference(receipt))
                if missing:
                    failures.append(f"audit line {line_number}: receipt_missing_fields={','.join(missing)}")
                receipt_core = dict(receipt)
                receipt_event_hash = receipt_core.pop("event_hash", None)
                if sha256_json(receipt_core) != event.get("receipt_hash"):
                    failures.append(f"audit line {line_number}: receipt_hash_mismatch")
                if receipt_event_hash != claimed_hash:
                    failures.append(f"audit line {line_number}: receipt_event_hash_mismatch")
                _verify_allowed_effect(targets, receipt, line_number, failures)
            previous_hash = str(claimed_hash)
    return ReplayResult(valid=not failures and checked > 0, checked_events=checked, failures=failures)


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
    facade = GovernedMCPServer(targets or create_fixture_environment(Path.cwd() / ".governed_mcp_v0"))

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
    "GovernanceDenied",
    "GovernanceStorageError",
    "GovernedMCPServer",
    "ReplayResult",
    "RuntimeTargets",
    "create_fixture_environment",
    "verify_replay_bundle",
]
