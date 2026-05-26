"""Domain types for governed MCP v0.

These dataclasses are pure data containers — no IO, no behaviour beyond
trivial derived path properties.  The PolicyEngine Protocol lives in the
same module because its method signature forward-refers to
RuntimeTargets and AdmissionDecision; co-locating them avoids a circular
import.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class PolicyEngine(Protocol):
    def evaluate(
        self,
        action_id: str,
        args: dict[str, Any],
        targets: "RuntimeTargets",
    ) -> "AdmissionDecision": ...


@dataclass(frozen=True)
class AdmissionDecision:
    action_id: str
    tool_name: str
    normalized_args_hash: str
    normalized_args: dict[str, Any]
    policy_ids: list[str]
    decision: str
    reason: str
    timestamp: str
    constitution_hash: str
    event_hash: str
    receipt_path: Path

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


@dataclass(frozen=True)
class ReplayResult:
    valid: bool
    checked_events: int
    failures: list[str]


@dataclass(frozen=True)
class RuntimeTargets:
    root: Path

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def fixtures_dir(self) -> Path:
        return self.evidence_dir / "fixtures"

    @property
    def fs_dir(self) -> Path:
        return self.fixtures_dir / "fs"

    @property
    def sqlite_path(self) -> Path:
        return self.fixtures_dir / "database.sqlite3"

    @property
    def outbox_path(self) -> Path:
        return self.evidence_dir / "outbox.jsonl"

    @property
    def deploy_state_path(self) -> Path:
        return self.evidence_dir / "deploy_state.json"

    @property
    def github_state_path(self) -> Path:
        return self.evidence_dir / "github_state.json"

    @property
    def audit_path(self) -> Path:
        return self.evidence_dir / "audit.jsonl"

    @property
    def receipts_dir(self) -> Path:
        return self.evidence_dir / "receipts"

    @property
    def constitution_path(self) -> Path:
        return self.evidence_dir / "constitution.json"
