from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    tenant: str = "default"
    scopes: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Principal":
        return cls(
            id=str(data["id"]),
            role=str(data["role"]),
            tenant=str(data.get("tenant", "default")),
            scopes=list(data.get("scopes", [])),
            attributes=dict(data.get("attributes", {})),
        )


@dataclass(frozen=True)
class ActionRequest:
    action_type: str
    resource: str
    actor: Principal
    intent: str
    inputs_hash: str
    tenant: str = "default"
    event_id: str = field(default_factory=lambda: str(uuid4()))
    amount_cents: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionRequest":
        actor = data.get("actor")
        if isinstance(actor, Principal):
            principal = actor
        elif isinstance(actor, dict):
            principal = Principal.from_dict(actor)
        else:
            raise ValueError("ActionRequest.actor must be a Principal or dict")

        return cls(
            event_id=str(data.get("event_id") or uuid4()),
            tenant=str(data.get("tenant", principal.tenant)),
            intent=str(data.get("intent", "")),
            action_type=str(data["action_type"]),
            resource=str(data["resource"]),
            inputs_hash=str(data.get("inputs_hash", "")),
            actor=principal,
            amount_cents=data.get("amount_cents"),
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GateResult:
    gate: str
    allowed: bool
    reason_codes: list[str]
    reasons: list[str]
    rule_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DecisionRecord:
    event_id: str
    tenant: str
    allow: bool
    reasons: list[str]
    reason_codes: list[str]
    rule_ids: list[str]
    checks: list[GateResult]
    request: ActionRequest
    policy_version: str
    role_version: str
    timestamp: str = field(default_factory=utc_now_iso)
    previous_hash: str | None = None
    event_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["checks"] = [check.to_dict() if isinstance(check, GateResult) else check for check in self.checks]
        data["request"] = self.request.to_dict() if isinstance(self.request, ActionRequest) else self.request
        return data

    def canonical_payload_for_hash(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("event_hash", None)
        return payload
