"""Authorization-propagation benchmark adapter.

This is a deliberately small model of the arXiv 2605.05440 propagation shape:
each hop carries a signed delegation lineage, and every receiving agent verifies
principal, tenant, role, path, capability, and parent linkage before the tool
side effect can run.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import time
from collections.abc import Mapping
from typing import Any

from gove_zone import Decision, DecisionRecord, Policy, canonical_json, new_event_id, sha256_json
from gove_zone.tool import ToolCall

SECRET = b"gove-zone-week2-propagation-secret"

ROLES: dict[str, str] = {
    "orchestrator": "workflow-owner",
    "planner": "planning-delegate",
    "executor": "execution-delegate",
}


def _sign(payload: Mapping[str, Any]) -> str:
    return hmac.new(SECRET, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def _unsigned(grant: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(grant)
    payload.pop("signature", None)
    return payload


def _grant_hash(grant: Mapping[str, Any]) -> str:
    return sha256_json(_unsigned(grant))


def _verify_signature(grant: Mapping[str, Any]) -> bool:
    expected = _sign(_unsigned(grant))
    return hmac.compare_digest(str(grant.get("signature", "")), expected)


@dataclasses.dataclass(frozen=True)
class PropagationGraph:
    """Signed lineage builder for a three-agent benchmark chain."""

    tenant: str = "tenant-alpha"
    path_prefix: str = "/workspace/"
    capability: str = "filesystem:read"

    def root_grant(self, path: str) -> dict[str, Any]:
        return self._grant(
            principal="orchestrator",
            issued_by="root",
            role=ROLES["orchestrator"],
            path=path,
            parent_hash="genesis",
            depth=0,
        )

    def delegate(self, *, parent: Mapping[str, Any], principal: str, path: str) -> dict[str, Any]:
        return self._grant(
            principal=principal,
            issued_by=str(parent["principal"]),
            role=ROLES[principal],
            path=path,
            parent_hash=_grant_hash(parent),
            depth=int(parent["depth"]) + 1,
        )

    def verify_lineage(self, lineage: tuple[Mapping[str, Any], ...], *, expected_agent: str) -> str:
        if not lineage:
            return "empty lineage"
        previous: Mapping[str, Any] | None = None
        for depth, grant in enumerate(lineage):
            if not _verify_signature(grant):
                return f"bad signature at depth {depth}"
            if grant.get("tenant") != self.tenant:
                return f"tenant mismatch at depth {depth}"
            if grant.get("capability") != self.capability:
                return f"capability mismatch at depth {depth}"
            if not str(grant.get("path", "")).startswith(self.path_prefix):
                return f"path outside caveat at depth {depth}"
            if grant.get("role") != ROLES.get(str(grant.get("principal"))):
                return f"role mismatch at depth {depth}"
            expected_parent = "genesis" if previous is None else _grant_hash(previous)
            if grant.get("parent_hash") != expected_parent:
                return f"parent hash mismatch at depth {depth}"
            previous = grant
        if lineage[-1].get("principal") != expected_agent:
            return f"principal mismatch: expected {expected_agent}"
        return ""

    def _grant(
        self,
        *,
        principal: str,
        issued_by: str,
        role: str,
        path: str,
        parent_hash: str,
        depth: int,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "scheme": "propagation-graph",
            "principal": principal,
            "issued_by": issued_by,
            "tenant": self.tenant,
            "role": role,
            "capability": self.capability,
            "path": path,
            "parent_hash": parent_hash,
            "depth": depth,
        }
        payload["signature"] = _sign(payload)
        return payload


class PropagationPolicy(Policy):
    def __init__(
        self,
        agent_name: str,
        graph: PropagationGraph,
        *,
        lookup_delay_seconds: float = 0.0,
    ) -> None:
        self.agent_name = agent_name
        self.graph = graph
        self.lookup_delay_seconds = lookup_delay_seconds

    @property
    def version(self) -> str:
        return f"authz-propagation/{self.agent_name}/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        if self.lookup_delay_seconds:
            time.sleep(self.lookup_delay_seconds)
        authz = call.args.get("authz")
        lineage_raw = authz.get("lineage") if isinstance(authz, Mapping) else None
        if not isinstance(lineage_raw, tuple):
            reason = "missing propagation lineage"
        else:
            reason = self.graph.verify_lineage(lineage_raw, expected_agent=self.agent_name)
        decision = Decision.DENY if reason else Decision.ALLOW
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=(() if decision is Decision.ALLOW else ("AUTHZ_PROPAGATION_INVALID",)),
            reason=reason or "propagation lineage verified",
        )


class PropagationAuthzStrategy:
    name = "propagation"

    def __init__(
        self,
        *,
        graph: PropagationGraph | None = None,
        lookup_delay_seconds: float = 0.0,
    ) -> None:
        self.graph = graph or PropagationGraph()
        self.lookup_delay_seconds = lookup_delay_seconds

    def policy_for_agent(self, agent_name: str) -> Policy:
        return PropagationPolicy(
            agent_name,
            self.graph,
            lookup_delay_seconds=self.lookup_delay_seconds,
        )

    def args_for_hop(
        self,
        *,
        agent_name: str,
        tool_name: str,
        payload: Mapping[str, Any],
        parent_authz: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        del tool_name
        path = str(payload["resource"])
        if parent_authz is None:
            lineage = (self.graph.root_grant(path),)
        else:
            parent_lineage = parent_authz["lineage"]
            lineage = (
                *parent_lineage,
                self.graph.delegate(parent=parent_lineage[-1], principal=agent_name, path=path),
            )
        return {"payload": payload, "authz": {"lineage": lineage}}

    def token_units_for_hop(self, args: Mapping[str, Any]) -> int:
        return max(1, len(canonical_json(args)) // 4)
