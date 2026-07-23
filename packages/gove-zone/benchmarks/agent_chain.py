"""Mock three-agent delegation chain for the Week-2 propagation gate."""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from gove_zone import ChainHashAuditStore, Kernel, Policy, ToolEffect

PAYLOAD_TARGET_BYTES = 50 * 1024


class AuthzStrategy(Protocol):
    """Authorization payload builder used by a benchmark chain."""

    name: str

    def policy_for_agent(self, agent_name: str) -> Policy:
        """Return the policy used by ``agent_name``'s kernel."""

    def args_for_hop(
        self,
        *,
        agent_name: str,
        tool_name: str,
        payload: Mapping[str, Any],
        parent_authz: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Build dispatch args for the next hop."""

    def token_units_for_hop(self, args: Mapping[str, Any]) -> int:
        """Return a deterministic token-consumption estimate for one hop."""


@dataclass(frozen=True)
class AgentHopResult:
    agent: str
    tool: str
    payload_bytes: int
    authz: Mapping[str, Any]


@dataclass(frozen=True)
class ChainRunResult:
    chain_id: int
    hops: tuple[AgentHopResult, ...]
    token_units: int


@dataclass(frozen=True)
class AgentSpec:
    name: str
    tool: str


AGENTS: tuple[AgentSpec, ...] = (
    AgentSpec(name="orchestrator", tool="orchestrate"),
    AgentSpec(name="planner", tool="plan"),
    AgentSpec(name="executor", tool="execute"),
)


def make_payload(chain_id: int, *, target_bytes: int = PAYLOAD_TARGET_BYTES) -> dict[str, Any]:
    """Return a deterministic structured payload of at least ``target_bytes``."""
    header = {
        "chain_id": chain_id,
        "tenant": "tenant-alpha",
        "resource": f"/workspace/project-{chain_id}/diff.patch",
        "capability": "filesystem:read",
        "goal": "validate delegated context access",
    }
    chunk = "context-line:{:04d}:governed-runtime-diff\n"
    lines: list[str] = []
    size = len(repr(header))
    i = 0
    while size < target_bytes:
        line = chunk.format(i)
        lines.append(line)
        size += len(line)
        i += 1
    return {**header, "context": lines}


def payload_size(payload: Mapping[str, Any]) -> int:
    """Approximate payload byte size without importing benchmark-only dependencies."""
    return len(repr(payload).encode("utf-8"))


class AgentChainRunner:
    """Runs Orchestrator -> Planner -> Executor through governed kernels."""

    def __init__(
        self,
        strategy: AuthzStrategy,
        *,
        audit_root: Path | None = None,
        tool_work: Callable[[Mapping[str, Any]], None] | None = None,
        policy_timeout: float | None = None,
    ) -> None:
        self.strategy = strategy
        self._tmp = None if audit_root is not None else tempfile.TemporaryDirectory()
        self.audit_root = audit_root or Path(self._tmp.name)
        self.tool_work = tool_work
        self.policy_timeout = policy_timeout

    def close(self) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()

    def run_one(self, chain_id: int) -> ChainRunResult:
        payload = make_payload(chain_id)
        parent_authz: Mapping[str, Any] | None = None
        hops: list[AgentHopResult] = []
        token_units = 0

        for spec in AGENTS:
            kernel = self._kernel_for(spec, chain_id)
            args = self.strategy.args_for_hop(
                agent_name=spec.name,
                tool_name=spec.tool,
                payload=payload,
                parent_authz=parent_authz,
            )
            token_units += self.strategy.token_units_for_hop(args)
            result, _receipt = kernel.dispatch(spec.tool, args, goal=str(payload["goal"]))
            parent_authz = result["authz"]
            hops.append(
                AgentHopResult(
                    agent=spec.name,
                    tool=spec.tool,
                    payload_bytes=payload_size(payload),
                    authz=parent_authz,
                )
            )

        return ChainRunResult(chain_id=chain_id, hops=tuple(hops), token_units=token_units)

    def run_parallel(self, *, concurrency: int = 10) -> tuple[ChainRunResult, ...]:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            return tuple(pool.map(self.run_one, range(concurrency)))

    def _kernel_for(self, spec: AgentSpec, chain_id: int) -> Kernel:
        audit = ChainHashAuditStore(self.audit_root / f"{self.strategy.name}-{chain_id}.jsonl")
        kernel = Kernel(
            policy=self.strategy.policy_for_agent(spec.name),
            audit=audit,
            actor=spec.name,
            policy_timeout=self.policy_timeout,
        )

        @kernel.tool(spec.tool, effect=ToolEffect.PURE_READ_ONLY)
        def governed_tool(payload: Mapping[str, Any], authz: Mapping[str, Any]) -> dict[str, Any]:
            if self.tool_work is not None:
                self.tool_work(payload)
            return {"payload_bytes": payload_size(payload), "authz": authz}

        return kernel
