"""High-level Managed Agent orchestration SDK.

Simplifies the developer experience for creating, sandboxing, and governing
agents using the gove-zone kernel.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.kernel import Kernel
from gove_zone.policy import AllowAllPolicy, Policy
from gove_zone.receipt import Receipt
from gove_zone.sandbox import SandboxProvider


class ManagedAgent:
    """Next-generation Managed Agent SDK.

    Provides a clean, high-level developer interface that orchestrates agent
    policies, audit ledgers, and secure sandboxed execution out-of-the-box.
    """

    def __init__(
        self,
        name: str,
        *,
        policy: Policy | None = None,
        audit_path: str | Path | None = None,
        sandbox: SandboxProvider | None = None,
        system_prompt: str | None = None,
    ) -> None:
        self.name = name
        self.system_prompt = system_prompt or "You are a governed AI agent."
        self.policy = policy or AllowAllPolicy()

        # Resolve audit log path and ensure directories exist
        resolved_audit = audit_path or Path(".gove-zone") / "audit.jsonl"
        Path(resolved_audit).parent.mkdir(parents=True, exist_ok=True)
        self.audit = ChainHashAuditStore(str(resolved_audit))

        self.sandbox = sandbox

        # Initialize the underlying dispatch kernel
        self._kernel = Kernel(
            policy=self.policy,
            audit=self.audit,
            actor=self.name,
        )

    def tool(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to register a tool under a specific name.

        Usage::

            @agent.tool("write_file")
            def write_file(path: str, content: str) -> None:
                ...
        """

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register_tool(name, fn)
            return fn

        return decorator

    def register_tool(self, name: str, fn: Callable[..., Any]) -> None:
        """Register a tool, wrapping it in the execution sandbox if configured."""
        if self.sandbox:
            sandbox = self.sandbox

            # Wrap function execution inside the sandbox provider
            def sandboxed_fn(**kwargs: Any) -> Any:
                return sandbox.run_tool(fn, kwargs)

            # Preserve metadata for importable functions inside sandboxes
            sandboxed_fn.__module__ = str(getattr(fn, "__module__", None) or "")
            sandboxed_fn.__name__ = str(getattr(fn, "__name__", None) or "")
            self._kernel.registry.register(name, sandboxed_fn)
        else:
            self._kernel.registry.register(name, fn)

    def dispatch(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> tuple[Any, Receipt]:
        """Execute a tool call governed by the policy, sandbox, and audit chain.

        Returns ``(result, receipt)`` on ALLOW or TRANSFORM. Raises appropriate
        exceptions (e.g. DeniedError) if execution fails or is blocked.
        """
        return self._kernel.dispatch(
            tool_name=tool_name,
            args=args,
            goal=goal,
            path=path,
            state=state,
        )
