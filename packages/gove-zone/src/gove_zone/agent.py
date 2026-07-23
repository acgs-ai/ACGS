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
from gove_zone.managed_execution import ManagedExecutionDispatcher, ManagedExecutionResult
from gove_zone.policy import DenyAllPolicy, Policy
from gove_zone.receipt import Receipt
from gove_zone.sandbox import SandboxProvider
from gove_zone.tool import ToolEffect


class ManagedAgent:
    """Next-generation Managed Agent SDK.

    Provides a clean, high-level developer interface that orchestrates agent
    policies, audit ledgers, and secure sandboxed execution out-of-the-box.

    Fail-closed default: when no ``policy`` is supplied the agent installs a
    :class:`~gove_zone.policy.DenyAllPolicy`, so an unconfigured agent denies
    every dispatch rather than executing tools unconditionally. Callers that
    intend to run tools must pass an explicit permissive policy.
    """

    def __init__(
        self,
        name: str,
        *,
        policy: Policy | None = None,
        audit_path: str | Path | None = None,
        sandbox: SandboxProvider | None = None,
        system_prompt: str | None = None,
        dispatcher: ManagedExecutionDispatcher | None = None,
    ) -> None:
        self.name = name
        self.system_prompt = system_prompt or "You are a governed AI agent."
        # Fail closed: an unconfigured agent denies every call rather than
        # running wrapped tools unconditionally (was AllowAllPolicy).
        self.policy = policy or DenyAllPolicy()

        # Resolve audit log path and ensure directories exist
        resolved_audit = audit_path or Path(".gove-zone") / "audit.jsonl"
        Path(resolved_audit).parent.mkdir(parents=True, exist_ok=True)
        self.audit = ChainHashAuditStore(str(resolved_audit))

        self.sandbox = sandbox
        self.dispatcher = dispatcher

        # Initialize the underlying dispatch kernel
        self._kernel = Kernel(
            policy=self.policy,
            audit=self.audit,
            actor=self.name,
            dispatcher=dispatcher,
        )

    def tool(
        self,
        name: str,
        *,
        effect: ToolEffect = ToolEffect.SIDE_EFFECT,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to register a tool under a specific name.

        Usage::

            @agent.tool("write_file")
            def write_file(path: str, content: str) -> None:
                ...
        """

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register_tool(name, fn, effect=effect)
            return fn

        return decorator

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        effect: ToolEffect = ToolEffect.SIDE_EFFECT,
    ) -> None:
        """Register a tool, wrapping it in the execution sandbox if configured."""
        registered_fn = fn
        if self.sandbox:
            sandbox = self.sandbox

            # Wrap function execution inside the sandbox provider
            def sandboxed_fn(**kwargs: Any) -> Any:
                return sandbox.run_tool(fn, kwargs)

            # Preserve metadata for importable functions inside sandboxes
            sandboxed_fn.__module__ = str(getattr(fn, "__module__", None) or "")
            sandboxed_fn.__name__ = str(getattr(fn, "__name__", None) or "")
            registered_fn = sandboxed_fn

        self._kernel.register_tool(name, registered_fn, effect=effect)

    def dispatch(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> tuple[Any, Receipt] | ManagedExecutionResult:
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
