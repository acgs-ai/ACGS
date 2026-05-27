"""The kernel dispatch loop — the central abstraction.

Every external action follows the same path::

    Goal → Proposed Action → Governance Decision → Tool Execution or Denial
         → Receipt → Audit Log

The kernel guarantees:

1. **Governed tool calls.** Every dispatch goes through ``policy.evaluate``
   before any side effect runs.
2. **Fail-closed behavior.** If policy evaluation raises, the kernel
   synthesizes a DENY record and appends it. If the audit append fails, the
   kernel raises :class:`~gove_zone.errors.AuditError` — never silent allow.
3. **Replayable receipts.** Every dispatch (ALLOW or otherwise) is anchored
   in the audit chain with a :class:`~gove_zone.receipt.Receipt`.
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import (
    AuditError,
    DeniedError,
    EscalateError,
    UnknownToolError,
)
from gove_zone.policy import Policy, new_event_id
from gove_zone.receipt import Receipt, safe_result_hash
from gove_zone.tool import ToolCall, ToolRegistry


class Kernel:
    """Governed dispatch kernel.

    Usage::

        kernel = Kernel(
            policy=BoundaryPolicy(forbidden_keywords=["~/.ssh"]),
            audit=ChainHashAuditStore("audit.jsonl"),
        )

        @kernel.tool("write_file")
        def write_file(path: str, content: str) -> None:
            with open(path, "w") as f: f.write(content)

        result, receipt = kernel.dispatch("write_file", {"path": "/tmp/safe", "content": "hi"})
    """

    def __init__(
        self,
        *,
        policy: Policy,
        audit: ChainHashAuditStore,
        registry: ToolRegistry | None = None,
        actor: str = "anonymous",
        policy_timeout: float | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.registry = registry or ToolRegistry()
        self.actor = actor
        # Watchdog: if set, policy.evaluate must return within this many
        # seconds or the kernel synthesizes a fail-closed DENY. None
        # preserves the unbounded synchronous path (default).
        self.policy_timeout = policy_timeout

    def tool(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to register a tool under *name*.

        ::

            @kernel.tool("http_post")
            def http_post(url: str, body: dict) -> int: ...
        """

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.registry.register(name, fn)
            return fn

        return decorator

    def dispatch(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
    ) -> tuple[Any, Receipt]:
        """Run the kernel loop for a single tool call.

        Returns ``(result, receipt)`` on ALLOW or TRANSFORM. Raises
        :class:`DeniedError` on DENY, :class:`EscalateError` on ESCALATE,
        :class:`UnknownToolError` if the tool is not registered, or
        :class:`AuditError` if the audit append fails.

        ``goal`` is the caller's high-level intent; the kernel records it
        verbatim in the decision and receipt for replay/debug.
        """
        args_dict: dict[str, Any] = dict(args or {})

        if not self.registry.has(tool_name):
            raise UnknownToolError(tool_name)

        call = ToolCall(name=tool_name, args=args_dict, goal=goal)
        record, audit_hash = self._evaluate_and_record(call)

        if record.decision is Decision.DENY:
            raise DeniedError(record, audit_hash)
        if record.decision is Decision.ESCALATE:
            raise EscalateError(record, audit_hash)
        if record.decision is Decision.TRANSFORM:
            if record.transformed_args is None:
                # Policy bug: TRANSFORM without args. Fail closed.
                raise DeniedError(record, audit_hash)
            args_dict = dict(record.transformed_args)
            call = call.with_args(args_dict)

        # ALLOW or TRANSFORM (post-replacement). Execute.
        tool_fn = self.registry.get(call.name)
        try:
            result = tool_fn(**args_dict)
        except Exception as exc:
            self._record_execution_failure(call, record, exc)
            raise

        receipt = Receipt(
            record=record,
            audit_hash=audit_hash,
            actor=self.actor,
            result_hash=safe_result_hash(result),
        )
        return result, receipt

    def _evaluate_and_record(self, call: ToolCall) -> tuple[DecisionRecord, str]:
        """Evaluate policy + append to audit. Fail-closed on both steps.

        - If policy.evaluate raises, synthesize a DENY record with the
          exception type in matched_rules and try to append it.
        - If audit.append raises, surface :class:`AuditError`.
        """
        try:
            record = self._evaluate_with_watchdog(call)
        except FuturesTimeoutError:
            record = DecisionRecord(
                decision=Decision.DENY,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version="fail-closed/policy-timeout",
                event_id=new_event_id(),
                matched_rules=(f"POLICY_ERROR:TIMEOUT:{self.policy_timeout}s",),
                reason=(f"policy evaluation exceeded watchdog timeout of {self.policy_timeout}s"),
                goal=call.goal,
            )
        except Exception as exc:
            record = DecisionRecord(
                decision=Decision.DENY,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version="fail-closed/policy-raised",
                event_id=new_event_id(),
                matched_rules=(f"POLICY_ERROR:{type(exc).__name__}",),
                reason=f"policy evaluation raised: {exc}",
                goal=call.goal,
            )
        else:
            # Inject the goal into the policy's record so callers don't have
            # to thread it through every policy implementation.
            record = dataclasses.replace(record, goal=call.goal)
            if record.decision is Decision.TRANSFORM and record.transformed_args is None:
                record = dataclasses.replace(
                    record,
                    decision=Decision.DENY,
                    matched_rules=(
                        *record.matched_rules,
                        "POLICY_ERROR:MALFORMED_TRANSFORM",
                    ),
                    reason=(f"{record.reason}; " if record.reason else "")
                    + "transform decision missing transformed_args",
                )

        try:
            payload = self.audit.append(record)
        except Exception as exc:
            raise AuditError(f"audit append failed for {record.event_id}: {exc}") from exc

        return record, str(payload["event_hash"])

    def _evaluate_with_watchdog(self, call: ToolCall) -> DecisionRecord:
        """Run ``policy.evaluate`` under the configured watchdog.

        When ``policy_timeout`` is ``None`` this is a direct synchronous
        call (no thread overhead, preserves existing behavior). When set,
        the evaluation runs on a single-shot worker thread and raises
        :class:`concurrent.futures.TimeoutError` if it exceeds the
        deadline. The orphan thread completes naturally; its result is
        discarded so a late ALLOW cannot bypass the fail-closed DENY the
        kernel will record.
        """
        if self.policy_timeout is None:
            return self.policy.evaluate(call)
        # Manual lifecycle: ThreadPoolExecutor's context manager blocks
        # on __exit__ waiting for the worker — that defeats the watchdog
        # when policy.evaluate is hung. Detach via shutdown(wait=False)
        # so dispatch returns inside the timeout; the orphan worker
        # completes naturally and is cleaned up by the interpreter at
        # exit.
        ex = ThreadPoolExecutor(max_workers=1)
        try:
            future = ex.submit(self.policy.evaluate, call)
            try:
                return future.result(timeout=self.policy_timeout)
            except FuturesTimeoutError:
                future.cancel()
                raise
        finally:
            ex.shutdown(wait=False)

    def _record_execution_failure(
        self,
        call: ToolCall,
        decision_record: DecisionRecord,
        exc: BaseException,
    ) -> None:
        """Best-effort: append a failure record after tool execution raises.

        The kernel re-raises the original exception regardless of whether
        this append succeeds — execution failures are surfaced to the caller
        even when we can't anchor them in the audit chain.
        """
        failure = DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=decision_record.policy_version,
            event_id=decision_record.event_id + ":failure",
            matched_rules=(f"EXEC_FAILURE:{type(exc).__name__}",),
            reason=f"execution raised: {exc}",
            goal=call.goal,
        )
        with contextlib.suppress(Exception):
            self.audit.append(failure)
