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
3. **Explicit evidence modes.** Recorded dispatches are audit-anchored. Plain
   ``evaluate`` results remain unanchored until explicitly appended, while
   managed SIDE_EFFECT dispatch uses the strict receipt-gated executor.
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from threading import RLock
from typing import TYPE_CHECKING, Any, NoReturn

from gove_zone.audit import AuditCommit, ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import (
    AuditError,
    DeniedError,
    EscalateError,
    SideEffectCallableAccessError,
    UnknownToolError,
)
from gove_zone.escalation import PendingApproval
from gove_zone.policy import Policy, new_event_id
from gove_zone.receipt import Receipt, safe_result_hash
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall, ToolEffect, ToolRegistry, normalize_path_context

if TYPE_CHECKING:
    from gove_zone.managed_execution import (
        ManagedExecutionDispatcher,
        ManagedExecutionResult,
    )


class Kernel:
    """Governed dispatch kernel.

    Usage::

        from gove_zone import BoundaryPolicy, ChainHashAuditStore, Kernel
        from gove_zone.tool import ToolEffect

        kernel = Kernel(
            policy=BoundaryPolicy(forbidden_keywords=["~/.ssh"]),
            audit=ChainHashAuditStore("audit.jsonl"),
        )

        @kernel.tool("preview", effect=ToolEffect.PURE_READ_ONLY)
        def preview(content: str) -> str:
            return content.upper()

        result, receipt = kernel.dispatch("preview", {"content": "hi"})

    SIDE_EFFECT tools require a configured strict managed dispatcher. Without
    one, dispatch returns the fixed ``SIDE_EFFECT_RECEIPT_REQUIRED`` denial and
    never runs the raw callable.
    """

    def __init__(
        self,
        *,
        policy: Policy,
        audit: ChainHashAuditStore,
        registry: ToolRegistry | None = None,
        actor: str = "anonymous",
        policy_timeout: float | None = None,
        side_store: ReplaySideStore | None = None,
        context_hydrator: Callable[[str, Mapping[str, Any]], dict[str, Any]] | None = None,
        dispatcher: ManagedExecutionDispatcher | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.registry = registry if registry is not None else ToolRegistry()
        self.actor = actor
        self.policy_timeout = policy_timeout
        self.side_store = side_store
        self.context_hydrator = context_hydrator
        self.dispatcher = dispatcher
        self._registration_lock = RLock()
        self._adopt_prepopulated_side_effects()

    @staticmethod
    def _side_effect_sentinel(name: str) -> Callable[..., Any]:
        def receipt_required_sentinel(**_kwargs: Any) -> Any:
            raise SideEffectCallableAccessError(name)

        receipt_required_sentinel.__name__ = f"receipt_required_{name.replace('.', '_')}"
        return receipt_required_sentinel

    def _adopt_prepopulated_side_effects(self) -> None:
        """Seal constructor-supplied side effects before adopting their adapters."""
        for name in self.registry.names():
            if self.registry.effect(name) is ToolEffect.PURE_READ_ONLY:
                continue
            adapter = self.registry._seal_side_effect(
                name,
                self._side_effect_sentinel(name),
            )
            if self.dispatcher is not None:
                self.dispatcher.register_adapter(name, adapter)

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        effect: ToolEffect = ToolEffect.SIDE_EFFECT,
    ) -> None:
        """Register one tool without exposing side-effect adapters in the registry."""
        if not callable(fn):
            raise TypeError("tool must be callable")
        declared_effect = ToolEffect(effect)
        with self._registration_lock:
            if self.registry.has(name):
                raise ValueError(f"tool already registered: {name!r}")
            if declared_effect is ToolEffect.PURE_READ_ONLY:
                self.registry.register(name, fn, effect=declared_effect)
                return
            if self.dispatcher is not None:
                self.dispatcher.register_adapter(name, fn)
            self.registry.register(
                name,
                self._side_effect_sentinel(name),
                effect=declared_effect,
            )

    def tool(
        self,
        name: str,
        *,
        effect: ToolEffect = ToolEffect.SIDE_EFFECT,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to register a tool under *name*.

        ::

            @kernel.tool("http_post")
            def http_post(url: str, body: dict) -> int: ...
        """

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register_tool(name, fn, effect=effect)
            return fn

        return decorator

    def deny_without_execution(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> NoReturn:
        """Append a fixed receipt-required denial without evaluating policy.

        The registered callable is never resolved or invoked, including under an
        explicitly permissive legacy policy.
        """
        if not self.registry.has(tool_name):
            raise UnknownToolError(tool_name)
        call = self._prepare_call(
            tool_name,
            args,
            goal=goal,
            path=path,
            state=state,
        )
        self._deny_prepared_without_execution(call)

    def _deny_prepared_without_execution(self, call: ToolCall) -> NoReturn:
        record = DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version="kernel/side-effect-receipt-required/v1",
            event_id=new_event_id(),
            matched_rules=("SIDE_EFFECT_RECEIPT_REQUIRED",),
            reason="side-effect execution requires a configured receipt-gated dispatcher",
        )
        record = self._attach_context(record, call)
        record, audit_hash = self._append_record(call, record)
        raise DeniedError(record, audit_hash)

    def dispatch(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> tuple[Any, Receipt] | ManagedExecutionResult:
        """Run the kernel loop for a single tool call.

        Returns ``(result, receipt)`` on ALLOW or TRANSFORM. Raises
        :class:`DeniedError` on DENY, :class:`EscalateError` on ESCALATE,
        :class:`UnknownToolError` if the tool is not registered, or
        :class:`AuditError` if the audit append fails.

        ``goal`` is the caller's high-level intent; the kernel records it
        verbatim in the decision and receipt for replay/debug.
        ``path`` and ``state`` are optional policies-on-paths context. They are
        available to policies before execution and persisted as path segments
        plus hashes in the audit record.
        """
        if not self.registry.has(tool_name):
            raise UnknownToolError(tool_name)

        call = self._prepare_call(
            tool_name,
            args,
            goal=goal,
            path=path,
            state=state,
        )
        if self.registry.effect(tool_name) is ToolEffect.SIDE_EFFECT:
            if self.dispatcher is None:
                self._deny_prepared_without_execution(call)
            from gove_zone.managed_execution import ManagedExecutionProposal

            return self.dispatcher.dispatch(
                ManagedExecutionProposal(
                    name=call.name,
                    args=call.args,
                    goal=call.goal,
                    path=call.path,
                    state=call.state,
                )
            )
        return self._dispatch_legacy_pure(call)

    def _dispatch_legacy_pure(self, call: ToolCall) -> tuple[Any, Receipt]:
        """Run the historical policy/audit path for an explicitly pure tool."""
        args_dict = dict(call.args)
        record, audit_hash = self._evaluate_and_record(call)

        if record.decision is Decision.DENY:
            raise DeniedError(record, audit_hash)
        if record.decision is Decision.ESCALATE:
            raise EscalateError(
                record,
                audit_hash,
                pending=PendingApproval(record, audit_hash, dict(call.args)),
            )
        if record.decision is Decision.TRANSFORM:
            if record.transformed_args is None:
                # Policy bug: TRANSFORM without args. Fail closed.
                raise DeniedError(record, audit_hash)
            args_dict = dict(record.transformed_args)
            call = call.with_args(args_dict)

        # ALLOW or TRANSFORM (post-replacement). Execute.
        tool_fn = self.registry._get_pure_callable(call.name)
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

    def simulate(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> DecisionRecord:
        """Predict the governance decision for a call **without** executing or
        recording it — read-only capability discovery ("would this be allowed?").

        Runs the exact same policy evaluation and fail-closed synthesis as
        :meth:`dispatch` (via the shared :meth:`_evaluate_only`), so the returned
        :class:`~gove_zone.decision.DecisionRecord` is the verdict ``dispatch``
        *would* reach for the same input — letting a caller (e.g. a denied agent)
        discover the decision before producing any side effect.

        Side-effect-free **at the kernel level**: no ``tool_fn`` is invoked, no
        ``audit.append`` and no side-store write occur, so the audit chain is
        unchanged. The returned record is **not** anchored in the audit chain (its
        ``event_id`` was never appended) — it is a prediction, not a receipt, and
        must never be presented as authorization to execute.

        Raises :class:`UnknownToolError` if the tool is not registered, mirroring
        :meth:`dispatch` so the prediction is faithful for unregistered tools too.
        (It cannot guarantee a user-supplied ``policy.evaluate`` is itself pure; it
        guarantees the *kernel* performs no execution or audit mutation.)
        """
        if not self.registry.has(tool_name):
            raise UnknownToolError(tool_name)

        call = self._prepare_call(
            tool_name,
            args,
            goal=goal,
            path=path,
            state=state,
        )
        return self._evaluate_only(call)

    def _prepare_call(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> ToolCall:
        """Build a call with kernel-owned actor and hydrated trusted state."""
        args_dict = dict(args or {})
        state_dict = dict(state or {})
        if self.context_hydrator is not None:
            hydrated = self.context_hydrator(tool_name, args_dict)
            state_dict.update(hydrated)
        return ToolCall(
            name=tool_name,
            args=args_dict,
            goal=goal,
            actor=self.actor,
            path=normalize_path_context(path),
            state=state_dict,
        )

    def evaluate_and_record(self, call: ToolCall) -> tuple[DecisionRecord, str]:
        """Evaluate *call* fail-closed and append exactly one audit event.

        This is the non-executing authorization seam for adapters. It performs
        no registry lookup or tool invocation. Actor and organizational context
        remain kernel-owned: ``Kernel.actor`` replaces ``call.actor``, trusted
        hydrator state wins, and caller-supplied path/state that differs from
        trusted context is recorded as a fail-closed DENY.

        Returns the decision record and its audit event hash. Audit append
        failures propagate as :class:`~gove_zone.errors.AuditError`, preserving
        the same fail-closed behavior used by :meth:`dispatch`.
        """
        record, event = self.evaluate_and_record_event(call)
        return record, str(event["event_hash"])

    def evaluate_and_record_event(
        self,
        call: ToolCall,
        *,
        trusted_timestamp_iso: str | None = None,
        trusted_fail_closed_policy_version: str | None = None,
    ) -> tuple[DecisionRecord, dict[str, Any]]:
        """Evaluate once and return the exact atomically appended audit event.

        This is the strict authorization seam for receipt issuers that must bind
        both ``previous_hash`` and ``event_hash`` without a racy
        ``last_hash()`` read before append.  ``trusted_timestamp_iso`` is an
        optional issuer-owned timestamp override applied after policy evaluation
        and before the single append.  A strict issuer may also provide
        ``trusted_fail_closed_policy_version`` so the kernel's own timeout/raised
        DENY remains bound to the attested policy reference instead of its
        diagnostic ``fail-closed/*`` marker.  It is applied only to those
        kernel-synthesized DENYs; ordinary policy records are never rewritten.
        Existing callers retain the policy record's fields by omitting both.

        Like :meth:`evaluate_and_record`, this method never performs a registry
        lookup and never invokes a tool.
        """
        trusted_call, prepared = self._prepare_authorization_record(
            call,
            trusted_timestamp_iso=trusted_timestamp_iso,
            trusted_fail_closed_policy_version=trusted_fail_closed_policy_version,
        )
        return self._append_record_event(trusted_call, prepared)

    def evaluate_and_record_commit(
        self,
        call: ToolCall,
        *,
        trusted_timestamp_iso: str | None = None,
        trusted_fail_closed_policy_version: str | None = None,
    ) -> tuple[DecisionRecord, AuditCommit]:
        """Evaluate once and return a signed, externally checkpointed commit.

        This additive strict seam preserves the legacy event/hash APIs while
        allowing a side-effect issuer to carry the exact ``AuditCommit`` into
        the final ``run_if_committed`` execution boundary.
        """

        trusted_call, prepared = self._prepare_authorization_record(
            call,
            trusted_timestamp_iso=trusted_timestamp_iso,
            trusted_fail_closed_policy_version=trusted_fail_closed_policy_version,
        )
        return self._append_record_commit(trusted_call, prepared)

    def _prepare_authorization_record(
        self,
        call: ToolCall,
        *,
        trusted_timestamp_iso: str | None,
        trusted_fail_closed_policy_version: str | None,
    ) -> tuple[ToolCall, DecisionRecord]:
        """Prepare one trusted call and one fail-closed decision without appending."""

        trusted_call = self._prepare_call(call.name, call.args, goal=call.goal)
        if call.path != trusted_call.path or dict(call.state) != dict(trusted_call.state):
            mismatch = DecisionRecord(
                decision=Decision.DENY,
                tool=trusted_call.name,
                argument_hash=trusted_call.argument_hash(),
                policy_version="fail-closed/context-mismatch",
                event_id=new_event_id(),
                matched_rules=("KERNEL_ERROR:UNTRUSTED_CONTEXT",),
                reason="caller-supplied path/state did not match trusted kernel context",
            )
            prepared = self._attach_context(mismatch, trusted_call)
        else:
            prepared = self._evaluate_only(trusted_call)
        if (
            trusted_fail_closed_policy_version is not None
            and prepared.decision is Decision.DENY
            and prepared.policy_version.startswith("fail-closed/")
        ):
            prepared = dataclasses.replace(
                prepared,
                policy_version=trusted_fail_closed_policy_version,
            )
        if trusted_timestamp_iso is not None:
            prepared = dataclasses.replace(
                prepared,
                timestamp_iso=trusted_timestamp_iso,
            )
        return trusted_call, prepared

    def _attach_context(self, record: DecisionRecord, call: ToolCall) -> DecisionRecord:
        return dataclasses.replace(
            record,
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
        )

    def _evaluate_only(self, call: ToolCall) -> DecisionRecord:
        """Evaluate policy under the fail-closed watchdog and attach kernel
        context, WITHOUT appending to the audit chain or executing the tool.

        Shared by :meth:`dispatch` (which then appends and executes) and
        :meth:`simulate` (which does neither), so a simulated prediction uses the
        exact same evaluation + fail-closed synthesis as a real dispatch.

        - policy raises -> synthesize a ``fail-closed/policy-raised`` DENY
        - policy times out -> synthesize a ``fail-closed/policy-timeout`` DENY
        - TRANSFORM without ``transformed_args`` -> DENY (malformed)
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
                reason=f"policy evaluation exceeded watchdog timeout of {self.policy_timeout}s",
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
            )
        else:
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
        # Inject kernel-owned context into the policy's record so callers don't
        # have to thread it through every policy implementation.
        return self._attach_context(record, call)

    def _evaluate_and_record(self, call: ToolCall) -> tuple[DecisionRecord, str]:
        """Evaluate (fail-closed) then append the decision to the audit chain.

        Surfaces :class:`AuditError` if the append fails.
        """
        record = self._evaluate_only(call)
        return self._append_record(call, record)

    def _append_record(
        self,
        call: ToolCall,
        record: DecisionRecord,
    ) -> tuple[DecisionRecord, str]:
        """Append one prepared decision and preserve fail-closed audit errors."""
        appended_record, payload = self._append_record_event(call, record)
        return appended_record, str(payload["event_hash"])

    def _append_record_event(
        self,
        call: ToolCall,
        record: DecisionRecord,
    ) -> tuple[DecisionRecord, dict[str, Any]]:
        """Append once and return the exact payload produced under the audit lock."""
        try:
            payload = self.audit.append(record)
        except Exception as exc:
            raise AuditError(f"audit append failed for {record.event_id}: {exc}") from exc

        # Additive raw-args side-store write. The audit chain is the source of
        # truth and is already recorded; a side-store failure must never corrupt
        # the audit contract or change the decision, so it is suppressed.
        if self.side_store is not None:
            with contextlib.suppress(Exception):
                self.side_store.append(call, record)

        return record, dict(payload)

    def _append_record_commit(
        self,
        call: ToolCall,
        record: DecisionRecord,
    ) -> tuple[DecisionRecord, AuditCommit]:
        """Append once through the strict signed-checkpoint audit seam."""

        try:
            commit = self.audit.append_committed(record)
        except Exception as exc:
            raise AuditError(f"committed audit append failed for {record.event_id}: {exc}") from exc
        if self.side_store is not None:
            with contextlib.suppress(Exception):
                self.side_store.append(call, record)
        return record, commit

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
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
        )
        with contextlib.suppress(Exception):
            self.audit.append(failure)


class GovernedTool:
    """Wrapper that freezes agent tool execution until evaluated by Kernel."""

    def __init__(
        self,
        kernel: Kernel,
        tool_name: str,
        tool_fn: Callable[..., Any],
        *,
        effect: ToolEffect = ToolEffect.SIDE_EFFECT,
    ) -> None:
        self.kernel = kernel
        self.tool_name = tool_name
        declared_effect = ToolEffect(effect)
        self.tool_fn = (
            tool_fn
            if declared_effect is ToolEffect.PURE_READ_ONLY
            else self.kernel._side_effect_sentinel(tool_name)
        )
        self.kernel.register_tool(tool_name, tool_fn, effect=declared_effect)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # Freeze and compile arguments
        call_args = dict(kwargs)
        if args:
            # Match positional arguments if metadata is not provided, fallback to standard indexing
            for idx, val in enumerate(args):
                call_args[f"arg_{idx}"] = val

        # Dispatch through the kernel's pre-execution interception wrapper
        result, _ = self.kernel.dispatch(self.tool_name, call_args)
        return result
