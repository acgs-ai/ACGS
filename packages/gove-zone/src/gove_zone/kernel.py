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
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic

if TYPE_CHECKING:
    from typing_extensions import TypeVar
else:
    from typing import TypeVar

from gove_zone.audit import AuditAppender
from gove_zone.authz import AuthzReason, PrincipalRegistry
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import (
    AuditError,
    DeniedError,
    EscalateError,
    UnknownToolError,
)
from gove_zone.escalation import PendingApproval
from gove_zone.policy import Policy, new_event_id
from gove_zone.receipt import Receipt, safe_result_hash
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall, ToolRegistry, normalize_path_context

if TYPE_CHECKING:
    AuditT = TypeVar("AuditT", bound=AuditAppender, default=AuditAppender)
else:
    AuditT = TypeVar("AuditT", bound=AuditAppender)


@dataclasses.dataclass(frozen=True, slots=True)
class AuditedDecision:
    """Decision record plus the immutable append result returned by the audit sink."""

    record: DecisionRecord
    append_result: Mapping[str, Any]

    @property
    def audit_hash(self) -> str:
        """The append-produced event hash for this audited decision."""
        return str(self.append_result["event_hash"])


class Kernel(Generic[AuditT]):
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
        audit: AuditT,
        registry: ToolRegistry | None = None,
        actor: str = "anonymous",
        policy_timeout: float | None = None,
        side_store: ReplaySideStore | None = None,
        authz_enforce: bool = False,
        principal_registry: PrincipalRegistry | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.registry = registry or ToolRegistry()
        self.actor = actor
        # Principal authorization (B13). When ``authz_enforce`` is False (the
        # default) the kernel never consults ``principal_registry`` and behaves
        # exactly as before. When True, every dispatch must come from a
        # registered, tool-authorized principal — so an enforcing kernel without
        # a registry is a misconfiguration and fails closed at construction
        # rather than denying everything silently at runtime.
        if authz_enforce and principal_registry is None:
            raise ValueError("authz_enforce=True requires a principal_registry (fail-closed)")
        self.authz_enforce = authz_enforce
        self.principal_registry = principal_registry
        # Watchdog: if set, policy.evaluate must return within this many
        # seconds or the kernel synthesizes a fail-closed DENY. None
        # preserves the unbounded synchronous path (default).
        self.policy_timeout = policy_timeout
        # Opt-in raw-args side-store. When None (default) the kernel writes
        # nothing extra and behaves byte-for-byte as before. When set, every
        # dispatch additionally persists the raw call so replay can re-derive
        # the decision. It never affects the audit chain, the returned receipt,
        # or the decision — strictly additive.
        self.side_store = side_store

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
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> tuple[Any, Receipt]:
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
        args_dict: dict[str, Any] = dict(args or {})

        if not self.registry.has(tool_name):
            raise UnknownToolError(tool_name)

        call = ToolCall(
            name=tool_name,
            args=args_dict,
            goal=goal,
            actor=self.actor,
            path=normalize_path_context(path),
            state=dict(state or {}),
        )
        original_call = call
        audited = self.evaluate_and_append(call)
        record = audited.record
        audit_hash = audited.audit_hash

        if record.decision is Decision.DENY:
            raise DeniedError(record, audit_hash)
        if record.decision is Decision.ESCALATE:
            raise EscalateError(
                record,
                audit_hash,
                pending=PendingApproval(record, audit_hash, dict(call.args)),
            )
        if record.decision is Decision.TRANSFORM:
            if record.transformed_args is None:  # pragma: no cover
                # Defense-in-depth re-raise: unreachable via the public API
                # because ``_evaluate_only`` already normalizes a malformed
                # TRANSFORM (transformed_args is None) into a DENY before this
                # point (the MALFORMED_TRANSFORM synthesis). Kept as a
                # fail-closed backstop so any future path that bypasses that
                # normalization still cannot execute a TRANSFORM without args.
                raise DeniedError(record, audit_hash)
            args_dict = dict(record.transformed_args)
            call = call.with_args(args_dict)

        # ALLOW or TRANSFORM (post-replacement). Execute.
        tool_fn = self.registry.get(call.name)
        try:
            result = tool_fn(**args_dict)
        except Exception as exc:
            self._record_execution_failure(original_call, audited, exc, executed_call=call)
            raise

        receipt = Receipt(
            record=record,
            audit_hash=audit_hash,
            actor=self.actor,
            result_hash=safe_result_hash(result),
        )
        return result, receipt

    def evaluate_and_record(self, call: ToolCall) -> tuple[DecisionRecord, str]:
        """Public governed decision primitive: evaluate *call* under the
        fail-closed watchdog and append the single decision to the audit chain,
        returning the real :class:`~gove_zone.decision.DecisionRecord` and its
        audit ``event_hash``.

        A thin public alias for the private :meth:`_evaluate_and_record` that
        :meth:`dispatch` itself calls (it delegates verbatim, adding no logic),
        exposed so transport adapters — e.g. the MCP gateway in
        :mod:`gove_zone.adapters.mcp_gateway` — can obtain the deciding record
        for all four verdicts without reconstructing it from a lossy projection:
        a DENY record still carries ``reason`` / ``decision_request_hash``, an
        ESCALATE record can be parked as a
        :class:`~gove_zone.escalation.PendingApproval`, and an ALLOW/TRANSFORM
        record can mint a :class:`~gove_zone.receipt.DecisionReceipt`.

        Contract (identical to the private method, since it is that method):
        evaluation runs under the same fail-closed watchdog and DENY synthesis
        as :meth:`dispatch`; **exactly one** audit event is appended; **no tool
        is executed** (there is no registry lookup and no ``tool_fn`` call — the
        caller drives execution through the signed
        :func:`~gove_zone.executor.execute_with_receipt` gate);
        :class:`~gove_zone.errors.AuditError` is raised if the append fails; and
        kernel-owned context is attached via :meth:`_attach_context`. It grants
        no new authority — it neither bypasses receipt validation nor executes
        before audit.

        Unlike :meth:`dispatch` it does **not** raise
        :class:`~gove_zone.errors.DeniedError` /
        :class:`~gove_zone.errors.EscalateError`: the caller inspects
        ``record.decision`` and drives the DENY / ESCALATE / ALLOW branch itself.
        """
        audited = self.evaluate_and_append(call)
        return audited.record, audited.audit_hash

    def evaluate_and_append(self, call: ToolCall) -> AuditedDecision:
        """Evaluate *call*, append exactly one audit event, and return the full
        immutable append result.

        This is the canonical no-execution decision primitive. It uses the same
        fail-closed evaluation path as dispatch and refuses malformed or
        mismatched append responses before returning authorization material.
        """
        return self._evaluate_and_append(call)

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
        call = ToolCall(
            name=tool_name,
            args=dict(args or {}),
            goal=goal,
            actor=self.actor,
            path=normalize_path_context(path),
            state=dict(state or {}),
        )
        return self._evaluate_only(call)

    def _attach_context(self, record: DecisionRecord, call: ToolCall) -> DecisionRecord:
        return dataclasses.replace(
            record,
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call._decision_request_hash(record.argument_hash),
        )

    def _authz_check(self, call: ToolCall) -> DecisionRecord | None:
        """Fail-closed principal authorization (B13).

        Returns a synthesized DENY record if ``call.actor`` is not an authorized
        principal for ``call.name``, else ``None``. Only consulted when
        ``authz_enforce`` is set; the constructor guarantees a registry exists.
        """
        registry = self.principal_registry
        reason = (
            AuthzReason.UNREGISTERED_PRINCIPAL
            if registry is None
            else registry.authorize(call.actor, call.name)
        )
        if reason is None:
            return None
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version="fail-closed/authz",
            event_id=new_event_id(),
            matched_rules=(f"AUTHZ_DENY:{reason}",),
            reason=f"actor {call.actor!r} not authorized for tool {call.name!r} ({reason})",
        )

    def _evaluate_only(self, call: ToolCall) -> DecisionRecord:
        """Evaluate policy under the fail-closed watchdog and attach kernel
        context, WITHOUT appending to the audit chain or executing the tool.

        Shared by :meth:`dispatch` (which then appends and executes) and
        :meth:`simulate` (which does neither), so a simulated prediction uses the
        exact same evaluation + fail-closed synthesis as a real dispatch.

        - actor not an authorized principal (enforce on) -> ``fail-closed/authz`` DENY
        - policy raises -> synthesize a ``fail-closed/policy-raised`` DENY
        - policy times out -> synthesize a ``fail-closed/policy-timeout`` DENY
        - TRANSFORM without ``transformed_args`` -> DENY (malformed)
        """
        if self.authz_enforce:
            denied = self._authz_check(call)
            if denied is not None:
                # Short-circuit before policy evaluation: an unauthorized actor
                # never reaches the policy or the tool, but the DENY is still
                # attached + audited like any other decision.
                return self._attach_context(denied, call)
        try:
            record = self._evaluate_with_watchdog(call)
        except FuturesTimeoutError:
            record = DecisionRecord(
                decision=Decision.DENY,
                tool=call.name,
                argument_hash=call.argument_hash(),
                policy_version="fail-closed/policy-timeout",
                event_id=new_event_id(),
                matched_rules=(f"POLICY_ERROR:TIMEOUT:{self.policy_timeout}s",),
                reason=f"policy evaluation exceeded watchdog timeout of {self.policy_timeout}s",
            )
        except Exception as exc:
            record = DecisionRecord(
                decision=Decision.DENY,
                tool=call.name,
                argument_hash=call.argument_hash(),
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
        audited = self._evaluate_and_append(call)
        return audited.record, audited.audit_hash

    def _evaluate_and_append(self, call: ToolCall) -> AuditedDecision:
        """Evaluate (fail-closed) then append the decision to the audit chain.

        Surfaces :class:`AuditError` if the append fails or returns malformed
        authorization material.
        """
        record = self._evaluate_only(call)
        self._pin_original_call_bindings(call)

        audited = self._append_validated(record)

        # Additive raw-args side-store write. The audit chain is the source of
        # truth and is already recorded; a side-store failure must never corrupt
        # the audit contract or change the decision, so it is suppressed.
        if self.side_store is not None:
            with contextlib.suppress(Exception):
                self.side_store.append(call, record)

        return audited

    def _append_validated(self, record: DecisionRecord) -> AuditedDecision:
        try:
            payload = self.audit.append(record)
        except Exception as exc:
            raise AuditError(f"audit append failed for {record.event_id}: {exc}") from exc
        self._validate_append_payload(record, payload)
        return AuditedDecision(record=record, append_result=_freeze_mapping(payload))

    def _validate_append_payload(self, record: DecisionRecord, payload: Mapping[str, Any]) -> None:
        if not isinstance(payload, Mapping):
            raise AuditError(f"audit append returned non-mapping for {record.event_id}")
        expected = record.to_dict()
        for key, expected_value in expected.items():
            if payload.get(key) != expected_value:
                raise AuditError(f"audit append returned mismatched {key!r} for {record.event_id}")
        previous_hash = payload.get("previous_hash")
        event_hash = payload.get("event_hash")
        if not _looks_like_sha256(previous_hash):
            raise AuditError(f"audit append returned invalid previous_hash for {record.event_id}")
        if not _looks_like_sha256(event_hash):
            raise AuditError(f"audit append returned invalid event_hash for {record.event_id}")
        hash_payload = dict(payload)
        hash_payload.pop("event_hash", None)
        if sha256_json(hash_payload) != event_hash:
            raise AuditError(f"audit append returned mismatched event_hash for {record.event_id}")

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
        audited_decision: AuditedDecision,
        exc: BaseException,
        *,
        executed_call: ToolCall | None = None,
    ) -> None:
        """Best-effort: append a failure record after tool execution raises.

        The kernel re-raises the original exception regardless of whether
        this append succeeds — execution failures are surfaced to the caller
        even when we can't anchor them in the audit chain.

        Failure details are redacted to the exception class, and the strict
        public append helper binds the failure record back to the original
        audited decision and call.
        """
        with contextlib.suppress(Exception):
            self.append_execution_failure(
                call,
                audited_decision,
                exc,
                executed_call=executed_call,
            )

    def append_execution_failure(
        self,
        call: ToolCall,
        audited_decision: AuditedDecision,
        exc: BaseException,
        *,
        executed_call: ToolCall | None = None,
    ) -> AuditedDecision:
        """Strictly append a redacted execution-failure record.

        Unlike dispatch's best-effort failure logging wrapper, this public
        primitive propagates binding or audit failures so callers that need a
        hard failure-audit contract can fail closed.
        """
        decision_record = audited_decision.record
        if decision_record.decision not in (Decision.ALLOW, Decision.TRANSFORM):
            raise AuditError(
                "execution-failure audit requires an ALLOW or TRANSFORM audited decision"
            )
        self._validate_failure_binding(call, audited_decision)
        effective_call = executed_call or call
        self._validate_effective_failure_call(call, effective_call)
        error_class = type(exc).__name__
        failure_argument_hash = sha256_json(dict(effective_call.args))
        matched_rules: tuple[str, ...] = (f"EXEC_FAILURE:{error_class}",)
        if failure_argument_hash != decision_record.argument_hash:
            matched_rules = (*matched_rules, "EXEC_ARGS_DIVERGED")
        failure = DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=failure_argument_hash,
            policy_version=decision_record.policy_version,
            event_id=decision_record.event_id + ":failure",
            matched_rules=matched_rules,
            reason=f"execution raised: {error_class}",
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
        )
        return self._append_validated(failure)

    def _validate_failure_binding(
        self,
        call: ToolCall,
        audited_decision: AuditedDecision,
    ) -> None:
        record = audited_decision.record
        if record.tool != call.name:
            raise AuditError("execution-failure audit binding mismatch: tool")
        if record.argument_hash != call.argument_hash():
            raise AuditError("execution-failure audit binding mismatch: argument_hash")
        if record.goal != call.goal:
            raise AuditError("execution-failure audit binding mismatch: goal")
        if record.actor != call.actor:
            raise AuditError("execution-failure audit binding mismatch: actor")
        if record.path != call.path:
            raise AuditError("execution-failure audit binding mismatch: path")
        if record.state_hash != call.state_hash():
            raise AuditError("execution-failure audit binding mismatch: state_hash")
        if record.decision_request_hash != call.decision_request_hash():
            raise AuditError("execution-failure audit binding mismatch: decision_request_hash")

    def _validate_effective_failure_call(
        self,
        original_call: ToolCall,
        effective_call: ToolCall,
    ) -> None:
        if effective_call.name != original_call.name:
            raise AuditError("execution-failure effective call mismatch: tool")
        if effective_call.goal != original_call.goal:
            raise AuditError("execution-failure effective call mismatch: goal")
        if effective_call.actor != original_call.actor:
            raise AuditError("execution-failure effective call mismatch: actor")
        if effective_call.path != original_call.path:
            raise AuditError("execution-failure effective call mismatch: path")
        if effective_call.state_hash() != original_call.state_hash():
            raise AuditError("execution-failure effective call mismatch: state_hash")

    def _pin_original_call_bindings(self, call: ToolCall) -> None:
        call.argument_hash()
        call.state_hash()
        call.decision_request_hash()


def _looks_like_sha256(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _freeze_mapping(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({str(key): _freeze_value(value) for key, value in payload.items()})


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, list | tuple):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_freeze_value(item) for item in value)
    return value
