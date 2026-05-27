"""
Hermes ACGS middleware: minimal runtime constitutional governance hooks.

This file is intentionally model-agnostic and Hermes-API-agnostic. Wire these
methods into Hermes' tool lifecycle:

    pre = acgs.check_pre_tool(tool_name, args, user_msg=user_msg, context=ctx)
    if pre.action in {"DENY", "REQUIRE_HUMAN"}:
        return acgs.user_friendly_explain(pre)

    result = call_tool(tool_name, pre.rewrite_args or args)

    post = acgs.check_post_tool(tool_name, args, result, context=ctx)
    result = acgs.apply_post_action(result, post)

    final = acgs.check_final(draft_answer, tool_trace=trace, context=ctx)
    return acgs.apply_final_action(draft_answer, final)

Actions:
    ALLOW, DENY, REQUIRE_HUMAN, REWRITE, REDACT, SOFT_BLOCK_WITH_EXPLANATION
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from .evidence_writer import ChainEvidenceWriter
except ImportError:  # pragma: no cover - supports direct file drop-in
    from evidence_writer import ChainEvidenceWriter

# Optional OpenTelemetry cross-link: enrich ACGS evidence rows with the active
# span's trace_id/span_id, and stamp the corresponding span with the ACGS
# decision + event_hash. See docs/design/acgs-phoenix-observability.md for the
# full cross-link contract.  No-op when opentelemetry is not installed OR when
# no span is currently active.  Kept strictly off the ChainEvidenceWriter
# hashing surface — only observed from _audit().
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    _otel_trace = None  # type: ignore[assignment]


def _current_otel_ids() -> tuple[str, str] | tuple[None, None]:
    """Return ``(trace_id_hex, span_id_hex)`` if a real span is active, else (None, None).

    opentelemetry exposes an ``INVALID_SPAN`` sentinel with all-zero IDs when no
    span is active; those are filtered out here so callers only see real spans.
    """
    if _otel_trace is None:
        return (None, None)
    try:
        span = _otel_trace.get_current_span()
    except Exception:  # pragma: no cover - OTEL in a broken state
        return (None, None)
    if span is None:
        return (None, None)
    try:
        ctx = span.get_span_context()
    except Exception:  # pragma: no cover - non-standard span impl
        return (None, None)
    if not ctx or not getattr(ctx, "is_valid", False):
        return (None, None)
    trace_id = getattr(ctx, "trace_id", 0)
    span_id = getattr(ctx, "span_id", 0)
    if not trace_id or not span_id:
        return (None, None)
    # OTEL span_context ids are ints; format to the canonical hex width used by
    # OpenInference / Phoenix (32 hex for trace, 16 hex for span).
    return (f"{trace_id:032x}", f"{span_id:016x}")


def _stamp_span_with_acgs(event_hash: str, decision: str) -> None:
    """Best-effort: set acgs.event_hash / acgs.decision on the current span.

    Silent no-op when OTEL is absent, no span is active, or the set_attribute
    call raises for any reason (never let observability degrade governance).
    """
    if _otel_trace is None:
        return
    try:
        span = _otel_trace.get_current_span()
        if span is None:
            return
        ctx = span.get_span_context()
        if not ctx or not getattr(ctx, "is_valid", False):
            return
        span.set_attribute("acgs.event_hash", event_hash)
        span.set_attribute("acgs.decision", decision)
    except Exception:  # pragma: no cover - never let stamping break a call
        return


ALLOW = "ALLOW"
DENY = "DENY"
REQUIRE_HUMAN = "REQUIRE_HUMAN"
REWRITE = "REWRITE"
REDACT = "REDACT"
SOFT_BLOCK_WITH_EXPLANATION = "SOFT_BLOCK_WITH_EXPLANATION"
OPENAI_STYLE_KEY_REGEX = r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_-])"


DEFAULT_CONSTITUTION: dict[str, Any] = {
    "version": 1,
    "name": "hermes-acgs-minimal",
    "description": "Minimal runtime constitution for Hermes tool and output governance.",
    "roles": {
        "proposer": "hermes_agent",
        "validator": "acgs_middleware",
        "executor": "hermes_tool_runtime",
        "observer": "evidence_log_reader",
    },
    "tool_allowlist": ["web_search", "retrieve_doc", "calc"],
    "write_tools": ["send_email", "write_file", "delete_file", "shell", "deploy"],
    "sensitive_operations": ["write", "delete", "transfer", "purchase", "deploy"],
    "risk_domains": ["legal", "medical", "finance"],
    "pii_patterns": [
        {
            "id": "PARAM_PII_GUARD",
            "regex": (
                r"(?i)\b(ssn|sin|social security|password|secret[_-]?key"
                r"|api[_-]?key|private[_-]?key)\b"
            ),
        }
    ],
    "redaction_patterns": [
        {
            "id": "OUTPUT_REDACT_API_KEY_ASSIGNMENT",
            "regex": (
                r"(?i)(api[_-]?key|secret[_-]?key|password)"
                r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{8,}[\"']?"
            ),
            "replacement": "[REDACTED:SECRET]",
        },
        {
            "id": "OUTPUT_REDACT_OPENAI_STYLE_KEY",
            "regex": OPENAI_STYLE_KEY_REGEX,
            "replacement": "[REDACTED:API_KEY]",
        },
    ],
    "final_disclaimer": (
        "This AI-generated output is not a substitute for qualified professional "
        "advice. Human review is required before acting on it."
    ),
    "rules": {
        "pre_tool": [
            {"id": "TOOL_ALLOWLIST", "action": "DENY", "when": "tool not in tool_allowlist"},
            {"id": "PARAM_PII_GUARD", "action": "DENY", "when": "args match pii_patterns"},
            {
                "id": "WRITE_OPERATION_HUMAN_REVIEW",
                "action": "REQUIRE_HUMAN",
                "when": "tool in write_tools or context.operation in sensitive_operations",
            },
        ],
        "post_tool": [
            {
                "id": "OUTPUT_REDACT",
                "action": "REDACT",
                "when": "raw_result matches redaction_patterns",
            }
        ],
        "final_check": [
            {
                "id": "HIGH_RISK_DOMAIN",
                "action": "REQUIRE_HUMAN",
                "when": "context.domain in risk_domains",
            },
            {
                "id": "FINAL_SECRET_GUARD",
                "action": "SOFT_BLOCK_WITH_EXPLANATION",
                "when": "draft_answer matches redaction_patterns",
            },
        ],
    },
}


@dataclass
class GovernanceDecision:
    action: str
    reasons: list[str] = field(default_factory=list)
    policy_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    rewrite_args: dict[str, Any] | None = None
    add_disclaimer: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.action in {DENY, REQUIRE_HUMAN, SOFT_BLOCK_WITH_EXPLANATION}


def _load_json_or_yaml(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8")

    # The included constitution.min.yaml is YAML-compatible JSON so the bundle
    # works without PyYAML. Normal YAML is also supported when PyYAML is present.
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "PyYAML is required for non-JSON YAML constitution files. "
                "Install pyyaml or pass constitution=dict."
            ) from exc
        data = yaml.safe_load(raw)

    if not isinstance(data, dict):
        raise ValueError(f"Constitution must be a mapping, got {type(data).__name__}")
    return data


def _jsonable_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except TypeError:
        return str(value)


def _compile_patterns(
    patterns: list[dict[str, str]] | None,
) -> list[tuple[str, re.Pattern[str], str]]:
    compiled: list[tuple[str, re.Pattern[str], str]] = []
    for index, item in enumerate(patterns or []):
        pattern_id = item.get("id") or f"PATTERN_{index}"
        regex = item["regex"]
        replacement = item.get("replacement", "[REDACTED]")
        compiled.append((pattern_id, re.compile(regex), replacement))
    return compiled


class HermesACGSMiddleware:
    """Runtime governance boundary for Hermes tool calls and final responses."""

    def __init__(
        self,
        *,
        constitution_path: str | Path | None = None,
        constitution: Mapping[str, Any] | None = None,
        evidence_path: str | Path | None = None,
        session_id: str | None = None,
        agent_id: str = "hermes-agent",
        fail_closed: bool = True,
    ) -> None:
        if constitution_path and constitution:
            raise ValueError("Pass either constitution_path or constitution, not both.")

        self.constitution = (
            dict(constitution)
            if constitution is not None
            else _load_json_or_yaml(constitution_path)
            if constitution_path is not None
            else dict(DEFAULT_CONSTITUTION)
        )
        self.agent_id = agent_id
        self.fail_closed = fail_closed
        self.evidence = (
            ChainEvidenceWriter(evidence_path, session_id=session_id)
            if evidence_path
            else None
        )

        self._pii_patterns = _compile_patterns(self.constitution.get("pii_patterns", []))
        self._redaction_patterns = _compile_patterns(
            self.constitution.get("redaction_patterns", [])
        )

    def check_pre_tool(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None,
        *,
        user_msg: str = "",
        context: Mapping[str, Any] | None = None,
    ) -> GovernanceDecision:
        """Validate a planned tool call before execution."""
        args_dict = dict(args or {})
        ctx = dict(context or {})
        payload = {
            "agent": self.agent_id,
            "user_msg": user_msg,
            "planned_tool": tool_name,
            "args": args_dict,
            "context": ctx,
        }

        try:
            decision = self._evaluate_pre_tool(tool_name, args_dict, ctx)
        except Exception as exc:  # fail-closed governance boundary
            decision = GovernanceDecision(
                action=DENY if self.fail_closed else ALLOW,
                reasons=[f"ACGS pre_tool evaluation error: {type(exc).__name__}: {exc}"],
                policy_ids=["ACGS_FAIL_CLOSED"],
                tags=["fail_closed"] if self.fail_closed else ["fail_open"],
            )

        self._audit("pre_tool", tool_name, payload, decision)
        return decision

    def _evaluate_pre_tool(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> GovernanceDecision:
        allowlist = set(self.constitution.get("tool_allowlist", []))
        if allowlist and tool_name not in allowlist:
            return GovernanceDecision(
                action=DENY,
                reasons=[f"Tool '{tool_name}' is not in the constitution allowlist."],
                policy_ids=["TOOL_ALLOWLIST"],
                tags=["tool_not_allowed"],
            )

        args_text = _jsonable_text(args)
        pii_hits = [
            pattern_id
            for pattern_id, pattern, _ in self._pii_patterns
            if pattern.search(args_text)
        ]
        if pii_hits:
            return GovernanceDecision(
                action=DENY,
                reasons=["Tool arguments matched sensitive-data guard patterns."],
                policy_ids=pii_hits,
                tags=["pii_or_secret_in_args"],
            )

        operation = str(context.get("operation", "")).lower()
        write_tools = set(self.constitution.get("write_tools", []))
        sensitive_ops = {
            str(op).lower() for op in self.constitution.get("sensitive_operations", [])
        }
        if tool_name in write_tools or operation in sensitive_ops:
            return GovernanceDecision(
                action=REQUIRE_HUMAN,
                reasons=["Tool call is a write/sensitive operation and requires human approval."],
                policy_ids=["WRITE_OPERATION_HUMAN_REVIEW"],
                tags=["requires_human_review"],
            )

        return GovernanceDecision(action=ALLOW, policy_ids=["ACGS_PRE_TOOL_ALLOW"])

    def check_post_tool(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None,
        raw_result: Any,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> GovernanceDecision:
        """Inspect and transform a raw tool result after execution."""
        ctx = dict(context or {})
        payload = {
            "agent": self.agent_id,
            "tool": tool_name,
            "args": dict(args or {}),
            "raw_result_hashable_text": _jsonable_text(raw_result),
            "context": ctx,
        }

        try:
            decision = self._evaluate_post_tool(raw_result)
        except Exception as exc:
            decision = GovernanceDecision(
                action=DENY if self.fail_closed else ALLOW,
                reasons=[f"ACGS post_tool evaluation error: {type(exc).__name__}: {exc}"],
                policy_ids=["ACGS_FAIL_CLOSED"],
                tags=["fail_closed"] if self.fail_closed else ["fail_open"],
            )

        self._audit("post_tool", tool_name, payload, decision)
        return decision

    def _evaluate_post_tool(self, raw_result: Any) -> GovernanceDecision:
        text = _jsonable_text(raw_result)
        redacted = text
        hits: list[str] = []

        for pattern_id, pattern, replacement in self._redaction_patterns:
            if pattern.search(redacted):
                hits.append(pattern_id)
                redacted = pattern.sub(replacement, redacted)

        if hits:
            return GovernanceDecision(
                action=REDACT,
                reasons=["Tool result contained secret-like material and was redacted."],
                policy_ids=hits,
                tags=["redacted_tool_output"],
                metadata={"redacted_result": redacted},
            )

        return GovernanceDecision(action=ALLOW, policy_ids=["ACGS_POST_TOOL_ALLOW"])

    def check_final(
        self,
        draft_answer: str,
        *,
        citations: list[str] | None = None,
        tool_trace: list[dict[str, Any]] | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> GovernanceDecision:
        """Final response check before user-visible answer is returned."""
        ctx = dict(context or {})
        payload = {
            "agent": self.agent_id,
            "draft_answer": draft_answer,
            "citations": citations or [],
            "tool_trace": tool_trace or [],
            "context": ctx,
        }

        try:
            decision = self._evaluate_final(draft_answer, ctx)
        except Exception as exc:
            decision = GovernanceDecision(
                action=SOFT_BLOCK_WITH_EXPLANATION if self.fail_closed else ALLOW,
                reasons=[f"ACGS final_check evaluation error: {type(exc).__name__}: {exc}"],
                policy_ids=["ACGS_FAIL_CLOSED"],
                tags=["fail_closed"] if self.fail_closed else ["fail_open"],
            )

        self._audit("final_check", "final_answer", payload, decision)
        return decision

    def _evaluate_final(self, draft_answer: str, context: Mapping[str, Any]) -> GovernanceDecision:
        domain = str(context.get("domain") or context.get("risk_domain") or "").lower()
        risk_domains = {str(item).lower() for item in self.constitution.get("risk_domains", [])}

        secret_hits = [
            pattern_id
            for pattern_id, pattern, _ in self._redaction_patterns
            if pattern.search(draft_answer)
        ]
        if secret_hits:
            return GovernanceDecision(
                action=SOFT_BLOCK_WITH_EXPLANATION,
                reasons=["Draft answer appears to contain secret-like material."],
                policy_ids=["FINAL_SECRET_GUARD", *secret_hits],
                tags=["secret_in_final_answer"],
            )

        if domain in risk_domains:
            return GovernanceDecision(
                action=REQUIRE_HUMAN,
                reasons=[f"Domain '{domain}' is high risk and requires human review."],
                policy_ids=["HIGH_RISK_DOMAIN"],
                tags=["high_risk_domain"],
                add_disclaimer=True,
                metadata={"disclaimer": self.constitution.get("final_disclaimer")},
            )

        return GovernanceDecision(action=ALLOW, policy_ids=["ACGS_FINAL_ALLOW"])

    def apply_post_action(self, raw_result: Any, decision: GovernanceDecision) -> Any:
        if decision.action == REDACT:
            return decision.metadata.get("redacted_result", "[REDACTED]")
        return raw_result

    def apply_final_action(self, draft_answer: str, decision: GovernanceDecision) -> str:
        if decision.action == ALLOW:
            return draft_answer

        if decision.action == REQUIRE_HUMAN:
            # Do NOT include draft_answer here — it must not reach the end-user before
            # a human reviewer approves it.  The draft is available to a reviewer-side
            # channel via the GovernanceDecision object returned by check_final().
            prefix = "Human review required before this answer is released."
            disclaimer = decision.metadata.get("disclaimer") if decision.add_disclaimer else None
            if disclaimer:
                return f"{prefix}\n\n{disclaimer}"
            return prefix

        if decision.action == SOFT_BLOCK_WITH_EXPLANATION:
            reason_text = (
                "; ".join(decision.reasons)
                or "Governance policy blocked the final answer."
            )
            return f"I cannot release this answer as written. Reason: {reason_text}"

        if decision.action == DENY:
            return self.user_friendly_explain(decision)

        return draft_answer

    def call_tool_with_governance(
        self,
        executor: Callable[[str, Mapping[str, Any]], Any],
        tool_name: str,
        args: Mapping[str, Any] | None,
        *,
        user_msg: str = "",
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convenience wrapper for synchronous Hermes-like tool executors."""
        pre = self.check_pre_tool(tool_name, args or {}, user_msg=user_msg, context=context)
        if pre.is_blocking:
            return {
                "ok": False,
                "stage": "pre_tool",
                "decision": pre,
                "message": self.user_friendly_explain(pre),
            }

        effective_args = pre.rewrite_args or dict(args or {})
        raw_result = executor(tool_name, effective_args)
        post = self.check_post_tool(tool_name, effective_args, raw_result, context=context)
        if post.action == DENY:
            return {
                "ok": False,
                "stage": "post_tool",
                "decision": post,
                "message": self.user_friendly_explain(post),
            }

        return {
            "ok": True,
            "stage": "complete",
            "pre_decision": pre,
            "post_decision": post,
            "result": self.apply_post_action(raw_result, post),
        }

    def user_friendly_explain(self, decision: GovernanceDecision) -> str:
        reasons = "; ".join(decision.reasons) if decision.reasons else "No reason provided."
        policies = ", ".join(decision.policy_ids) if decision.policy_ids else "unclassified_policy"
        return (
            f"ACGS blocked or paused this action. Decision={decision.action}. "
            f"Policies={policies}. Reason={reasons}"
        )

    def _audit(
        self,
        hook: str,
        subject: str,
        input_payload: Any,
        decision: GovernanceDecision,
    ) -> dict[str, Any] | None:
        if not self.evidence:
            # No persistent audit — still stamp the span so operators can see
            # the decision in Phoenix even when running evidence-less.
            # Defensive wrap: observability must NEVER break governance, even
            # if a downstream plugin monkeypatches the stamper to raise.
            try:
                _stamp_span_with_acgs(event_hash="", decision=decision.action)
            except Exception:
                pass
            return None

        # Build audit metadata. If an OpenTelemetry span is active, fold its
        # trace_id/span_id into the metadata so the ACGS row deterministically
        # binds to the observability trace. These become part of the canonical
        # event body that feeds event_hash, which is intentional: the binding
        # is now part of the tamper-evident record, not a side channel.
        metadata: dict[str, Any] = {
            "agent_id": self.agent_id,
            "add_disclaimer": decision.add_disclaimer,
            "decision_metadata": decision.metadata,
        }
        # Defensive wrap: a broken OTEL SDK must not block the audit write.
        try:
            trace_id, span_id = _current_otel_ids()
        except Exception:
            trace_id, span_id = (None, None)
        if trace_id and span_id:
            metadata["trace_id"] = trace_id
            metadata["span_id"] = span_id

        event = self.evidence.append_event(
            hook=hook,
            subject=subject,
            input_payload=input_payload,
            decision=decision.action,
            reasons=decision.reasons,
            policy_ids=decision.policy_ids,
            tags=decision.tags,
            actor_role="validator",
            metadata=metadata,
        )

        # Best-effort: stamp the Phoenix/OpenInference span with the real
        # event_hash so the trace carries a pointer back to the authoritative
        # record. Never let a stamping failure break governance — the
        # authoritative record has already been persisted above.
        event_hash = event.get("event_hash", "") if isinstance(event, dict) else ""
        try:
            _stamp_span_with_acgs(event_hash=event_hash, decision=decision.action)
        except Exception:
            pass

        return event
