"""Policy ABC and concrete policy implementations.

A :class:`Policy` produces a :class:`~gove_zone.decision.DecisionRecord` from
a :class:`~gove_zone.tool.ToolCall`. The kernel calls ``policy.evaluate(call)``
exactly once per dispatch and appends the result to the audit chain before
any side effect runs.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence

from gove_zone.decision import (
    Decision,
    DecisionRecord,
    canonical_json,
    sha256_json,
)
from gove_zone.tool import ToolCall


def new_event_id() -> str:
    """Generate a 16-hex-char event id prefixed with ``ev_``."""
    return f"ev_{uuid.uuid4().hex[:16]}"


class Policy(ABC):
    """Abstract policy. Subclasses implement :meth:`evaluate`."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Stable identifier for this policy instance.

        Two policies with the same version MUST produce the same decision for
        the same input — that's what makes replay meaningful.
        """

    @abstractmethod
    def evaluate(self, call: ToolCall) -> DecisionRecord:
        """Decide what to do about *call*. Must not raise on policy-internal
        errors — return a DENY record instead. The kernel's fail-closed
        wrapper catches any leaked exception and converts it to a DENY.
        """


class AllowAllPolicy(Policy):
    """Allows every call. Useful only in tests."""

    @property
    def version(self) -> str:
        return "allow-all/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            reason="allow-all policy",
        )


class DenyAllPolicy(Policy):
    """Denies every call. Useful for kill-switches and tests."""

    def __init__(self, reason: str = "deny-all policy") -> None:
        self._reason = reason

    @property
    def version(self) -> str:
        return "deny-all/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("DENY_ALL",),
            reason=self._reason,
        )


class BoundaryPolicy(Policy):
    """Hard-deny when the canonical-JSON of the args matches a forbidden
    keyword (substring, case-insensitive) or regex pattern.

    Generalized from ``acgs-lite/src/acgs_lite/constitution/boundaries.py``
    to operate on the structured tool-call arguments rather than free-text
    actions — keywords and patterns now match against
    ``canonical_json(call.args)``.
    """

    def __init__(
        self,
        *,
        forbidden_keywords: Sequence[str] = (),
        forbidden_patterns: Sequence[str] = (),
        rule_id: str = "BOUNDARY",
        only_tools: Sequence[str] | None = None,
    ) -> None:
        self._keywords = tuple(k.lower() for k in forbidden_keywords)
        self._patterns = tuple(
            re.compile(p, re.IGNORECASE) for p in forbidden_patterns
        )
        self._raw_patterns = tuple(forbidden_patterns)
        self._rule_id = rule_id
        self._only_tools = (
            None if only_tools is None else frozenset(only_tools)
        )
        self._version = self._compute_version()

    def _compute_version(self) -> str:
        h = hashlib.sha256()
        h.update(canonical_json(list(self._keywords)).encode())
        h.update(b"|")
        h.update(canonical_json(list(self._raw_patterns)).encode())
        h.update(b"|")
        h.update(self._rule_id.encode())
        h.update(b"|")
        only = sorted(self._only_tools) if self._only_tools else []
        h.update(canonical_json(only).encode())
        return f"boundary/{h.hexdigest()[:16]}"

    @property
    def version(self) -> str:
        return self._version

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        if self._only_tools is not None and call.name not in self._only_tools:
            return DecisionRecord(
                decision=Decision.ALLOW,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version=self.version,
                event_id=new_event_id(),
                reason=f"out of scope for {self._rule_id}",
            )

        canonical = canonical_json(dict(call.args))
        lower = canonical.lower()
        matched: list[str] = []
        for kw in self._keywords:
            if kw in lower:
                matched.append(f"{self._rule_id}:keyword:{kw}")
        for pat in self._patterns:
            if pat.search(canonical):
                matched.append(f"{self._rule_id}:pattern:{pat.pattern}")

        decision = Decision.DENY if matched else Decision.ALLOW
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(matched),
            reason=(
                f"matched {len(matched)} boundary rule(s)"
                if matched
                else "no boundary match"
            ),
        )


class CompositePolicy(Policy):
    """Run N policies in order; first non-ALLOW wins.

    The returned record's ``policy_version`` is set to this composite's own
    version (``+``-joined member versions) so replay against the composite is
    stable.
    """

    def __init__(self, policies: Sequence[Policy]) -> None:
        if not policies:
            raise ValueError("CompositePolicy requires at least one policy")
        self._policies = tuple(policies)
        self._version = "composite[" + "+".join(p.version for p in policies) + "]"

    @property
    def version(self) -> str:
        return self._version

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        last: DecisionRecord | None = None
        for p in self._policies:
            record = p.evaluate(call)
            last = record
            if record.decision is not Decision.ALLOW:
                return dataclasses.replace(record, policy_version=self.version)
        assert last is not None  # at least one policy enforced in __init__
        return dataclasses.replace(
            last,
            policy_version=self.version,
            reason=f"all {len(self._policies)} policies allowed",
        )
