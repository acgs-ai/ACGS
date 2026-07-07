"""Tool registry and tool-call schema.

A ``ToolCall`` is the structured payload the kernel evaluates. A
``ToolRegistry`` maps a tool name to a callable that produces the side effect.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from gove_zone.decision import sha256_json


def normalize_path_context(path: str | Sequence[str] | None = None) -> tuple[str, ...]:
    """Normalize a runtime path/context into canonical path segments.

    The "path" in policies-on-paths is broader than a filesystem path: it can
    be a tenant/matter/resource chain, a repo path, or a workflow lane. Strings
    are split on ``/`` (and ``\\`` for host-runtime file paths); sequences are
    stringified segment-by-segment. Empty segments are discarded so callers can
    pass ``"/tenant/matter"`` and ``("tenant", "matter")`` interchangeably.
    """
    if path is None:
        return ()
    if isinstance(path, str):
        raw_segments = path.replace("\\", "/").split("/")
    else:
        raw_segments = [str(segment) for segment in path]
    return tuple(segment for segment in (s.strip() for s in raw_segments) if segment)


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A proposed tool invocation.

    ``args`` is stored by reference and MUST be treated as frozen by every
    consumer: the dataclass blocks field rebinding, but nothing deep-copies
    or proxy-wraps the mapping, so mutating it (or a nested value) after
    construction violates the contract. The memoized hashes below record the
    args *as first observed/authorized*; the kernel's post-execution failure
    path (``Kernel._record_execution_failure``) deliberately recomputes the
    hash fresh so a mid-flight mutation still surfaces as an audit-trail
    divergence. ``goal`` is the caller's high-level intent — opaque to the
    kernel, available to policies that want to reason about purpose.

    ``actor``, ``path``, and ``state`` make the call compatible with
    policies-on-paths: policies can evaluate who is acting, where in the
    workflow/resource path they are acting, and which organizational state was
    known before the side effect.
    """

    name: str
    args: Mapping[str, Any] = field(default_factory=dict)
    goal: str = ""
    actor: str = ""
    path: tuple[str, ...] = ()
    state: Mapping[str, Any] = field(default_factory=dict)
    # Per-instance memo for the canonical-JSON hashes below. A slot of its own
    # because slots=True removes __dict__; mutating the dict's contents is
    # legal on a frozen instance. Excluded from eq/repr, and never carried to
    # a new instance (init=False → re-defaulted by with_args / replace).
    _hash_cache: dict[str, str] = field(default_factory=dict, init=False, repr=False, compare=False)

    def with_args(self, args: Mapping[str, Any]) -> ToolCall:
        """Return a new ToolCall with the same context but replaced args.

        Used by the kernel after a TRANSFORM decision to re-canonicalize.
        """
        return ToolCall(
            name=self.name,
            args=args,
            goal=self.goal,
            actor=self.actor,
            path=self.path,
            state=self.state,
        )

    def argument_hash(self) -> str:
        """Hash only the proposed tool arguments.

        Memoized: a single dispatch hashes the same args several times (policy
        record, kernel context, decision-request binding), so the canonical
        JSON + SHA-256 is computed once per ``ToolCall`` instance. Every args
        replacement goes through :meth:`with_args` (a new instance, fresh
        cache). The value is therefore the hash of the args *as first
        observed*: a caller that violates the treat-as-frozen contract above
        by mutating the mapping mid-evaluation gets the first-observation
        hash from this method — the kernel's post-execution failure record
        recomputes fresh precisely so that divergence stays detectable.
        """
        cached = self._hash_cache.get("args")
        if cached is None:
            cached = sha256_json(dict(self.args))
            self._hash_cache["args"] = cached
        return cached

    def state_hash(self) -> str | None:
        """Hash organizational/runtime state when supplied. Memoized like
        :meth:`argument_hash`."""
        if not self.state:
            return None
        cached = self._hash_cache.get("state")
        if cached is None:
            cached = sha256_json(dict(self.state))
            self._hash_cache["state"] = cached
        return cached

    def decision_request_hash(self) -> str:
        """Hash the full pre-execution decision request.

        This hash binds actor + path + goal + tool + argument hash + state
        hash without storing potentially large/sensitive state inline.

        Note: the kernel derives this hash from the policy-supplied
        ``DecisionRecord.argument_hash`` (all built-in policies set it to
        ``sha256_json(dict(call.args))``); a custom policy that emits a
        divergent argument_hash will see that value bound here, keeping the
        decision request consistent with the receipt's stored argument_hash.
        """
        return self._decision_request_hash(self.argument_hash())

    def _decision_request_hash(self, argument_hash: str) -> str:
        """Build the decision-request hash from a precomputed argument hash.

        Factored out so a caller that already holds this call's argument hash
        (e.g. the kernel, from ``record.argument_hash``) can avoid recomputing
        it. The public :meth:`decision_request_hash` delegates here with a
        freshly computed hash, so both produce byte-identical output.
        Memoized per *argument_hash* like :meth:`argument_hash`.
        """
        cache_key = f"drh:{argument_hash}"
        cached = self._hash_cache.get(cache_key)
        if cached is None:
            cached = sha256_json(
                {
                    "actor": self.actor,
                    "path": list(self.path),
                    "goal": self.goal,
                    "tool": self.name,
                    "argument_hash": argument_hash,
                    "state_hash": self.state_hash(),
                }
            )
            self._hash_cache[cache_key] = cached
        return cached


class ToolRegistry:
    """Simple name → callable registry. Single registration per name."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        """Register *fn* under *name*. Raises if *name* is already registered."""
        if name in self._tools:
            raise ValueError(f"tool already registered: {name!r}")
        self._tools[name] = fn

    def get(self, name: str) -> Callable[..., Any]:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name!r}")
        return self._tools[name]

    def has(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def __len__(self) -> int:
        return len(self._tools)
