"""Principal authorization for the governed kernel (B13, first slice).

A minimal, fail-closed authorization seam: a registry of agent *principals* and
the tools each may invoke, plus an ``AUTHZ_ENFORCE`` kill-switch read once at
kernel construction. When enforcement is OFF (the default) the kernel behaves
byte-for-byte as before; when ON, a dispatch whose actor is not a registered,
tool-authorized principal is denied *before* policy evaluation and audited.

Scope (first slice): this authorizes the integrator-set ``Kernel.actor`` only —
a per-kernel identity, not a per-call claim (a request must never assert its own
identity; that is a spoofing vector, deferred). Roles, delegation, aggregation,
and trace policies (R2, R4-R7 of AUTHZ-ROADMAP.md) are out of scope here; this
delivers R1 (first-class principals) and the named R3 enforcement seam.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class AuthzRegistryError(Exception):
    """Raised when a principal registry cannot be loaded — fail-closed.

    A registry that cannot be read or parsed must never degrade into a
    permissive (empty) registry; loading raises instead.
    """


class AuthzReason(StrEnum):
    """Machine-readable reason codes for an authorization denial.

    Serialised into a ``DecisionRecord.matched_rules`` entry as
    ``AUTHZ_DENY:<reason>`` so a relying party asserts on the code, not the
    human message. Mirrors :class:`acgs_proofpack_verifier.errors.ReceiptRejectionReason`.
    """

    UNREGISTERED_PRINCIPAL = "UNREGISTERED_PRINCIPAL"
    TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"


@dataclass(frozen=True)
class PrincipalEntry:
    """One authorized principal: an id and the tools it may invoke.

    ``allowed_tools=None`` authorizes every tool; an empty frozenset authorizes
    none. Roles/boundaries are intentionally omitted from the first slice.
    """

    principal_id: str
    allowed_tools: frozenset[str] | None = None


class PrincipalRegistry:
    """An in-memory set of authorized principals.

    Lookups are exact-match and fail-closed: an unknown principal, or a tool
    outside a known principal's ``allowed_tools``, is unauthorized.
    """

    def __init__(self) -> None:
        self._entries: dict[str, PrincipalEntry] = {}

    def add(self, entry: PrincipalEntry) -> None:
        if entry.principal_id in self._entries:
            raise ValueError(f"principal already registered: {entry.principal_id!r}")
        self._entries[entry.principal_id] = entry

    def authorize(self, principal_id: str, tool_name: str) -> AuthzReason | None:
        """Return ``None`` if *principal_id* may invoke *tool_name*, else the
        specific :class:`AuthzReason` for the denial."""
        entry = self._entries.get(principal_id)
        if entry is None:
            return AuthzReason.UNREGISTERED_PRINCIPAL
        if entry.allowed_tools is not None and tool_name not in entry.allowed_tools:
            return AuthzReason.TOOL_NOT_PERMITTED
        return None

    @classmethod
    def from_json(cls, path: str | Path) -> PrincipalRegistry:
        """Load a registry from JSON: ``[{"principal_id": str, "allowed_tools": [str]|null}]``.

        Fail-closed: any read, parse, or shape error raises
        :class:`AuthzRegistryError` rather than yielding a permissive registry.
        """
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AuthzRegistryError(f"cannot load principal registry at {path}: {exc}") from exc
        if not isinstance(raw, list):
            raise AuthzRegistryError("principal registry must be a JSON array of entries")
        registry = cls()
        for item in raw:
            if not isinstance(item, dict) or "principal_id" not in item:
                raise AuthzRegistryError(f"malformed principal entry: {item!r}")
            tools = item.get("allowed_tools")
            if tools is None:
                allowed: frozenset[str] | None = None
            elif isinstance(tools, list) and all(isinstance(t, str) for t in tools):
                allowed = frozenset(tools)
            else:
                raise AuthzRegistryError(
                    f"allowed_tools must be a list of strings or null, got {tools!r}"
                )
            try:
                registry.add(
                    PrincipalEntry(principal_id=str(item["principal_id"]), allowed_tools=allowed)
                )
            except ValueError as exc:  # duplicate principal_id -> fail closed
                raise AuthzRegistryError(str(exc)) from exc
        return registry


def authz_enforce_from_env(default: bool = False) -> bool:
    """Resolve the ``AUTHZ_ENFORCE`` kill-switch from the environment.

    Truthy values (``1``/``true``/``yes``/``on``, case-insensitive) enable
    enforcement; anything else (including unset) returns *default*. Read this
    once at kernel construction — never in the dispatch hot path.
    """
    value = os.environ.get("AUTHZ_ENFORCE")
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
