"""Owner-controlled tool side-effect classification.

The registry is configuration supplied by the embedding runtime, not data
derived from an observed bus message.  Unknown tools remain unknown so an
untrusted payload cannot self-declare that execution is read-only.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from agent_bus_analyzer.process_mining.schemas.process_event import SideEffectClassification


class TrustedToolEffectRegistry:
    """Immutable owner-controlled mapping from exact tool names to effects."""

    __slots__ = ("_classifications",)

    def __init__(
        self,
        classifications: Mapping[str, SideEffectClassification] | None = None,
    ) -> None:
        trusted: dict[str, SideEffectClassification] = {}
        for tool_name, classification in (classifications or {}).items():
            if not isinstance(tool_name, str) or not tool_name.strip():
                raise ValueError("trusted tool names must be non-empty strings")
            if not isinstance(classification, SideEffectClassification):
                raise TypeError("trusted tool classifications must use SideEffectClassification")
            trusted[tool_name] = classification
        self._classifications: Mapping[str, SideEffectClassification] = MappingProxyType(trusted)

    def classify(self, tool_name: str | None) -> SideEffectClassification:
        """Return the trusted exact-name classification, or fail closed unknown."""
        if tool_name is None:
            return SideEffectClassification.UNKNOWN
        return self._classifications.get(tool_name, SideEffectClassification.UNKNOWN)
