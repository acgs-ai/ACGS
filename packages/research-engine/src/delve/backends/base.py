"""Abstract backend contracts and shared types.

- :class:`LLMClient` and :class:`SearchClient` are ABCs: every backend MUST
  implement them.
- :class:`SupportsUsage` is a runtime-checkable Protocol: an OPTIONAL capability
  a backend may opt into (token/usage accounting). The orchestrator checks for
  it rather than requiring it.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from delve.domain import Citation


def estimate_tokens(text: str) -> int:
    """Cheap, deterministic token estimate (~4 chars/token). Used by fakes and
    as a fallback when a provider does not report usage."""
    return max(1, len(text) // 4)


@dataclass(frozen=True, slots=True)
class SearchHit:
    """A single result from a search backend; bridges to a graph Citation."""

    url: str
    title: str = ""
    snippet: str = ""
    source: str = ""
    score: float = 0.0

    def to_citation(self, *, retrieved_at: str | None = None) -> Citation:
        return Citation(
            url=self.url,
            title=self.title,
            source=self.source,
            snippet=self.snippet,
            retrieved_at=retrieved_at,
        )


@runtime_checkable
class SupportsUsage(Protocol):
    """Optional capability: report per-model call/token accounting."""

    def get_usage_summary(self) -> dict[str, Any]: ...


class LLMClient(ABC):
    """Text-completion contract with built-in usage accounting.

    Subclasses implement :meth:`complete` and call :meth:`_record_usage` so the
    whole system can report cost via :meth:`get_usage_summary` (satisfies
    :class:`SupportsUsage`).
    """

    def __init__(self) -> None:
        self._total_calls = 0
        self._usage: dict[str, dict[str, int]] = {}
        self._usage_lock = threading.Lock()

    @abstractmethod
    def complete(self, prompt: str, *, system: str | None = None, max_tokens: int = 1024) -> str:
        """Return a text completion for ``prompt``."""

    def _record_usage(self, model: str, input_tokens: int, output_tokens: int) -> None:
        # Locked so usage stays correct if LLM ops are ever fanned out concurrently.
        with self._usage_lock:
            self._total_calls += 1
            bucket = self._usage.setdefault(
                model, {"calls": 0, "input_tokens": 0, "output_tokens": 0}
            )
            bucket["calls"] += 1
            bucket["input_tokens"] += input_tokens
            bucket["output_tokens"] += output_tokens

    def get_usage_summary(self) -> dict[str, Any]:
        with self._usage_lock:
            return {
                "total_calls": self._total_calls,
                "by_model": {model: dict(stats) for model, stats in self._usage.items()},
            }


class SearchClient(ABC):
    """Web/search contract. Implementations return ranked :class:`SearchHit`s."""

    @abstractmethod
    def search(self, query: str, *, limit: int = 5) -> list[SearchHit]:
        """Return up to ``limit`` hits for ``query``."""
