"""Factories that route a backend name to an implementation via lazy imports.

Only the selected provider's SDK is imported, and only when constructed — so
``import delve`` never pulls in ``anthropic`` / ``exa_py`` / ``tavily``. Missing
optional deps surface as a clear, actionable :class:`ImportError`.
"""

from __future__ import annotations

from typing import Any

from delve.backends.base import LLMClient, SearchClient

_LLM_BACKENDS = ("fake", "anthropic")
_SEARCH_BACKENDS = ("fake", "exa", "tavily")


def available_llm_backends() -> tuple[str, ...]:
    return _LLM_BACKENDS


def available_search_backends() -> tuple[str, ...]:
    return _SEARCH_BACKENDS


def make_llm(name: str, **kwargs: Any) -> LLMClient:
    key = name.lower()
    if key == "fake":
        from delve.backends.fakes import FakeLLMClient

        return FakeLLMClient(**kwargs)
    if key == "anthropic":
        try:
            from delve.backends.adapters.anthropic_llm import AnthropicLLM
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "The 'anthropic' LLM backend requires the optional dependency. "
                "Install it with: pip install 'delve[anthropic]'"
            ) from exc
        return AnthropicLLM(**kwargs)
    raise ValueError(f"Unknown LLM backend {name!r}. Available: {', '.join(_LLM_BACKENDS)}")


def make_search(name: str, **kwargs: Any) -> SearchClient:
    key = name.lower()
    if key == "fake":
        from delve.backends.fakes import FakeSearchClient

        return FakeSearchClient(**kwargs)
    if key == "exa":
        try:
            from delve.backends.adapters.exa_search import ExaSearch
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'exa' search backend requires the optional dependency. "
                "Install it with: pip install 'delve[exa]'"
            ) from exc
        return ExaSearch(**kwargs)
    if key == "tavily":
        try:
            from delve.backends.adapters.tavily_search import TavilySearch
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'tavily' search backend requires the optional dependency. "
                "Install it with: pip install 'delve[tavily]'"
            ) from exc
        return TavilySearch(**kwargs)
    raise ValueError(f"Unknown search backend {name!r}. Available: {', '.join(_SEARCH_BACKENDS)}")
