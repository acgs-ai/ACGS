"""Pluggable LLM and search backends.

The orchestration core depends only on the abstract :class:`LLMClient` and
:class:`SearchClient` contracts. Concrete providers are constructed through the
:func:`make_llm` / :func:`make_search` factories, which lazily import provider
SDKs only when that provider is selected — so installing delve with no extras
still runs the full engine against the deterministic fakes.
"""

from delve.backends.base import (
    LLMClient,
    SearchClient,
    SearchHit,
    SupportsUsage,
    estimate_tokens,
)
from delve.backends.factory import (
    available_llm_backends,
    available_search_backends,
    make_llm,
    make_search,
)
from delve.backends.fakes import FakeLLMClient, FakeSearchClient

__all__ = [
    "LLMClient",
    "SearchClient",
    "SearchHit",
    "SupportsUsage",
    "estimate_tokens",
    "make_llm",
    "make_search",
    "available_llm_backends",
    "available_search_backends",
    "FakeLLMClient",
    "FakeSearchClient",
]
