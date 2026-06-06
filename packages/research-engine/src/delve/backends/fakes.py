"""Deterministic, offline fakes for the backend contracts.

These let the full engine run in tests with zero network and zero API keys.
Both fakes are programmable (substring routing or a callable) and record their
calls for assertions.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from delve.backends.base import LLMClient, SearchClient, SearchHit, estimate_tokens


class FakeLLMClient(LLMClient):
    """A scriptable LLM.

    Resolution order for a prompt: an explicit ``responder`` callable wins;
    otherwise the first key in ``responses`` that is a substring of the prompt
    (insertion order); otherwise ``default``.
    """

    def __init__(
        self,
        *,
        responder: Callable[[str, str | None], str] | None = None,
        responses: Mapping[str, str] | None = None,
        default: str = "",
        model: str = "fake-llm",
    ) -> None:
        super().__init__()
        self.model = model
        self._responder = responder
        self._responses = dict(responses or {})
        self._default = default
        self.calls: list[dict[str, str | None]] = []

    def complete(self, prompt: str, *, system: str | None = None, max_tokens: int = 1024) -> str:
        if self._responder is not None:
            out = self._responder(prompt, system)
        else:
            out = self._default
            for needle, resp in self._responses.items():
                if needle in prompt:
                    out = resp
                    break
        self.calls.append({"prompt": prompt, "system": system})
        self._record_usage(
            self.model, estimate_tokens(prompt + (system or "")), estimate_tokens(out)
        )
        return out


class FakeSearchClient(SearchClient):
    """A scriptable search backend.

    Returns the hits for the first key in ``hits`` that is a substring of the
    query (insertion order), else ``default``.
    """

    def __init__(
        self,
        *,
        hits: Mapping[str, Sequence[SearchHit]] | None = None,
        default: Sequence[SearchHit] | None = None,
        source: str = "fake",
    ) -> None:
        self._hits = {k: list(v) for k, v in (hits or {}).items()}
        self._default = list(default or [])
        self.source = source
        self.calls: list[str] = []

    def search(self, query: str, *, limit: int = 5) -> list[SearchHit]:
        self.calls.append(query)
        result = self._default
        for needle, hs in self._hits.items():
            if needle in query:
                result = hs
                break
        return list(result[:limit])
