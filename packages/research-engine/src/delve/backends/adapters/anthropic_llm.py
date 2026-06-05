"""Anthropic-backed :class:`LLMClient`.

The ``anthropic`` SDK is imported lazily inside ``__init__``. A pre-built
``client`` may be injected for testing without the SDK installed.
"""

from __future__ import annotations

from typing import Any

from delve.backends.base import LLMClient, estimate_tokens

_DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicLLM(LLMClient):
    def __init__(
        self,
        *,
        model: str = _DEFAULT_MODEL,
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        super().__init__()
        self.model = model
        if client is not None:
            self._client = client
        else:
            import anthropic

            self._client = (
                anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
            )

    def complete(self, prompt: str, *, system: str | None = None, max_tokens: int = 1024) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        response = self._client.messages.create(**kwargs)

        text = "".join(getattr(block, "text", "") for block in getattr(response, "content", []))
        usage = getattr(response, "usage", None)
        in_tokens = int(getattr(usage, "input_tokens", estimate_tokens(prompt)))
        out_tokens = int(getattr(usage, "output_tokens", estimate_tokens(text)))
        self._record_usage(self.model, in_tokens, out_tokens)
        return text
