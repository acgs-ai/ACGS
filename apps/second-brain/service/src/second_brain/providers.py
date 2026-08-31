import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx


class ProviderUnavailable(RuntimeError):
    pass


class EmbeddingProvider(Protocol):
    @property
    def status(self) -> str: ...
    @property
    def dimensions(self) -> int: ...
    @property
    def model_identifier(self) -> str: ...
    @property
    def profile_version(self) -> int: ...
    def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]: ...


class GenerationProvider(Protocol):
    @property
    def status(self) -> str: ...
    @property
    def model_identifier(self) -> str: ...
    def generate(
        self,
        system_prompt: str,
        user_payload: str | None = None,
        *,
        deadline: float | None = None,
    ) -> str: ...


@dataclass(frozen=True)
class FakeEmbeddingProvider:
    dimensions: int = 8
    status: str = "available"
    model_identifier: str = "deterministic-sha256-v1"
    profile_version: int = 1

    def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
        if deadline is not None and deadline <= time.monotonic():
            raise ProviderUnavailable("embedding provider unavailable")
        vectors: list[list[float]] = []
        for value in texts:
            material = bytearray(hashlib.sha256(value.encode()).digest())
            counter = 1
            while len(material) < self.dimensions:
                material.extend(hashlib.sha256(f"{counter}:{value}".encode()).digest())
                counter += 1
            vectors.append([byte / 255 for byte in material[: self.dimensions]])
        return vectors


@dataclass(frozen=True)
class UnavailableEmbeddingProvider:
    dimensions: int = 0
    status: str = "unavailable"
    model_identifier: str = "unavailable"
    profile_version: int = 1

    def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
        del texts, deadline
        raise ProviderUnavailable("embedding provider unavailable")


@dataclass(frozen=True)
class FakeGenerationProvider:
    response: str = "Insufficient evidence."
    status: str = "available"
    model_identifier: str = "deterministic-fake-generation-v1"

    def generate(
        self,
        system_prompt: str,
        user_payload: str | None = None,
        *,
        deadline: float | None = None,
    ) -> str:
        del system_prompt
        if deadline is not None and deadline <= time.monotonic():
            raise ProviderUnavailable("generation provider unavailable")
        if self.response == "Insufficient evidence." and user_payload is not None:
            try:
                payload = json.loads(user_payload)
                evidence = payload["evidence"]
                first = evidence[0]
                chunk_id = first["chunk_id"]
                content = first["content"]
                if not isinstance(chunk_id, str) or not isinstance(content, str):
                    raise TypeError
            except (IndexError, KeyError, TypeError, json.JSONDecodeError):
                return json.dumps(
                    {
                        "sufficient": False,
                        "reason_code": "no_retrieved_evidence",
                        "statements": [],
                    }
                )
            return json.dumps(
                {
                    "sufficient": True,
                    "reason_code": "supported_by_selected_evidence",
                    "statements": [
                        {
                            "text": content,
                            "citations": [{"chunk_id": chunk_id}],
                        }
                    ],
                }
            )
        return self.response


@dataclass(frozen=True)
class UnavailableGenerationProvider:
    status: str = "unavailable"
    model_identifier: str = "unavailable"

    def generate(
        self,
        system_prompt: str,
        user_payload: str | None = None,
        *,
        deadline: float | None = None,
    ) -> str:
        del system_prompt, user_payload, deadline
        raise ProviderUnavailable("generation provider unavailable")


class _RetryableProviderError(RuntimeError):
    pass


def _remaining_timeout(deadline: float | None, configured_timeout: float) -> float:
    if deadline is None:
        return configured_timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProviderUnavailable("model provider unavailable")
    return min(configured_timeout, remaining)


def _read_json_response(response: httpx.Response, max_response_bytes: int) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise ProviderUnavailable("model provider unavailable")
    if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
        raise ProviderUnavailable("model provider unavailable")
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_response_bytes:
                raise ProviderUnavailable("model provider unavailable")
        except ValueError:
            raise ProviderUnavailable("model provider unavailable") from None
    body = bytearray()
    chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
    for chunk in chunks:
        body.extend(chunk)
        if len(body) > max_response_bytes:
            raise ProviderUnavailable("model provider unavailable")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderUnavailable("model provider unavailable") from None
    if not isinstance(value, dict):
        raise ProviderUnavailable("model provider unavailable")
    return value


def _post_json(
    url: str,
    api_key: str,
    payload: dict[str, Any],
    *,
    timeout: float,
    retries: int,
    deadline: float | None,
    max_request_bytes: int,
    max_response_bytes: int,
    transport: httpx.BaseTransport | None,
    backoff_seconds: float,
) -> dict[str, Any]:
    try:
        request_body = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    except (TypeError, ValueError):
        raise ProviderUnavailable("model provider unavailable") from None
    if len(request_body) > max_request_bytes:
        raise ProviderUnavailable("model provider unavailable")

    for attempt in range(retries + 1):
        attempt_timeout = _remaining_timeout(deadline, timeout)
        try:
            with (
                httpx.Client(
                    trust_env=False,
                    follow_redirects=False,
                    timeout=attempt_timeout,
                    transport=transport,
                ) as client,
                client.stream(
                    "POST",
                    url,
                    headers={
                        "authorization": f"Bearer {api_key}",
                        "content-type": "application/json",
                        "accept": "application/json",
                        "accept-encoding": "identity",
                    },
                    content=request_body,
                ) as response,
            ):
                if response.status_code in {408, 429} or 500 <= response.status_code <= 599:
                    raise _RetryableProviderError
                if response.status_code < 200 or response.status_code >= 300:
                    raise ProviderUnavailable("model provider unavailable")
                return _read_json_response(response, max_response_bytes)
        except ProviderUnavailable:
            raise
        except (httpx.TransportError, _RetryableProviderError):
            if attempt >= retries:
                raise ProviderUnavailable("model provider unavailable") from None
            delay = backoff_seconds * (2**attempt)
            if deadline is not None and time.monotonic() + delay >= deadline:
                raise ProviderUnavailable("model provider unavailable") from None
            if delay:
                time.sleep(delay)
    raise ProviderUnavailable("model provider unavailable")


class OpenAICompatibleEmbeddingProvider:
    status = "available"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        dimensions: int,
        *,
        profile_version: int = 1,
        timeout: float = 10,
        retries: int = 2,
        max_request_bytes: int = 2_000_000,
        max_response_bytes: int = 8_000_000,
        transport: httpx.BaseTransport | None = None,
        backoff_seconds: float = 0.1,
    ) -> None:
        self.base_url, self.api_key, self.model_identifier, self.dimensions = (
            base_url.rstrip("/"),
            api_key,
            model,
            dimensions,
        )
        self.profile_version = profile_version
        self.timeout, self.retries = timeout, retries
        self.max_request_bytes, self.max_response_bytes = max_request_bytes, max_response_bytes
        self.transport, self.backoff_seconds = transport, backoff_seconds

    def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
        payload = _post_json(
            f"{self.base_url}/embeddings",
            self.api_key,
            {"model": self.model_identifier, "input": texts, "dimensions": self.dimensions},
            timeout=self.timeout,
            retries=self.retries,
            deadline=deadline,
            max_request_bytes=self.max_request_bytes,
            max_response_bytes=self.max_response_bytes,
            transport=self.transport,
            backoff_seconds=self.backoff_seconds,
        )
        data = payload.get("data")
        if not isinstance(data, list) or len(data) != len(texts):
            raise ProviderUnavailable("embedding provider unavailable")
        by_index: dict[int, list[float]] = {}
        for item in data:
            if not isinstance(item, dict):
                raise ProviderUnavailable("embedding provider unavailable")
            index, raw_vector = item.get("index"), item.get("embedding")
            if isinstance(index, bool) or not isinstance(index, int) or index in by_index:
                raise ProviderUnavailable("embedding provider unavailable")
            if not isinstance(raw_vector, list) or len(raw_vector) != self.dimensions:
                raise ProviderUnavailable("embedding provider unavailable")
            vector: list[float] = []
            for value in raw_vector:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ProviderUnavailable("embedding provider unavailable")
                number = float(value)
                if not math.isfinite(number):
                    raise ProviderUnavailable("embedding provider unavailable")
                vector.append(number)
            by_index[index] = vector
        if set(by_index) != set(range(len(texts))):
            raise ProviderUnavailable("embedding provider unavailable")
        return [by_index[index] for index in range(len(texts))]


class OpenAICompatibleGenerationProvider:
    status = "available"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        timeout: float = 20,
        retries: int = 2,
        max_request_bytes: int = 2_000_000,
        max_response_bytes: int = 2_000_000,
        max_generated_chars: int = 100_000,
        transport: httpx.BaseTransport | None = None,
        backoff_seconds: float = 0.1,
    ) -> None:
        self.base_url, self.api_key, self.model_identifier = (
            base_url.rstrip("/"),
            api_key,
            model,
        )
        self.timeout, self.retries = timeout, retries
        self.max_request_bytes, self.max_response_bytes = max_request_bytes, max_response_bytes
        self.max_generated_chars = max_generated_chars
        self.transport, self.backoff_seconds = transport, backoff_seconds

    def generate(
        self,
        system_prompt: str,
        user_payload: str | None = None,
        *,
        deadline: float | None = None,
    ) -> str:
        messages = [{"role": "system", "content": system_prompt}]
        if user_payload is not None:
            messages.append({"role": "user", "content": user_payload})
        payload = _post_json(
            f"{self.base_url}/chat/completions",
            self.api_key,
            {"model": self.model_identifier, "messages": messages},
            timeout=self.timeout,
            retries=self.retries,
            deadline=deadline,
            max_request_bytes=self.max_request_bytes,
            max_response_bytes=self.max_response_bytes,
            transport=self.transport,
            backoff_seconds=self.backoff_seconds,
        )
        choices = payload.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ProviderUnavailable("generation provider unavailable")
        choice = choices[0]
        if not isinstance(choice, dict) or choice.get("index", 0) != 0:
            raise ProviderUnavailable("generation provider unavailable")
        message = choice.get("message")
        if not isinstance(message, dict):
            raise ProviderUnavailable("generation provider unavailable")
        value = message.get("content")
        if not isinstance(value, str) or len(value) > self.max_generated_chars:
            raise ProviderUnavailable("generation provider unavailable")
        citations = message.get("citations", [])
        if not isinstance(citations, list) or len(citations) > 100:
            raise ProviderUnavailable("generation provider unavailable")
        if any(not isinstance(citation, str) or len(citation) > 200 for citation in citations):
            raise ProviderUnavailable("generation provider unavailable")
        return value
