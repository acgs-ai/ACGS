import json
import logging
import time
from collections.abc import Callable

import httpx
import pytest

from second_brain.providers import (
    OpenAICompatibleEmbeddingProvider,
    OpenAICompatibleGenerationProvider,
    ProviderUnavailable,
)


def provider(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    dimensions: int = 2,
    retries: int = 0,
    max_response_bytes: int = 4096,
) -> OpenAICompatibleEmbeddingProvider:
    return OpenAICompatibleEmbeddingProvider(
        "https://provider.invalid/v1",
        "server-only-secret-key",
        "embedding-model",
        dimensions,
        timeout=1,
        retries=retries,
        max_request_bytes=4096,
        max_response_bytes=max_response_bytes,
        transport=httpx.MockTransport(handler),
        backoff_seconds=0,
    )


@pytest.mark.parametrize(
    "data",
    [
        [{"index": 0, "embedding": [0.1, 0.2]}],
        [
            {"index": 0, "embedding": [0.1, 0.2]},
            {"index": 0, "embedding": [0.3, 0.4]},
        ],
        [
            {"index": 0, "embedding": [0.1, 0.2]},
            {"index": 2, "embedding": [0.3, 0.4]},
        ],
        [
            {"index": 0, "embedding": [0.1]},
            {"index": 1, "embedding": [0.3, 0.4]},
        ],
        [
            {"index": 0, "embedding": [float("nan"), 0.2]},
            {"index": 1, "embedding": [0.3, 0.4]},
        ],
        [
            {"index": 0, "embedding": [float("inf"), 0.2]},
            {"index": 1, "embedding": [0.3, 0.4]},
        ],
        [
            {"index": 0, "embedding": [True, 0.2]},
            {"index": 1, "embedding": [0.3, 0.4]},
        ],
    ],
    ids=[
        "wrong-count",
        "duplicate-index",
        "missing-index",
        "wrong-dimension",
        "nan",
        "infinity",
        "boolean",
    ],
)
def test_embedding_provider_rejects_malformed_vectors(data: list[dict[str, object]]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=json.dumps({"data": data}).encode(),
            request=request,
        )

    with pytest.raises(ProviderUnavailable, match="unavailable"):
        provider(handler).embed(["first", "second"], deadline=time.monotonic() + 1)


@pytest.mark.parametrize(
    ("status", "headers", "body"),
    [
        (200, {"content-type": "text/plain"}, b"not json"),
        (302, {"content-type": "application/json", "location": "https://other.invalid"}, b"{}"),
        (200, {"content-type": "application/json"}, b"x" * 4097),
    ],
    ids=["wrong-content-type", "redirect", "oversized"],
)
def test_provider_rejects_wrong_mime_redirects_and_oversized_responses(
    status: int, headers: dict[str, str], body: bytes
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, content=body, request=request)

    with pytest.raises(ProviderUnavailable):
        provider(handler).embed(["first", "second"], deadline=time.monotonic() + 1)


@pytest.mark.parametrize("retry_status", [408, 429, 500, 503])
def test_provider_retries_only_transient_statuses(retry_status: int) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                retry_status,
                headers={"content-type": "application/json"},
                content=b"{}",
                request=request,
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "data": [
                    {"index": 1, "embedding": [0.3, 0.4]},
                    {"index": 0, "embedding": [0.1, 0.2]},
                ]
            },
            request=request,
        )

    vectors = provider(handler, retries=1).embed(["first", "second"], deadline=time.monotonic() + 1)
    assert vectors == [[0.1, 0.2], [0.3, 0.4]]
    assert len(requests) == 2


def test_provider_does_not_retry_permanent_4xx_or_expose_key_and_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    requests = 0
    private_body = "private-source-body-never-log"
    secret_key = "server-only-secret-key"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            400,
            headers={"content-type": "application/json"},
            content=private_body.encode(),
            request=request,
        )

    with caplog.at_level(logging.DEBUG), pytest.raises(ProviderUnavailable) as error:
        provider(handler, retries=2).embed([private_body], deadline=time.monotonic() + 1)
    assert requests == 1
    combined = caplog.text + str(error.value)
    assert private_body not in combined
    assert secret_key not in combined


def test_provider_deadline_caps_attempt_timeout_and_backoff() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            503,
            headers={"content-type": "application/json"},
            content=b"{}",
            request=request,
        )

    with pytest.raises(ProviderUnavailable):
        provider(handler, retries=5).embed(["first"], deadline=time.monotonic() - 0.001)
    assert requests == 0


def test_generation_provider_bounds_and_validates_text() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"choices": [{"index": 0, "message": {"content": "x" * 11}}]},
            request=request,
        )

    generation = OpenAICompatibleGenerationProvider(
        "https://provider.invalid/v1",
        "server-only-secret-key",
        "generation-model",
        timeout=1,
        retries=0,
        max_request_bytes=4096,
        max_response_bytes=4096,
        max_generated_chars=10,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderUnavailable):
        generation.generate("bounded prompt", deadline=time.monotonic() + 1)
