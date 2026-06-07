"""Tests for backend contracts, fakes, and factory routing."""

import pytest

from delve.backends import (
    FakeLLMClient,
    FakeSearchClient,
    SearchHit,
    SupportsUsage,
    available_llm_backends,
    available_search_backends,
    make_llm,
    make_search,
)


def test_fake_llm_responder_and_usage() -> None:
    llm = FakeLLMClient(responder=lambda prompt, system: f"echo:{prompt}")
    out = llm.complete("hello", system="be terse")
    assert out == "echo:hello"
    assert llm.calls == [{"prompt": "hello", "system": "be terse"}]
    summary = llm.get_usage_summary()
    assert summary["total_calls"] == 1
    assert summary["by_model"]["fake-llm"]["calls"] == 1
    assert summary["by_model"]["fake-llm"]["output_tokens"] >= 1


def test_fake_llm_substring_routing_first_match_wins() -> None:
    llm = FakeLLMClient(responses={"verify": "VERDICT", "extract": "CLAIMS"}, default="?")
    assert llm.complete("please verify this") == "VERDICT"
    assert llm.complete("please extract that") == "CLAIMS"
    assert llm.complete("something else") == "?"


def test_fake_llm_satisfies_supports_usage_protocol() -> None:
    assert isinstance(FakeLLMClient(), SupportsUsage)


def test_fake_search_routing_and_limit() -> None:
    hits = [SearchHit(url=f"https://x.com/{i}", title=str(i)) for i in range(5)]
    search = FakeSearchClient(hits={"topic": hits})
    out = search.search("a topic query", limit=2)
    assert [h.title for h in out] == ["0", "1"]
    assert search.calls == ["a topic query"]


def test_fake_search_default_when_no_match() -> None:
    search = FakeSearchClient(default=[SearchHit(url="https://d.com")])
    assert search.search("anything")[0].url == "https://d.com"


def test_search_hit_to_citation_carries_source() -> None:
    hit = SearchHit(url="https://a.com", title="A", snippet="s", source="exa")
    cit = hit.to_citation(retrieved_at="2026-01-01T00:00:00Z")
    assert cit.source == "exa"
    assert cit.retrieved_at == "2026-01-01T00:00:00Z"
    assert cit.title == "A"


def test_factory_routes_fakes() -> None:
    assert isinstance(make_llm("fake"), FakeLLMClient)
    assert isinstance(make_llm("FAKE"), FakeLLMClient)  # case-insensitive
    assert isinstance(make_search("fake"), FakeSearchClient)


def test_factory_unknown_backend_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Unknown LLM backend"):
        make_llm("gpt-9")
    with pytest.raises(ValueError, match="Unknown search backend"):
        make_search("altavista")


def test_available_backends_listing() -> None:
    assert "fake" in available_llm_backends()
    assert "anthropic" in available_llm_backends()
    assert {"fake", "exa", "tavily"} <= set(available_search_backends())


def test_factory_passes_kwargs_to_fake() -> None:
    llm = make_llm("fake", default="canned")
    assert llm.complete("x") == "canned"
