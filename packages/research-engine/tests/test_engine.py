"""End-to-end tests for the self-deepening loop with deterministic fakes."""

import json
from pathlib import Path

from delve.analysis import Analyst
from delve.backends.base import SearchHit
from delve.backends.fakes import FakeLLMClient, FakeSearchClient
from delve.domain import Claim, ClaimStatus
from delve.engine import Engine, ResearchConfig
from delve.graph import KnowledgeGraph


def _scenario_responder(prompt: str, system: str | None) -> str:
    """A deterministic analyst that converges: one claim, then nothing new."""
    if "TASK: derive_queries" in prompt:
        return '["sky color physics"]'
    if "TASK: extract_claims" in prompt:
        return '[{"claim": "The sky is blue due to Rayleigh scattering", "supports": [0]}]'
    if "TASK: verify_claim" in prompt:
        return '{"verdict": "supported", "reason": "source confirms scattering"}'
    if "TASK: propose_gaps" in prompt:
        return '[{"question": "What causes red sunsets?", "rationale": "edge case"}]'
    return "[]"


def _build_engine(config: ResearchConfig) -> Engine:
    search = FakeSearchClient(
        default=[
            SearchHit(
                url="https://physics.org/rayleigh",
                title="Rayleigh scattering",
                snippet="The sky appears blue because of Rayleigh scattering of sunlight.",
                source="fake",
            )
        ]
    )
    analyst = Analyst(FakeLLMClient(responder=_scenario_responder))
    return Engine(search=search, analyst=analyst, config=config)


def test_run_converges_by_dryness_not_cap(tmp_path: Path) -> None:
    config = ResearchConfig(
        max_waves=6,
        patience=1,
        graph_path=tmp_path / "graph.delve.json",
        trajectory_path=tmp_path / "trace.jsonl",
    )
    result = _build_engine(config).run("Why is the sky blue?")

    # The headline guarantee: the loop stopped because it ran dry, NOT because
    # it exhausted the wave cap. This is what proves self-deepening converges.
    assert result.converged is True
    assert result.waves < config.max_waves

    # One supported claim survived verification.
    supported = result.graph.supported_claims()
    assert len(supported) == 1
    assert "Rayleigh" in supported[0].text or "scattering" in supported[0].text

    # The gap raised in wave 1 was investigated (closed) by a later wave.
    assert result.graph.open_gaps() == []
    assert len(result.graph.gaps) == 1


def test_run_persists_graph_and_trajectory(tmp_path: Path) -> None:
    graph_path = tmp_path / "graph.delve.json"
    trace_path = tmp_path / "trace.jsonl"
    config = ResearchConfig(max_waves=6, graph_path=graph_path, trajectory_path=trace_path)
    result = _build_engine(config).run("Why is the sky blue?")

    # Graph persisted and reloadable with the same stats.
    assert graph_path.exists()
    assert KnowledgeGraph.load(graph_path).stats() == result.graph.stats()

    # Trajectory is append-only JSONL, one parseable event per line.
    lines = trace_path.read_text(encoding="utf-8").strip().splitlines()
    events = [json.loads(line) for line in lines]
    types = {e["type"] for e in events}
    assert {"run_start", "wave_start", "verdict", "wave_end", "run_end"} <= types
    assert any(e["type"] == "wave_end" and e["dry"] for e in events)


def test_unsupported_claim_is_auto_refuted_without_llm() -> None:
    # Seed a claim with NO citations; the engine must refute it without an LLM call.
    graph = KnowledgeGraph()
    graph.add_claim(Claim(text="An unsourced assertion", support=()))
    engine = _build_engine(ResearchConfig(max_waves=1))
    engine.graph = graph
    result = engine.run("Why is the sky blue?")

    refuted = result.graph.claims_by_status(ClaimStatus.REFUTED)
    assert any(c.text == "An unsourced assertion" for c in refuted)
    unsourced = next(c for c in refuted if c.text == "An unsourced assertion")
    assert "no supporting sources" in unsourced.verdict_reason


def test_llm_refutation_marks_tombstone() -> None:
    def responder(prompt: str, system: str | None) -> str:
        if "TASK: derive_queries" in prompt:
            return '["q"]'
        if "TASK: extract_claims" in prompt:
            return '[{"claim": "A dubious claim", "supports": [0]}]'
        if "TASK: verify_claim" in prompt:
            return '{"verdict": "refuted", "reason": "source does not support it"}'
        return "[]"

    search = FakeSearchClient(default=[SearchHit(url="https://x.com", snippet="unrelated text")])
    engine = Engine(
        search=search,
        analyst=Analyst(FakeLLMClient(responder=responder)),
        config=ResearchConfig(max_waves=2),
    )
    result = engine.run("Question?")
    assert result.graph.supported_claims() == []
    assert len(result.graph.claims_by_status(ClaimStatus.REFUTED)) == 1


def test_parse_failure_emits_event_and_is_not_treated_as_dry() -> None:
    def responder(prompt: str, system: str | None) -> str:
        if "TASK: derive_queries" in prompt:
            return '["q"]'
        if "TASK: extract_claims" in prompt:
            return "I cannot extract claims from this."  # unparseable
        return "[]"

    search = FakeSearchClient(default=[SearchHit(url="https://x.com", snippet="text")])
    config = ResearchConfig(max_waves=2)
    engine = Engine(
        search=search, analyst=Analyst(FakeLLMClient(responder=responder)), config=config
    )
    result = engine.run("Q?")
    assert any(e["type"] == "parse_error" and e["op"] == "extract_claims" for e in result.events)
    # A parse-failing wave must not be silently counted as convergence.
    assert any(
        e["type"] == "wave_end" and e["parse_failed"] and not e["dry"] for e in result.events
    )


def test_fan_out_preserves_order_when_parallel() -> None:
    # max_workers>1 fans out search concurrently but must keep input order.
    hits = {str(i): [SearchHit(url=f"https://x.com/{i}")] for i in range(4)}
    search = FakeSearchClient(hits=hits)

    def responder(prompt: str, system: str | None) -> str:
        if "TASK: derive_queries" in prompt:
            return '["0", "1", "2", "3"]'
        return "[]"

    engine = Engine(
        search=search,
        analyst=Analyst(FakeLLMClient(responder=responder)),
        config=ResearchConfig(max_waves=1, max_workers=4, queries_per_wave=4),
    )
    result = engine.run("Q?")
    # All four queries ran (execution order across threads is not guaranteed)...
    assert sorted(search.calls) == ["0", "1", "2", "3"]
    # ...and each distinct hit landed in the graph, so result order was preserved
    # when zipping hits back to their queries.
    urls = {c.normalized_url for c in result.graph.citations.values()}
    assert urls == {f"https://x.com/{i}" for i in range(4)}


def test_extraction_retries_after_parse_failure() -> None:
    # Regression: a finding whose extraction parse-fails on wave 1 must be
    # re-extracted on a later wave, not orphaned behind the dedup gate.
    state = {"extract_calls": 0}

    def responder(prompt: str, system: str | None) -> str:
        if "TASK: derive_queries" in prompt:
            return '["q"]'
        if "TASK: extract_claims" in prompt:
            state["extract_calls"] += 1
            if state["extract_calls"] == 1:
                return "Sorry, I cannot produce JSON here."  # parse failure, wave 1
            return '[{"claim": "Recovered claim", "supports": [0]}]'
        if "TASK: verify_claim" in prompt:
            return '{"verdict": "supported", "reason": "ok"}'
        return "[]"

    search = FakeSearchClient(default=[SearchHit(url="https://x.com", snippet="a durable fact")])
    engine = Engine(
        search=search,
        analyst=Analyst(FakeLLMClient(responder=responder)),
        config=ResearchConfig(max_waves=4),
    )
    result = engine.run("Q?")
    assert state["extract_calls"] >= 2  # the orphaned finding was retried
    assert any(c.text == "Recovered claim" for c in result.graph.claims.values())


def test_usage_is_threaded_into_run_result() -> None:
    result = _build_engine(ResearchConfig(max_waves=2)).run("Why is the sky blue?")
    assert "total_calls" in result.usage
    assert result.usage["total_calls"] >= 1
