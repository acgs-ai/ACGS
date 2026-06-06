"""Tests for the `delve` CLI wiring (offline fake backends)."""

from pathlib import Path

import pytest

from delve.cli import main
from delve.domain import Citation, Claim, ClaimStatus
from delve.graph import KnowledgeGraph


def test_run_writes_brief_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "brief.md"
    code = main(["run", "Why is the sky blue?", "--out", str(out), "--max-waves", "2"])
    assert code == 0
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("# Research Brief: Why is the sky blue?")


def test_run_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", "What is X?", "--max-waves", "1"])
    assert code == 0
    assert "# Research Brief: What is X?" in capsys.readouterr().out


def test_run_requires_a_question(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", "--max-waves", "1"])
    assert code == 2
    assert "question is required" in capsys.readouterr().err


def test_run_persists_graph(tmp_path: Path) -> None:
    graph_path = tmp_path / "kg.delve.json"
    code = main(["run", "Why is the sky blue?", "--graph", str(graph_path), "--max-waves", "1"])
    assert code == 0
    assert graph_path.exists()
    reloaded = KnowledgeGraph.load(graph_path)
    assert reloaded.question == "Why is the sky blue?"


def test_resume_uses_persisted_question(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Seed a persisted graph with a question + a supported claim.
    graph_path = tmp_path / "kg.delve.json"
    graph = KnowledgeGraph(question="What is dark matter?", wave=1)
    cit = Citation(url="https://a.com", title="Source A")
    claim, _ = graph.add_claim(Claim(text="Dark matter does not emit light", support=(cit,)))
    graph.set_claim_status(claim.id, ClaimStatus.SUPPORTED, "verified")
    graph.save(graph_path)

    # Resume WITHOUT passing a question — it must come from the graph.
    code = main(["run", "--resume", str(graph_path), "--max-waves", "1"])
    assert code == 0
    out = capsys.readouterr().out
    assert "# Research Brief: What is dark matter?" in out
    assert "Dark matter does not emit light" in out  # prior knowledge carried forward


def test_unknown_backend_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown LLM backend"):
        main(["run", "Q?", "--llm", "gpt-9", "--max-waves", "1"])


def test_negative_verify_samples_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", "Q?", "--verify-samples", "-1", "--max-waves", "1"])
    assert code == 2
    assert "--verify-samples must be >= 1" in capsys.readouterr().err


def test_run_reports_llm_call_count(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", "What is X?", "--max-waves", "1"])
    assert code == 0
    assert "llm_calls=" in capsys.readouterr().err  # usage is wired into output
