"""Snapshot + placeholder tests for the markdown brief renderer."""

from delve.brief import render_brief
from delve.domain import Citation, Claim, ClaimStatus, Gap
from delve.graph import KnowledgeGraph

EXPECTED = """# Research Brief: Why is the sky blue?

> 1 supported · 1 refuted · 1 open gap(s) · 2 wave(s)

## Key Findings

- The sky is blue due to Rayleigh scattering [1]

## Open Questions

- What causes red sunsets? — edge case

## Refuted / Unsupported

- ~~The sky is blue because of the ocean~~ — no supporting sources

## Sources

[1] Rayleigh scattering — https://physics.org/rayleigh
"""


def _build_graph() -> KnowledgeGraph:
    graph = KnowledgeGraph(question="Why is the sky blue?", wave=2)
    cit = Citation(url="https://physics.org/rayleigh", title="Rayleigh scattering", source="fake")
    supported, _ = graph.add_claim(
        Claim(text="The sky is blue due to Rayleigh scattering", support=(cit,))
    )
    graph.set_claim_status(supported.id, ClaimStatus.SUPPORTED, "verified")
    refuted, _ = graph.add_claim(Claim(text="The sky is blue because of the ocean"))
    graph.set_claim_status(refuted.id, ClaimStatus.REFUTED, "no supporting sources")
    graph.add_gap(Gap(question="What causes red sunsets?", rationale="edge case"))
    return graph


def test_render_brief_snapshot() -> None:
    assert render_brief(_build_graph()) == EXPECTED


def test_render_brief_is_deterministic() -> None:
    assert render_brief(_build_graph()) == render_brief(_build_graph())


def test_render_brief_empty_graph_uses_placeholders() -> None:
    out = render_brief(KnowledgeGraph(question="Q?"))
    assert "# Research Brief: Q?" in out
    assert "_No supported claims yet._" in out
    assert "_None — the question appears thoroughly explored._" in out
    assert "_No sources cited yet._" in out
    assert "## Refuted / Unsupported" not in out  # section omitted when empty
