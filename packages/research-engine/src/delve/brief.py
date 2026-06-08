"""Render a knowledge graph into a living, citation-backed markdown brief.

Deterministic by construction: claims, gaps, and sources are emitted in
id-sorted order and no timestamps are included, so the same graph always
renders byte-identical output (snapshot-testable).
"""

from __future__ import annotations

from delve.domain import Citation, ClaimStatus
from delve.graph import KnowledgeGraph


def _number_sources(graph: KnowledgeGraph) -> tuple[dict[str, int], list[Citation]]:
    """Assign [n] numbers to citations referenced by supported claims, in the
    deterministic order those claims (and their support) are emitted."""
    numbering: dict[str, int] = {}
    ordered: list[Citation] = []
    for claim in graph.supported_claims():  # already id-sorted
        for citation in claim.support:  # already id-sorted
            if citation.id not in numbering:
                numbering[citation.id] = len(ordered) + 1
                ordered.append(citation)
    return numbering, ordered


def render_brief(graph: KnowledgeGraph) -> str:
    stats = graph.stats()
    numbering, sources = _number_sources(graph)
    lines: list[str] = []

    title = graph.question or "(untitled)"
    lines.append(f"# Research Brief: {title}")
    lines.append("")
    lines.append(
        f"> {stats['claims_supported']} supported · {stats['claims_refuted']} refuted · "
        f"{stats['gaps_open']} open gap(s) · {stats['wave']} wave(s)"
    )
    lines.append("")

    # Key findings -----------------------------------------------------
    lines.append("## Key Findings")
    lines.append("")
    supported = graph.supported_claims()
    if supported:
        for claim in supported:
            refs = "".join(f"[{numbering[c.id]}]" for c in claim.support if c.id in numbering)
            suffix = f" {refs}" if refs else ""
            lines.append(f"- {claim.text}{suffix}")
    else:
        lines.append("_No supported claims yet._")
    lines.append("")

    # Open questions ---------------------------------------------------
    lines.append("## Open Questions")
    lines.append("")
    open_gaps = graph.open_gaps()
    if open_gaps:
        for gap in open_gaps:
            tail = f" — {gap.rationale}" if gap.rationale else ""
            lines.append(f"- {gap.question}{tail}")
    else:
        lines.append("_None — the question appears thoroughly explored._")
    lines.append("")

    # Refuted ----------------------------------------------------------
    refuted = graph.claims_by_status(ClaimStatus.REFUTED)
    if refuted:
        lines.append("## Refuted / Unsupported")
        lines.append("")
        for claim in refuted:
            reason = f" — {claim.verdict_reason}" if claim.verdict_reason else ""
            lines.append(f"- ~~{claim.text}~~{reason}")
        lines.append("")

    # Sources ----------------------------------------------------------
    lines.append("## Sources")
    lines.append("")
    if sources:
        for citation in sources:
            label = citation.title or citation.url
            lines.append(f"[{numbering[citation.id]}] {label} — {citation.url}")
    else:
        lines.append("_No sources cited yet._")
    lines.append("")

    return "\n".join(lines)
