"""Tests for the KnowledgeGraph: dedup-merge, tombstones, persistence."""

from pathlib import Path

from delve.domain import Citation, Claim, ClaimStatus, Finding, Gap
from delve.graph import KnowledgeGraph


def test_add_citation_dedup_signals_new() -> None:
    g = KnowledgeGraph()
    _, new1 = g.add_citation(Citation(url="https://a.com"))
    _, new2 = g.add_citation(Citation(url="https://a.com/?utm_source=x"))  # same after normalize
    assert new1 is True
    assert new2 is False
    assert len(g.citations) == 1


def test_add_finding_registers_its_citations() -> None:
    g = KnowledgeGraph()
    f = Finding(text="t", query="q", wave=0, citations=(Citation(url="https://a.com"),))
    _, new = g.add_finding(f)
    assert new is True
    assert len(g.citations) == 1


def test_add_claim_merges_support_and_provenance() -> None:
    g = KnowledgeGraph()
    g.add_claim(
        Claim(
            text="X",
            support=(Citation(url="https://a.com"),),
            first_seen_wave=1,
            finding_ids=("fnd_a",),
        )
    )
    merged, new = g.add_claim(
        Claim(
            text="x",
            support=(Citation(url="https://b.com"),),
            first_seen_wave=0,
            finding_ids=("fnd_b",),
        )
    )
    assert new is False
    assert len(merged.support) == 2
    assert merged.first_seen_wave == 0  # earliest wins
    assert set(merged.finding_ids) == {"fnd_a", "fnd_b"}
    assert len(g.claims) == 1


def test_refuted_claim_is_a_tombstone() -> None:
    g = KnowledgeGraph()
    claim, _ = g.add_claim(Claim(text="false thing"))
    g.set_claim_status(claim.id, ClaimStatus.REFUTED, reason="no evidence")
    # rediscovery in a later wave must NOT resurrect or re-flag it as new
    _, new = g.add_claim(Claim(text="false thing"))
    assert new is False
    assert g.claims[claim.id].status is ClaimStatus.REFUTED
    assert g.claims[claim.id].verdict_reason == "no evidence"


def test_unverified_query_excludes_tombstones() -> None:
    g = KnowledgeGraph()
    a, _ = g.add_claim(Claim(text="a"))
    b, _ = g.add_claim(Claim(text="b"))
    g.set_claim_status(b.id, ClaimStatus.REFUTED)
    assert [c.text for c in g.unverified_claims()] == ["a"]


def test_close_gap() -> None:
    g = KnowledgeGraph()
    gap, _ = g.add_gap(Gap(question="why?"))
    assert len(g.open_gaps()) == 1
    g.close_gap(gap.id)
    assert g.open_gaps() == []


def test_stats_counts() -> None:
    g = KnowledgeGraph(wave=2)
    g.add_claim(Claim(text="a", status=ClaimStatus.SUPPORTED))
    g.add_claim(Claim(text="b"))
    g.add_gap(Gap(question="q"))
    s = g.stats()
    assert s["claims"] == 2
    assert s["claims_supported"] == 1
    assert s["claims_unverified"] == 1
    assert s["gaps_open"] == 1
    assert s["wave"] == 2


def test_save_load_round_trip(tmp_path: Path) -> None:
    g = KnowledgeGraph(question="What is X?", wave=3)
    g.add_finding(
        Finding(
            text="finding one",
            query="x",
            wave=1,
            citations=(Citation(url="https://a.com", title="A"),),
        )
    )
    claim, _ = g.add_claim(
        Claim(
            text="claim one",
            status=ClaimStatus.SUPPORTED,
            support=(Citation(url="https://a.com"),),
            first_seen_wave=1,
        )
    )
    g.set_claim_status(claim.id, ClaimStatus.REFUTED, reason="retracted")
    g.add_gap(Gap(question="open q", wave=2))

    path = tmp_path / "graph.delve.json"
    g.save(path)
    loaded = KnowledgeGraph.load(path)

    assert loaded.question == g.question
    assert loaded.wave == g.wave
    assert loaded.stats() == g.stats()
    # tombstone status survives the round trip
    assert loaded.claims[claim.id].status is ClaimStatus.REFUTED
    assert loaded.claims[claim.id].verdict_reason == "retracted"


def test_to_dict_is_deterministic() -> None:
    def build() -> KnowledgeGraph:
        g = KnowledgeGraph(question="q")
        for t in ["zebra", "apple", "mango"]:
            g.add_claim(Claim(text=t, support=(Citation(url=f"https://{t}.com"),)))
        return g

    assert build().to_json() == build().to_json()
    # claims serialized in id-sorted order
    ids = [c["id"] for c in build().to_dict()["claims"]]
    assert ids == sorted(ids)
