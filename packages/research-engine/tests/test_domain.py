"""Tests for domain models: id stability, normalization, serialization."""

from delve.domain import (
    Citation,
    Claim,
    ClaimStatus,
    Finding,
    Gap,
    GapStatus,
    normalize_text,
    normalize_url,
)


def test_normalize_text_collapses_and_strips() -> None:
    assert normalize_text("  Hello   World.  ") == "hello world"
    assert normalize_text("A\tB\nC!!!") == "a b c"


def test_normalize_url_drops_tracking_and_fragment() -> None:
    a = normalize_url("https://Example.com/Page/?utm_source=x&id=7#section")
    b = normalize_url("https://example.com/Page?id=7")
    assert a == b
    assert "utm_source" not in a
    assert "#section" not in a


def test_normalize_url_sorts_params_and_strips_trailing_slash() -> None:
    assert normalize_url("https://x.com/a/?b=2&a=1") == normalize_url("https://x.com/a?a=1&b=2")


def test_citation_id_stable_across_tracking_variants() -> None:
    c1 = Citation(url="https://ex.com/doc?utm_campaign=spring", source="exa")
    c2 = Citation(url="https://ex.com/doc/", source="tavily")
    assert c1.id == c2.id  # same content, different tracking/trailing slash/source


def test_claim_id_ignores_case_and_whitespace() -> None:
    assert Claim(text="The Sky Is Blue").id == Claim(text="the  sky is blue.").id


def test_finding_and_gap_ids_are_prefixed() -> None:
    assert Finding(text="x", query="q", wave=0).id.startswith("fnd_")
    assert Gap(question="why?").id.startswith("gap_")
    assert Citation(url="https://x.com").id.startswith("cit_")


def test_models_are_immutable() -> None:
    import dataclasses

    claim = Claim(text="t")
    try:
        claim.text = "u"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:  # pragma: no cover
        raise AssertionError("Claim should be frozen")


def test_claim_round_trip_serialization() -> None:
    claim = Claim(
        text="Photons have no mass",
        status=ClaimStatus.SUPPORTED,
        support=(Citation(url="https://a.com", title="A"), Citation(url="https://b.com")),
        verdict_reason="3/3 verifiers agree",
        first_seen_wave=2,
        finding_ids=("fnd_1", "fnd_2"),
    )
    restored = Claim.from_dict(claim.to_dict())
    assert restored == claim


def test_gap_round_trip_serialization() -> None:
    gap = Gap(
        question="What about edge cases?",
        rationale="untested",
        status=GapStatus.CLOSED,
        wave=3,
    )
    assert Gap.from_dict(gap.to_dict()) == gap


def test_claim_support_serialized_sorted_by_id() -> None:
    cits = (Citation(url="https://zzz.com"), Citation(url="https://aaa.com"))
    claim = Claim(text="t", support=cits)
    serialized_ids = [c["id"] for c in claim.to_dict()["support"]]
    assert serialized_ids == sorted(serialized_ids)
