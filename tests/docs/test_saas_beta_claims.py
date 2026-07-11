from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_claim_boundaries_and_control_plane_readme() -> None:
    claims = _read("docs/CLAIMS.md")
    roadmap = _read("docs/ROADMAP.md")
    comparison = _read("docs/COMPARISON.md")
    comparison_lower = comparison.lower()
    control_plane = _read("packages/acgs-control-plane/README.md")
    control_plane_lower = control_plane.lower()
    combined = "\n".join((claims, roadmap, comparison, control_plane)).lower()

    for required in (
        "alpha, local receipt-gated kernel",
        "native receipt",
        "federated attestation",
        "observed evidence",
        "aws agentcore policy",
        "microsoft agent control specification",
        "galileo agent control",
        "opa / cedar",
        "single-use enforcement is optional",
        "not independent witnessing",
        "legacy and unsigned",
        "production posture refuses",
        "no authenticated customer-runtime evidence-ingestion api",
    ):
        assert required in combined

    assert "require_signature=true" in control_plane_lower
    assert "fails loudly without configured trust" in control_plane_lower
    assert "audit append is outside the sql transaction" in control_plane_lower
    assert "transaction spine is not shipped" in comparison_lower
    assert "never represented as pre-execution authorization proof" in comparison_lower

    for forbidden in (
        "production-ready",
        "three paid design partners",
        "revenue-generating platform",
        "competitors only log after",
        "every action carries a verifiable, single-use decision receipt",
        "commits atomically with the side effect",
        "neither store can silently rewrite the other",
    ):
        assert forbidden not in combined
