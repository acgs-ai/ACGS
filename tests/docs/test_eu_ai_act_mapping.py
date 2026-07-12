"""Pin docs/EU_AI_ACT_MAPPING.md to cover every Article 12 sub-duty.

The mapping doc claims to map Decision Receipt fields to the record-keeping /
logging sub-duties of EU AI Act Article 12. This test mechanically guards that
claim: for each canonical sub-duty id below, the doc must (1) name the sub-duty
and (2) carry either a field mapping or an explicit GAP marker on the same line.
It also pins the claim-safe framing so the doc can never silently drift into
"compliant / certified / regulator-approved" overclaiming.

Run at the repo root without installing gove-zone; ``conftest.py`` puts the
pure-source package on ``sys.path`` (this module needs no gove_zone import, but
follows the same collection contract as its sibling tests). See
``.github/workflows/tests-docs.yml``.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAPPING_DOC = ROOT / "docs" / "EU_AI_ACT_MAPPING.md"

# Canonical Article 12 sub-duties this mapping must address. Each id MUST appear
# in the doc, and for each the doc must carry a field mapping (`receipt.py:` cite
# or a backtick-quoted field) OR an explicit GAP marker.
ART12_SUBDUTIES = (
    "Art 12(1)",
    "Art 12(2)",
    "Art 12(3)(a)",
    "Art 12(3)(b)",
    "Art 12(3)(c)",
    "Art 12(3)(d)",
)

# Tokens that count as "this sub-duty is mapped to a field/mechanism".
FIELD_EVIDENCE_TOKENS = ("receipt.py:", "`audit_event_hash`", "`timestamp`",
                         "`validator_id`", "`policy_bundle_id`", "`argument_hash`",
                         "`matched_rules`", "`expires_at`")

# Tokens that count as "this sub-duty is an explicit non-coverage statement".
GAP_TOKENS = ("GAP", "not covered", "PARTIAL")

# Claim-safe framing: these MUST be present.
REQUIRED_FRAMING = ("evidence toward", "non-conformity")

# Overclaiming wording that must NEVER appear as a self-description.
BANNED_OVERCLAIMS = (
    "is compliant",
    "is certified",
    "regulator-approved",
    "compliance certification.",
    "conformity assessment.",
)


def _read() -> str:
    return MAPPING_DOC.read_text(encoding="utf-8")


def test_mapping_doc_exists() -> None:
    assert MAPPING_DOC.is_file(), f"missing {MAPPING_DOC.relative_to(ROOT)}"


def test_every_subduty_is_named_and_addressed() -> None:
    """Each Art 12 sub-duty id appears AND is addressed by a field or a GAP."""
    text = _read()
    for subduty in ART12_SUBDUTIES:
        assert subduty in text, (
            f"EU_AI_ACT_MAPPING.md does not mention sub-duty {subduty!r}"
        )
        # Find the lines that name this sub-duty and require evidence-or-gap on one.
        lines = [ln for ln in text.splitlines() if subduty in ln]
        assert lines, subduty
        addressed = any(
            any(tok in ln for tok in FIELD_EVIDENCE_TOKENS)
            or any(tok in ln for tok in GAP_TOKENS)
            for ln in lines
        )
        assert addressed, (
            f"sub-duty {subduty!r} is named but no line maps it to a receipt "
            f"field/mechanism nor marks it GAP/PARTIAL/not-covered"
        )


def test_doc_is_claim_safe() -> None:
    """Claim-safe framing present; overclaiming self-descriptions absent."""
    text = _read()
    lowered = text.lower()
    for token in REQUIRED_FRAMING:
        assert token in lowered, (
            f"EU_AI_ACT_MAPPING.md missing required claim-safe framing: {token!r}"
        )
    # gove-zone must be described as NOT compliant/certified/approved. Any of the
    # banned self-claims appearing without a negation is an overclaim.
    for banned in BANNED_OVERCLAIMS:
        if banned in lowered:
            # Allowed only inside an explicit negation ("not a compliance
            # certification.", "not ... regulator-approved").
            assert "not" in lowered, (
                f"overclaim {banned!r} present without negation"
            )


def test_explicit_gap_section_present() -> None:
    """The doc must carry explicit GAP non-coverage statements, not just mappings."""
    text = _read()
    assert "GAP" in text, "mapping doc must include explicit GAP non-coverage notes"
    assert text.count("GAP") >= 3, (
        "expected several explicit GAP notes (lifetime retention, biometric DB, "
        "natural-person authentication, etc.)"
    )
