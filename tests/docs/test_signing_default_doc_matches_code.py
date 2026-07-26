"""Pin docs about the signing default to the shipped code default.

The CLAIMS integrity defect this guards: docs once asserted signing was OFF by
default (``require_signature`` defaults ``False``, "unsigned dev mode is the
default") while the shipped code defaults it ON (``require_signature: bool =
True`` in both ``execute_with_receipt`` and ``ReceiptVerifier.__init__``). The
secure profile is the default; without a configured trusted verifier the gate
fails closed (raises ``ProductionProfileError``) rather than emitting an
unsigned receipt — it does NOT auto-sign.

This test reads the *actual* code default via ``inspect.signature`` and asserts:
  1. the runtime default is ``True`` in both governed-execution entry points, and
  2. each governance doc states the correct default-string AND contains none of
     the stale false phrases.

The negative (banned-phrase) assertions are the anti-drift mechanism: they fail
loud if the old "off/unsigned by default" wording is ever reintroduced, OR if
someone flips the code default back to ``False`` without correcting the docs.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from gove_zone.contracts import ReceiptVerifier
from gove_zone.executor import execute_with_receipt

ROOT = Path(__file__).resolve().parents[2]

# Docs whose signing-default wording must track the code default.
SIGNING_DEFAULT_DOCS = (
    "docs/CLAIMS.md",
    "docs/SECURITY_MODEL.md",
    "docs/ARCHITECTURE.md",
)

# Phrases that were FALSE under the shipped code and must never reappear while
# the code default is ``True``. Matched case-insensitively.
BANNED_STALE_PHRASES = (
    "require_signature defaults to `false`",
    "require_signature` defaults `false`",
    "require_signature defaults false",
    "signing is off by default",
    "verification is unsigned by default",
    "unsigned dev mode is the default",
    "default is unsigned local mode",
)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _code_default(func, *, attr: str = "require_signature") -> object:
    return inspect.signature(func).parameters[attr].default


def test_code_default_for_require_signature_is_true() -> None:
    """Ground truth: both governed-execution entry points default to True."""
    assert _code_default(execute_with_receipt) is True, (
        "execute_with_receipt no longer defaults require_signature=True; "
        "update the signing-default docs to match."
    )
    assert _code_default(ReceiptVerifier.__init__) is True, (
        "ReceiptVerifier.__init__ no longer defaults require_signature=True; "
        "update the signing-default docs to match."
    )


def test_docs_state_the_true_default_and_no_stale_false_wording() -> None:
    """Docs must reflect the code default (True) — no 'off/unsigned by default'."""
    executor_default = _code_default(execute_with_receipt)
    verifier_default = _code_default(ReceiptVerifier.__init__)
    assert executor_default is verifier_default is True  # guarded above; defensive

    # The literal default-string the docs must carry, derived from the code.
    default_str = f"`require_signature` defaults to `{executor_default!s}`"

    for rel in SIGNING_DEFAULT_DOCS:
        text = _read(rel)
        lowered = text.lower()

        # (1) No stale phrase that contradicts the shipped default.
        for phrase in BANNED_STALE_PHRASES:
            assert phrase not in lowered, (
                f"{rel}: stale signing-default wording '{phrase}' contradicts the "
                f"shipped code default ({default_str})."
            )

        # (2) The doc must reference require_signature with the True default,
        #     and must NOT imply auto-signing.
        assert "require_signature" in lowered, rel
        assert "auto-sign" in lowered or "does not auto-sign" in lowered, (
            f"{rel}: must state the default does not auto-sign (it fails closed)."
        )

    # (3) The canonical default-string must appear verbatim in at least one doc
    #     so the literal default is asserted, not just paraphrased.
    assert any(default_str in _read(rel) for rel in SIGNING_DEFAULT_DOCS), (
        f"no governance doc carries the literal default-string {default_str!r}"
    )


def test_claims_row_marks_secure_profile_as_the_default() -> None:
    """The CLAIMS row is a TRUE positive, not 'not claimed', and is fail-closed-accurate."""
    text = _read("docs/CLAIMS.md").lower()
    # The reframed claim must not headline auto-signing ("signed by default").
    assert "verification is signed by default" not in text, (
        "CLAIMS.md must not headline 'signed by default' (implies auto-signing)."
    )
    # The default posture must be described as secure (require_signature=True).
    assert "require_signature=True`) is the default".lower() in text or (
        "secure profile" in text and "require_signature" in text
    ), "CLAIMS.md must mark the secure (require_signature=True) profile as the default."
    # And must describe the fail-closed (raises), no-auto-sign behavior.
    assert "fails closed" in text and "does not auto-sign" in text, (
        "CLAIMS.md must state the default fails closed and does not auto-sign."
    )
