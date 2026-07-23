"""Adaptive-stability tripwire for the adversary suite.

Runs the deterministic adaptive-attack harness (``adaptive.py``) against the REAL gate
for every manifest class and asserts observed stability matches the pinned ``adaptive``
value. This is the "defense arrived / regressed" tripwire in the *adaptive* dimension,
the sibling of ``test_taxonomy_posture_is_pinned`` in the static dimension.

Honest scope: this is a bounded, deterministic config/input-space variant search over
gove-zone's own gate — NOT a model-in-the-loop adaptive evaluation. "Adaptively stable"
means only "no bounded variant in family F bypassed surface S" (see ``README.md`` and
``docs/research/adaptive-eval-adversary-analysis.md`` §6).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

# The adversary suite already gates on `cryptography` via conftest.importorskip; keep a
# defensive skip here so this module is safe to import in isolation too.
pytest.importorskip("cryptography")


def _load(name: str):
    """Load a sibling module by file path (robust under --import-mode=importlib, where
    sibling top-level/relative imports are not resolvable without an __init__.py)."""
    import sys

    spec = importlib.util.spec_from_file_location(
        f"adversary_{name}", Path(__file__).with_name(f"{name}.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec: dataclasses' field-type resolution looks the module up via
    # sys.modules[cls.__module__], which fails with AttributeError on an unregistered module.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


adaptive = _load("adaptive")
MANIFEST = _load("test_coverage_manifest").MANIFEST

# Which classical property (per analysis §1/§4/§5.2) earns each STABLE verdict.
_STABLE_PROPERTY: dict[str, str] = {
    "forged-authorization": (
        "cryptographic trust-root binding — strict standalone execution requires a valid "
        "signature from the configured verifier"
    ),
    "replayed-authorization": (
        "durable single-use authorization — reserve/commit consumption precedes execution "
        "and rejects a second use"
    ),
    "policy-downgrade": (
        "policy artifact binding — the strict caller pins the in-force policy hash and "
        "bundle identity"
    ),
    "validator-bypass": (
        "authority separation — the strict caller pins trusted authority and validator "
        "identity at the final gate"
    ),
    "signature-stripping": (
        "reference-monitor totality — require_signature=True is a total check; no "
        "receipt lacking a valid trusted signature is admitted"
    ),
    "tenant-crossover": (
        "least-privilege binding — expected_tenant_id/execution_boundary are "
        "hash-bound and checked by default at the gate"
    ),
    "evidence-omission": (
        "Biba integrity / total mediation — anchor-before-execute; no receipt (via "
        "execute_with_receipt) and no anchored audit evidence (via Kernel.dispatch: "
        "stripped-audit fails closed, and the anchor is recorded before the tool runs) "
        "both mean no side effect, regardless of every other parameter"
    ),
    "adapter-bypass": (
        "reference-monitor routing — ManagedAgent side-effect registrations retain only a "
        "blocked legacy sentinel and require the receipt-gated dispatcher even when the "
        "legacy policy is explicitly permissive"
    ),
}


def test_adaptive_stability_matches_manifest() -> None:
    """For each class, the harness's observed stability must equal the pinned ``adaptive``
    value. STABLE <=> result.stable. A drift (a fix that closes a gap, or a regression
    that opens one) flips this — the adaptive-dimension tripwire."""
    mismatches: list[str] = []
    for cls, entry in MANIFEST.items():
        pinned = entry["adaptive"]
        if pinned == "UNTESTED":
            continue
        result = adaptive.adaptive_attack(cls)
        observed = "STABLE" if result.stable else "BYPASSABLE"
        if observed != pinned:
            mismatches.append(
                f"{cls}: pinned={pinned} observed={observed} first_bypass={result.first_bypass}"
            )
    assert not mismatches, "adaptive stability drifted from the manifest:\n" + "\n".join(mismatches)


def test_adaptive_posture_is_pinned() -> None:
    """Freeze the adaptive headline: 8 STABLE / 2 BYPASSABLE / 0 UNTESTED. Changing the
    posture must be a deliberate manifest edit, mirroring test_taxonomy_posture_is_pinned."""
    counts = {"STABLE": 0, "BYPASSABLE": 0, "UNTESTED": 0}
    for entry in MANIFEST.values():
        counts[entry["adaptive"]] += 1  # type: ignore[index]
    assert counts == {"STABLE": 8, "BYPASSABLE": 2, "UNTESTED": 0}, counts


def test_stable_classes_have_no_bypass_and_named_property() -> None:
    """Each STABLE class must (a) survive its whole bounded family with no admitted
    variant, and (b) be annotated with the classical property that earns the verdict
    (Biba integrity / reference-monitor totality / least-privilege binding)."""
    for cls, entry in MANIFEST.items():
        if entry["adaptive"] != "STABLE":
            continue
        result = adaptive.adaptive_attack(cls)
        assert result.stable and result.first_bypass is None, (
            f"{cls} pinned STABLE but a variant bypassed: {result.first_bypass}"
        )
        assert result.variants_tried >= 1, f"{cls} tried no variants"
        assert cls in _STABLE_PROPERTY, f"{cls} is STABLE but has no classical-property annotation"


def test_bypassable_classes_recover_a_minimal_bypass() -> None:
    """Each BYPASSABLE class must yield a concrete first bypass id — the harness recovers
    the minimal admitted variant, it does not merely assert 'not stable'."""
    for cls, entry in MANIFEST.items():
        if entry["adaptive"] != "BYPASSABLE":
            continue
        result = adaptive.adaptive_attack(cls)
        assert not result.stable and result.first_bypass is not None, (
            f"{cls} pinned BYPASSABLE but no variant was admitted"
        )


def test_stable_class_families_fit_within_budget() -> None:
    """A STABLE verdict requires the WHOLE bounded family to be denied, but
    ``adaptive_attack`` stops enumerating at ``budget`` (``tried >= budget``). A family
    whose size reaches DEFAULT_BUDGET would be silently truncated — a bypass hiding past
    the cut would never be evaluated, yet the class would still read STABLE. Assert every
    STABLE class's full family is strictly under the budget, so a future added variant
    that reaches the ceiling fails loudly HERE instead of truncating silently."""
    for cls, entry in MANIFEST.items():
        if entry["adaptive"] != "STABLE":
            continue
        family = list(adaptive.VARIANT_GENERATORS[cls](adaptive.DEFAULT_BUDGET))
        assert len(family) < adaptive.DEFAULT_BUDGET, (
            f"{cls} family size {len(family)} >= DEFAULT_BUDGET "
            f"{adaptive.DEFAULT_BUDGET}: adaptive_attack would truncate the family and "
            "could hide an admitted variant past the cut — raise DEFAULT_BUDGET"
        )


def test_adaptive_attack_is_deterministic() -> None:
    """Reproducibility: two runs of the same (class, budget) yield the same verdict and
    the same first_bypass id — the result is a pure function of its arguments."""
    for cls in MANIFEST:
        a = adaptive.adaptive_attack(cls)
        b = adaptive.adaptive_attack(cls)
        assert (a.stable, a.first_bypass) == (b.stable, b.first_bypass), cls
