"""Tripwires for the bounded adaptive dimension of the adversary taxonomy."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")


def _load(name: str):
    """Load a sibling by path under pytest's importlib mode."""
    spec = importlib.util.spec_from_file_location(
        f"adversary_{name}", Path(__file__).with_name(f"{name}.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


adaptive = _load("adaptive")
MANIFEST = _load("test_coverage_manifest").MANIFEST

_STABLE_PROPERTIES = {
    "signature-stripping": "signature verification is total when required",
    "tenant-crossover": "tenant and execution-boundary binding is checked",
    "evidence-omission": "receipt/audit anchoring fails closed before execution",
}


def test_adaptive_registry_matches_manifest() -> None:
    assert frozenset(adaptive.VARIANT_GENERATORS) == frozenset(MANIFEST)


def test_adaptive_observations_match_manifest() -> None:
    mismatches: list[str] = []
    for class_name, entry in MANIFEST.items():
        result = adaptive.adaptive_attack(class_name)
        observed = "STABLE" if result.stable else "BYPASSABLE"
        if observed != entry["adaptive"]:
            mismatches.append(
                f"{class_name}: pinned={entry['adaptive']} observed={observed} "
                f"first_bypass={result.first_bypass}"
            )
    assert not mismatches, "adaptive posture drifted:\n" + "\n".join(mismatches)


def test_adaptive_posture_is_pinned() -> None:
    counts = {"STABLE": 0, "BYPASSABLE": 0, "UNTESTED": 0}
    for entry in MANIFEST.values():
        counts[entry["adaptive"]] += 1
    assert counts == {"STABLE": 3, "BYPASSABLE": 5, "UNTESTED": 0}


def test_stable_families_are_complete_and_named() -> None:
    for class_name, entry in MANIFEST.items():
        if entry["adaptive"] != "STABLE":
            continue
        family = list(adaptive.VARIANT_GENERATORS[class_name](adaptive.DEFAULT_BUDGET))
        assert len(family) >= 2, f"{class_name} needs a meaningful variant family"
        assert len(family) < adaptive.DEFAULT_BUDGET, f"{class_name} family would truncate"
        result = adaptive.adaptive_attack(class_name)
        assert result.stable and result.first_bypass is None
        assert class_name in _STABLE_PROPERTIES


def test_bypassable_families_recover_first_admitted_variant() -> None:
    for class_name, entry in MANIFEST.items():
        if entry["adaptive"] != "BYPASSABLE":
            continue
        result = adaptive.adaptive_attack(class_name)
        assert not result.stable
        assert result.first_bypass is not None


def test_adaptive_results_are_deterministic() -> None:
    for class_name in MANIFEST:
        first = adaptive.adaptive_attack(class_name)
        second = adaptive.adaptive_attack(class_name)
        assert (
            first.stable,
            first.first_bypass,
            first.variants_tried,
        ) == (
            second.stable,
            second.first_bypass,
            second.variants_tried,
        ), class_name


def test_gate_counts_side_effect_before_validation_error_as_admitted(monkeypatch) -> None:
    def late_failure(*, tool_fn, args, **_kwargs):
        tool_fn(**args)
        raise adaptive.ReceiptValidationError("late validation failure")

    monkeypatch.setattr(adaptive, "execute_with_receipt", late_failure)
    assert adaptive._gate_admits(adaptive._mint()) is True


def test_adaptive_harness_cleans_its_temporary_artifacts(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(adaptive.tempfile, "tempdir", str(tmp_path))
    for class_name in ("evidence-omission", "ledger-tampering"):
        adaptive.adaptive_attack(class_name)
    assert list(tmp_path.iterdir()) == []


def test_validator_family_has_a_pinned_negative_control() -> None:
    variants = list(adaptive.VARIANT_GENERATORS["validator-bypass"](adaptive.DEFAULT_BUDGET))
    assert variants[0].variant_id == "authority:pinned-escalated-scope-rejected"
    assert variants[0].admits() is False
