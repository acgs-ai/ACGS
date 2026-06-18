"""Runner for the offline proof-pack fixture corpus (B4 §8).

For every committed pack under ``fixtures/proofpacks/<name>/`` this asserts
``verify_proof_pack`` returns the DECLARED ``valid`` AND that the declared
``expected_reasons`` are a subset of the observed reasons (the runner only
requires the load-bearing codes to be present, not an exact set). A second test
regenerates the whole matrix into ``tmp_path`` and runs the same assertions —
proving the generator, not the committed snapshot, is the source of truth (the
kernel path is nondeterministic, so there is intentionally NO byte-drift guard).

Non-bypassability (spec §6) and the module-boundary guard (spec §5.4, AST-based)
prove the checks are load-bearing and the verifier stays engine-independent.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

cryptography = pytest.importorskip("cryptography")  # signed packs need verification

from gove_zone import Ed25519Signer  # noqa: E402
from gove_zone.verifier import (  # noqa: E402
    ProofPackVerificationResult,
    verify_proof_pack,
)

CORPUS = Path(__file__).parent / "fixtures" / "proofpacks"
_GENERATOR = Path(__file__).parent / "fixtures" / "_generate_proofpacks.py"
_VERIFIER_SRC = Path(__file__).parents[1] / "src" / "gove_zone" / "verifier.py"
_NOW = "2026-01-01T00:00:00+00:00"

# Rebuild the public-key verifier from the same fixed seed the generator signs with
# (mirrors test_fixture_corpus.py). A pack's meta.json names which verifier to use.
_SEED = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
_TRUSTED = Ed25519Signer.from_public_bytes(
    Ed25519Signer.from_private_bytes(_SEED, key_id="fixture-key-1").public_bytes(),
    key_id="fixture-key-1",
)
_VERIFIERS: dict[str, Any] = {"trusted": _TRUSTED, "none": None}


def _load_meta(pack: Path) -> dict[str, Any]:
    return json.loads((pack / "meta.json").read_text(encoding="utf-8"))


def _run(pack: Path) -> tuple[ProofPackVerificationResult, dict[str, Any]]:
    meta = _load_meta(pack)
    result = verify_proof_pack(pack, verifier=_VERIFIERS[meta["verifier"]], now_iso=_NOW)
    return result, meta


def _assert_matches_meta(
    result: ProofPackVerificationResult, meta: dict[str, Any], name: str
) -> None:
    assert result.valid == meta["expected_valid"], (
        f"{name}: valid={result.valid!r}, expected {meta['expected_valid']!r} "
        f"(reasons={result.reasons})"
    )
    observed = {str(r) for r in result.reasons}
    expected = set(meta["expected_reasons"])
    assert expected.issubset(observed), (
        f"{name}: expected reasons {sorted(expected)} not all present in {sorted(observed)}"
    )


def _committed_pack_names() -> list[str]:
    return sorted(p.name for p in CORPUS.iterdir() if p.is_dir())


def _load_generator() -> Any:
    spec = importlib.util.spec_from_file_location("_proofpack_gen", _GENERATOR)
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


@pytest.mark.parametrize("name", _committed_pack_names())
def test_committed_pack_verdict_and_reasons(name: str) -> None:
    result, meta = _run(CORPUS / name)
    _assert_matches_meta(result, meta, name)


def test_corpus_is_nonempty_and_covers_both_outcomes() -> None:
    names = _committed_pack_names()
    metas = [_load_meta(CORPUS / n) for n in names]
    outcomes = {m["expected_valid"] for m in metas}
    assert outcomes == {True, False}, outcomes
    assert len(names) == 9


def test_regenerated_matrix_matches_meta(tmp_path: Path) -> None:
    """The generator is the source of truth: regenerate the matrix into a temp dir
    and assert the SAME verdicts. The kernel path is nondeterministic (wall-clock +
    uuid), so this pins the verdict contract, never the bytes.
    """
    gen = _load_generator()
    fresh = tmp_path / "proofpacks"
    n = gen.write_proofpacks(fresh)
    assert n == 9
    assert sorted(p.name for p in fresh.iterdir() if p.is_dir()) == _committed_pack_names()
    for pack in sorted(p for p in fresh.iterdir() if p.is_dir()):
        result, meta = _run(pack)
        _assert_matches_meta(result, meta, pack.name)


def test_negative_control_checks_are_load_bearing() -> None:
    """Spec §6: prove the verifier's verdict is NOT a tautology a trivial accept would pass.

    A no-op ``lambda: True`` "verifier" would accept the tampered/chain-break packs;
    the real ``verify_proof_pack`` rejects them. Asserting the real verdict DIFFERS
    from the trivial-accept verdict proves the checks are load-bearing.
    """

    def trivial_accept(_pack: Path) -> bool:
        return True  # a verifier that skips every check

    for name in ("tampered-receipt", "chain-break"):
        pack = CORPUS / name
        result, _ = _run(pack)
        assert result.valid is False, f"{name}: real verifier must reject"
        assert trivial_accept(pack) is True
        assert result.valid != trivial_accept(pack), (
            f"{name}: real verdict must differ from a trivial accept"
        )


def test_verifier_module_is_engine_independent() -> None:
    """Spec §5.4: verifier.py must not import the enforcement engine at module scope.

    AST-based, not sys.modules-based: importing the submodule triggers the package
    ``__init__`` which eagerly loads everything, so sys.modules cannot prove
    independence. The source AST can: collect MODULE-SCOPE imports and assert none
    are engine modules, while the replay tier's engine imports live in function
    bodies (lazy) — proving the tier exists but is deferred.
    """
    tree = ast.parse(_VERIFIER_SRC.read_text(encoding="utf-8"))
    engine = {
        "gove_zone.kernel",
        "gove_zone.executor",
        "gove_zone.policy",
        "gove_zone.replay",
        "gove_zone.replay_store",
    }

    def _imported_modules(nodes: Any) -> set[str]:
        mods: set[str] = set()
        for node in nodes:
            if isinstance(node, ast.Import):
                mods.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module)
        return mods

    module_scope = _imported_modules(
        n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))
    )
    function_scope: set[str] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_scope |= _imported_modules(
                x for x in ast.walk(fn) if isinstance(x, (ast.Import, ast.ImportFrom))
            )

    assert not (module_scope & engine), (
        f"verifier.py imports the engine at module scope: {sorted(module_scope & engine)}"
    )
    # The decision-replay tier (policy + replay + replay_store) is imported lazily —
    # present in function bodies, proving the tier exists but is deferred.
    assert {"gove_zone.policy", "gove_zone.replay", "gove_zone.replay_store"} <= function_scope, (
        f"lazy replay-tier imports missing from function bodies: {sorted(function_scope)}"
    )
