from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_typecheck_py_uses_configured_mypy_scope() -> None:
    makefile = (ROOT / "Makefile").read_text()

    assert "typecheck-py:" in makefile
    assert "grep -q '^\\[tool\\.mypy\\]'" in makefile
    assert "grep -q '^files = '" in makefile
    assert "$(UV) run mypy) || exit $$?" in makefile
    assert "$(UV) run mypy src tests) || exit $$?" in makefile
    assert "$(UV) run mypy ." not in makefile
    assert "mypy skipped — not configured" in makefile


def test_cft_governance_pack_has_strict_mypy_gate() -> None:
    pyproject = (ROOT / "acgs-cft-governance-pack" / "pyproject.toml").read_text()

    assert "[tool.mypy]" in pyproject
    assert "strict = true" in pyproject
    assert 'files = ["acgs_cft_governance_pack", "tests"]' in pyproject
    assert "[[tool.mypy.overrides]]" in pyproject
    assert 'module = ["yaml"]' in pyproject
    assert "ignore_missing_imports = true" in pyproject
