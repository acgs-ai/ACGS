from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_typecheck_py_uses_configured_mypy_scope() -> None:
    makefile = (ROOT / "Makefile").read_text()

    assert "typecheck-py:" in makefile
    assert "grep -q '^\\[tool\\.mypy\\]'" in makefile
    assert "grep -q '^files = '" in makefile
    assert "$(UV) run $$extra mypy $$mypy_args) || exit $$?" in makefile
    assert 'mypy_args="src tests"' in makefile
    assert "$(UV) run mypy ." not in makefile
    assert "no [tool.mypy]; not gated" in makefile


def test_cft_governance_pack_has_strict_mypy_gate() -> None:
    pyproject = (ROOT / "acgs-cft-governance-pack" / "pyproject.toml").read_text()

    assert "[tool.mypy]" in pyproject
    assert "strict = true" in pyproject
    assert 'files = ["acgs_cft_governance_pack", "tests"]' in pyproject
    assert "[[tool.mypy.overrides]]" in pyproject
    assert 'module = ["yaml"]' in pyproject
    assert "ignore_missing_imports = true" in pyproject


def test_eval_mvp_has_strict_mypy_gate() -> None:
    pyproject = (ROOT / "acgs_governance_eval_mvp" / "pyproject.toml").read_text()

    assert "[tool.mypy]" in pyproject
    assert "strict = true" in pyproject
    assert 'files = ["governance", "governed_mcp_v0"]' in pyproject
    assert "[[tool.mypy.overrides]]" in pyproject
    assert "module = [" in pyproject
    assert '"yaml"' in pyproject
    assert '"dspy"' in pyproject
    assert '"opentelemetry"' in pyproject
    assert '"mcp.server.fastmcp"' in pyproject
    assert '"fastmcp"' in pyproject
    assert '"langgraph.*"' in pyproject
    assert "ignore_missing_imports = true" in pyproject


def test_acgs_swarm_has_whole_package_mypy_gate() -> None:
    """Acgs-Swarm's mypy gate covers the whole package with no adoption allow-list.

    The gate deliberately is NOT `strict = true`: the submodule documents (in its
    pyproject comments and BLOCKERS.md B3) that its contract is whole-package
    coverage with env-stable settings — strict mode plus its optional-extra type
    surfaces (websockets/langgraph ship py.typed) would flip the verdict by
    environment. This test pins the actual invariants: whole-package scope, the
    3.11 floor, and the env-robust acgs-lite override.
    """
    pyproject_path = ROOT / "packages" / "Acgs-Swarm" / "pyproject.toml"
    if not pyproject_path.exists():
        import pytest

        pytest.skip("Acgs-Swarm submodule not initialized in this checkout")
    pyproject = pyproject_path.read_text()

    assert "[tool.mypy]" in pyproject
    assert 'python_version = "3.11"' in pyproject
    # Whole-package scope — no per-file adoption list may narrow the gate.
    assert 'files = ["src/constitutional_swarm"]' in pyproject
    assert "ignore_missing_imports = true" in pyproject
    assert "warn_redundant_casts = true" in pyproject
    # acgs-lite override keeps the verdict independent of which acgs-lite build
    # (workspace vs PyPI wheel, with or without py.typed) is installed.
    assert "[[tool.mypy.overrides]]" in pyproject
    assert 'module = ["acgs_lite", "acgs_lite.*"]' in pyproject
    assert 'follow_imports = "skip"' in pyproject
