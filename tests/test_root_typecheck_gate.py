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


def test_acgs_swarm_has_strict_core_mypy_gate() -> None:
    pyproject = (ROOT / "packages" / "Acgs-Swarm" / "pyproject.toml").read_text()

    assert "[tool.mypy]" in pyproject
    assert "python_version = \"3.11\"" in pyproject
    assert "strict = true" in pyproject
    for source_file in [
        "src/constitutional_swarm/artifact.py",
        "src/constitutional_swarm/capability.py",
        "src/constitutional_swarm/execution.py",
        "src/constitutional_swarm/governance_receipts.py",
        "src/constitutional_swarm/swarm.py",
    ]:
        assert f'"{source_file}"' in pyproject
