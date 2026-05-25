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
