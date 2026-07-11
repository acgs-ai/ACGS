"""Release-metadata invariants: single-sourced PEP 440 version, Beta status."""

import re
import tomllib
from pathlib import Path

import gove_zone

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"

# Release segments we allow: final, rcN, aN, bN, .devN
PEP440_RE = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?(?:\.dev\d+)?$")


def _pyproject() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def test_version_is_dynamic_single_source() -> None:
    data = _pyproject()
    assert "version" not in data["project"], "static [project].version reintroduces dual-sourcing"
    assert data["project"]["dynamic"] == ["version"]
    assert data["tool"]["hatch"]["version"]["path"] == "src/gove_zone/__init__.py"


def test_version_is_pep440_and_release_candidate() -> None:
    assert PEP440_RE.match(gove_zone.__version__), gove_zone.__version__
    assert gove_zone.__version__ == "1.0.0rc1"


def test_development_status_is_beta() -> None:
    classifiers = _pyproject()["project"]["classifiers"]
    assert "Development Status :: 4 - Beta" in classifiers
    assert not any("Production/Stable" in c for c in classifiers), (
        "Stable classifier is reserved for the human-reviewed 1.0.0 final release PR"
    )
