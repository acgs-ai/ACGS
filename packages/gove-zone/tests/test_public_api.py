"""Public-API freeze: gove_zone's top-level ``__all__`` is the semver surface.

Removing or renaming a name here is a MAJOR-version event. To intentionally
change the surface, regenerate the fixture (command in its header) and call
the change out in CHANGELOG.md.
"""

from pathlib import Path

import gove_zone

FIXTURE = Path(__file__).parent / "fixtures" / "public_api.txt"


def _pinned_names() -> list[str]:
    lines = FIXTURE.read_text().splitlines()
    return [ln for ln in lines if ln and not ln.startswith("#")]


def test_all_matches_pinned_surface() -> None:
    assert sorted(gove_zone.__all__) == _pinned_names()


def test_every_public_name_is_importable() -> None:
    missing = [name for name in gove_zone.__all__ if not hasattr(gove_zone, name)]
    assert missing == []


def test_no_duplicate_exports() -> None:
    assert len(gove_zone.__all__) == len(set(gove_zone.__all__))
