"""Guards for ``tools/kg/Makefile`` credential handling.

REGRESSION. Recipes that expanded ``$(NEO4J_PASSWORD)`` at make time spliced
the credential into shell source *before* the shell parsed it: an override
containing a double quote or ``$(...)`` substitution executed as code (a
quoted ``touch`` payload in the password created the requested file via
``make browser``). Every recipe must instead expand the exported value at
shell time — ``$$NEO4J_PASSWORD`` inside double quotes — where it is data.
"""

from __future__ import annotations

from pathlib import Path

MAKEFILE = Path(__file__).resolve().parent.parent / "tools" / "kg" / "Makefile"


def recipe_lines() -> list[str]:
    return [line for line in MAKEFILE.read_text().splitlines() if line.startswith("\t")]


def test_no_recipe_expands_the_password_at_make_time():
    """``$(NEO4J_PASSWORD)`` in a recipe is make-time interpolation: the raw
    password lands in shell source unquoted. Only the exported
    ``$$NEO4J_PASSWORD`` (shell-time, inside double quotes) is safe."""
    offenders = [line for line in recipe_lines() if "$(NEO4J_PASSWORD)" in line]

    assert offenders == [], f"make-time password interpolation in recipes: {offenders}"


def test_credential_consuming_recipes_use_the_exported_shell_variable():
    """The up readiness loop, cypher-shell, and the browser hint all need the
    credential; each must read the exported environment variable."""
    text = MAKEFILE.read_text()

    assert "export NEO4J_PASSWORD" in text
    assert text.count("$$NEO4J_PASSWORD") >= 3
