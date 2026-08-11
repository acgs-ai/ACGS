"""Guards for ``tools/kg/docker-compose.yml`` credential handling.

REGRESSION. The Neo4j healthcheck interpolated ``${NEO4J_PASSWORD}`` at Compose
parse time straight into a ``CMD-SHELL`` command: a password containing
whitespace split into extra arguments and shell metacharacters executed, so a
correctly configured container was marked unhealthy forever. The healthcheck
must expand the credential inside the container, quoted, from the environment
Compose already sets (``NEO4J_AUTH=neo4j/<password>``).
"""

from __future__ import annotations

import re
from pathlib import Path

COMPOSE = Path(__file__).resolve().parent.parent / "tools" / "kg" / "docker-compose.yml"


def healthcheck_test_line() -> str:
    text = COMPOSE.read_text()
    m = re.search(r"^\s*test:\s*(.+)$", text, re.M)
    assert m, "compose file no longer declares a healthcheck test"
    return m.group(1)


def test_healthcheck_does_not_splice_the_host_password_into_the_shell():
    """A single ``$`` is Compose-time interpolation: the raw password lands
    unquoted in the shell command. Only ``$$`` (container-time) is safe."""
    line = healthcheck_test_line()

    assert not re.search(r"(?<!\$)\$\{NEO4J_PASSWORD", line)


def test_healthcheck_expands_the_container_credential_quoted():
    line = healthcheck_test_line()

    assert re.search(r"\\\"\$\$\{NEO4J_AUTH#neo4j/\}\\\"", line), (
        "healthcheck must pass the container's NEO4J_AUTH-derived password "
        f"as a double-quoted shell expansion, got: {line}"
    )


def test_compose_still_derives_auth_from_the_documented_password_override():
    """The Makefile documents ``NEO4J_PASSWORD`` as the override knob; the
    container's NEO4J_AUTH (which the healthcheck reads) must keep honouring
    it, defaulting to the local dev password."""
    text = COMPOSE.read_text()

    assert 'NEO4J_AUTH: "neo4j/${NEO4J_PASSWORD:-acgs-kg-local}"' in text
