"""Run the shipped example demos end-to-end so they cannot silently rot.

Each demo is a self-contained, tempdir-only script with a ``python demo.py``
entry that exits 0 on success (it asserts its own invariants and returns
non-zero if any fail). Running them here through a subprocess — the same way a
reader would — proves they still execute against the current kernel API, not
just that they import. This is the wiring proof for the integration and
evidence demos added alongside the production-profile default.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# These demos deliberately run under the production signed profile and generate
# an in-process Ed25519 keypair, so they require the optional ``crypto`` extra
# (``cryptography``). Skip cleanly when it is absent rather than hard-failing in
# a minimal install; a crypto-extra CI lane exercises them for real.
pytest.importorskip("cryptography", reason="signed-receipt example demos require the optional 'crypto' extra")

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

# Demos that run to a clean exit 0 with no arguments and no stdin.
_RUNNABLE_DEMOS = [
    "mcp-tool-gateway/demo.py",
    "agent-framework-wrapper/demo.py",
    "ci-deployment-gate/demo.py",
    "undeniable-demo/demo.py",
]


@pytest.mark.parametrize("rel_path", _RUNNABLE_DEMOS)
def test_example_demo_runs_clean(rel_path: str) -> None:
    demo = _EXAMPLES / rel_path
    assert demo.is_file(), f"demo missing: {demo}"
    result = subprocess.run(
        [sys.executable, str(demo)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, (
        f"{rel_path} exited {result.returncode}\n"
        f"--- stdout (tail) ---\n{result.stdout[-2000:]}\n"
        f"--- stderr (tail) ---\n{result.stderr[-2000:]}"
    )
