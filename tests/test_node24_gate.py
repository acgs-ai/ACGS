"""Tests for the local acgi-ai Node 24 verification wrapper."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_node24_gate_script_is_executable_and_fail_closed():
    script = ROOT / "scripts" / "run_acgi_node24_gate.sh"
    source = script.read_text()

    assert script.is_file()
    assert os.access(script, os.X_OK)
    assert "set -euo pipefail" in source
    assert "fnm use" in source
    assert "process.versions.node" in source
    assert "packageManager.split('@')" in source
    assert "pnpm -F acgi-ai run test:all" in source


def test_makefile_exposes_node24_verification_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "verify-js-node24:" in makefile
    assert "bash scripts/run_acgi_node24_gate.sh $(PNPM) -F acgi-ai run test:all" in makefile
