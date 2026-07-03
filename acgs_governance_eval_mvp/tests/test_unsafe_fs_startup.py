"""Startup-level proof for the unsafe-filesystem guard.

``governance.service.api`` constructs a ``ChainHashAuditStore`` at import
time (module-level ``_adapter = build_adapter()``), so a service whose
audit path resolves to an unreliable filesystem must *refuse to start*:
the import fails and the interpreter exits non-zero. The positive
control proves the same import exits zero on a local filesystem.

Subprocess-based so the assertion is on the literal process exit code,
not on an in-process exception.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]

_UNSAFE_SNIPPET = """
import governance.audit.jsonl_chain as jsonl_chain
jsonl_chain._detect_fs_type = lambda path: "nfs"
import governance.service.api  # noqa: F401  (module-level build_adapter())
"""

_SAFE_SNIPPET = """
import governance.service.api  # noqa: F401  (module-level build_adapter())
"""


def _run_service_import(snippet: str, audit_path: Path) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "ACGS_AUDIT_PATH": str(audit_path),
        "ACGS_ROLES_PATH": str(_PACKAGE_ROOT / "governance" / "roles.json"),
        "ACGS_POLICY_DIR": str(_PACKAGE_ROOT / "governance" / "policies" / "2026-05"),
    }
    return subprocess.run(
        [sys.executable, "-c", snippet],
        cwd=_PACKAGE_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_service_refuses_to_start_on_unreliable_fs(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    result = _run_service_import(_UNSAFE_SNIPPET, audit_path)
    assert result.returncode != 0, (
        f"service import must exit non-zero on an unreliable audit filesystem; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "UnsafeAuditStorageError" in result.stderr
    assert "nfs" in result.stderr
    # Refuse-to-start must leave no audit bytes behind.
    assert not audit_path.exists()


def test_service_starts_on_local_fs(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    result = _run_service_import(_SAFE_SNIPPET, audit_path)
    assert result.returncode == 0, (
        f"positive control failed: service import must exit 0 on a local filesystem; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
