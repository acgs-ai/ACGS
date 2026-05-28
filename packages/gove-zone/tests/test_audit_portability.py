"""Portability boundary tests for the audit store.

These tests do not claim Windows append support. They only prove importing the
package does not fail just because ``fcntl`` is unavailable at module import
time.
"""

from __future__ import annotations

import subprocess
import sys
from textwrap import dedent


def test_audit_module_import_does_not_require_fcntl() -> None:
    code = dedent(
        """
        import builtins

        real_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name == "fcntl":
                raise ModuleNotFoundError("No module named 'fcntl'")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = guarded_import

        import gove_zone.audit

        assert gove_zone.audit.ChainHashAuditStore
        print("audit import ok without fcntl")
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "audit import ok without fcntl" in result.stdout
