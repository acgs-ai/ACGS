"""Make the pure-source gove-zone package importable during tests/docs collection.

``tests/docs`` runs at the repo root *without* installing gove-zone — see
``.github/workflows/tests-docs.yml``, which only injects ``packages/gove-zone/src``
onto ``PYTHONPATH`` for the demo *subprocesses* it spawns, not into the pytest
process itself. Modules that import ``gove_zone`` at top level during collection
(e.g. ``test_signing_default_doc_matches_code.py``) therefore fail with
``ModuleNotFoundError`` unless the source is on ``sys.path`` in-process.

``conftest.py`` is imported by pytest before it collects any test module, so this
guarantees the path is set first. gove-zone is pure-source with zero runtime
dependencies, so a ``sys.path`` entry is sufficient — no install step needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

_GOVE_ZONE_SRC = Path(__file__).resolve().parents[2] / "packages" / "gove-zone" / "src"
if _GOVE_ZONE_SRC.is_dir() and str(_GOVE_ZONE_SRC) not in sys.path:
    sys.path.insert(0, str(_GOVE_ZONE_SRC))
