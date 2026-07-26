"""Test config — exposes scripts/ to imports as a flat module path."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

# Make scripts/ importable so tests can `import verify_constitutional_hashes`.
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
