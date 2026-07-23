"""Worked end-to-end example: governed file writes.

Demonstrates the full kernel loop on a single tool — ``write_file``:

  Goal → Proposed Action → Governance Decision → Tool Execution or Denial
       → Receipt → Audit Log

Run::

    PYTHONPATH=packages/gove-zone/src python3 packages/gove-zone/examples/write_file_guard.py
"""

from __future__ import annotations

import json

from gove_zone import run_smoke


def main() -> None:
    print(json.dumps(run_smoke(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
