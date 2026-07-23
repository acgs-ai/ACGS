"""Thin fixture-only entrypoint for the official-client MCP proof demo.

This module intentionally delegates to :mod:`gove_zone.cli`. It does not define
another policy, receipt gate, audit stream, proof format, or execution path.

Run from the monorepo root with one new or empty output directory::

    uv run --package gove-zone python \
        packages/gove-zone/examples/mcp-tool-gateway/demo.py /tmp/acgs-mcp-proof

The CLI emits JSON containing the proof-pack path, verification-envelope path,
and external envelope digest needed by the independent verifier and replay
commands. The runtime is local and fixture-only.
"""

from __future__ import annotations

import json
import sys
import tempfile

from gove_zone.cli import main as gove_zone_main


def main() -> int:
    """Invoke the canonical MCP demo handler without creating a parallel gate."""

    if len(sys.argv) > 2 or (len(sys.argv) == 2 and not sys.argv[1]):
        sys.stdout.write(
            json.dumps(
                {
                    "valid": False,
                    "reason_code": "MCP_DEMO_ARGUMENT_INVALID",
                    "error": "provide exactly one new or empty output directory",
                },
                sort_keys=True,
            )
            + "\n"
        )
        return 2
    # The package smoke contract executes every example without arguments. Keep
    # that path useful by retaining an owner-only temporary export whose location
    # and external digest are emitted by the canonical CLI. A caller that supplies
    # a path owns its lifecycle explicitly.
    output = (
        sys.argv[1] if len(sys.argv) == 2 else tempfile.mkdtemp(prefix="gove-zone-mcp-example-")
    )
    return gove_zone_main(["mcp", "demo", "--output", output])


if __name__ == "__main__":
    raise SystemExit(main())
