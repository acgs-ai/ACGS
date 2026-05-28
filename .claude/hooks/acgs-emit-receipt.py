#!/usr/bin/env python3
"""govern-zone PreToolUse hook — emit one governance receipt per mutating
runtime action through the canonical ``gove_zone.integration`` adapter.

Matched on ``Edit | Write | MultiEdit`` and selected ``Bash`` workflow
commands by ``.claude/settings.json``.

Behavior is governed by ``GOVE_ZONE_GATE_MODE``:

* unset / ``observe`` (default): fail-open. Import or emission failures
  exit 0 and swallow the error. Preserves existing behavior.
* ``enforce``: fail-closed. Import or emission failures exit non-zero with
  a stderr diagnostic, blocking the tool call until the operator fixes
  the audit pipeline. Set this to make the gate auditable.

No ``sys.path`` manipulation: the hook relies on ``gove-zone`` being
installed in the active interpreter's environment (workspace ``uv sync``
or ``pip install -e packages/gove-zone``).
"""

from __future__ import annotations

import json
import os
import sys


def _gate_enforce() -> bool:
    return (os.environ.get("GOVE_ZONE_GATE_MODE") or "").strip().lower() == "enforce"


def _classify(tool_name: str, tool_input: dict) -> str | None:
    if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        return "edit"
    if tool_name == "Bash":
        cmd = (tool_input.get("command") or "").lower()
        if "autopilot" in cmd:
            return "autopilot"
        if "ralph" in cmd:
            return "ralph"
        if " team " in f" {cmd} ":
            return "team"
    return None


def main() -> int:
    enforce = _gate_enforce()
    try:
        raw = sys.stdin.read()
    except Exception as exc:
        if enforce:
            print(f"gove-zone hook: stdin read failed: {exc!r}", file=sys.stderr)
            return 2
        return 0

    if not raw.strip():
        return 0

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        if enforce:
            print(f"gove-zone hook: invalid JSON payload: {exc}", file=sys.stderr)
            return 2
        return 0

    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}
    action_kind = _classify(tool_name, tool_input if isinstance(tool_input, dict) else {})
    if action_kind is None:
        return 0

    try:
        from gove_zone.integration import GateModeError, emit_receipt_for_hook
    except ImportError as exc:
        if enforce:
            print(
                "gove-zone hook: cannot import gove_zone.integration "
                f"({exc}). Install with `uv sync` or `pip install -e packages/gove-zone`.",
                file=sys.stderr,
            )
            return 2
        return 0

    actor = os.environ.get("PAPERCLIP_AGENT_ID") or "govern-zone-hook"
    run_id = os.environ.get("PAPERCLIP_RUN_ID") or None

    try:
        emit_receipt_for_hook(payload, action_kind=action_kind, actor=actor, run_id=run_id)
    except GateModeError as exc:
        print(f"gove-zone hook (enforce): {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if enforce:
            print(f"gove-zone hook (enforce): unexpected failure: {exc!r}", file=sys.stderr)
            return 2
        # observe: stay silent, preserve fail-open contract.

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # last-resort guard
        if (os.environ.get("GOVE_ZONE_GATE_MODE") or "").strip().lower() == "enforce":
            print(f"gove-zone hook: top-level failure: {exc!r}", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)
