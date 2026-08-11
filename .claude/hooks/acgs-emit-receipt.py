#!/usr/bin/env python3
"""govern-zone PreToolUse hook — route every matched tool call through the
governed decision gateway (ADR-0010 / P11, Execution Governance Layer).

This hook replaces a passive auditor with an enforced gateway. Three things
changed, and each closes a specific finding from the 2026-08-09 incident:

1. **The decision surface.** ``UniversalGateway.handle_claude_hook`` evaluates a
   real ``CompositePolicy`` and mints a ``DecisionReceipt``. It supersedes
   ``integration.emit_receipt_for_hook``, whose ``_ObserverPolicy`` returned
   ``ALLOW`` unconditionally and emitted the 5-field ``Receipt``, which has no
   signature field and which ``execute_with_receipt`` does not accept.

2. **Classification.** Bash commands are classified structurally by
   :func:`gove_zone.execution.classify_command` (argv prefix), replacing the
   substring matcher that produced three observed false positives — including a
   ``grep`` audited as an ``autopilot`` orchestration event. Nothing is exempt
   from audit any more: the old classifier returned ``None`` for anything it did
   not recognize and the hook exited 0 unaudited, which is why the live chain
   held 396 records and exactly one ``runtime.Bash``.

3. **Attribution.** The actor comes from :func:`resolve_execution_actor`, which
   states its source rather than falling back to a hardcoded
   ``"govern-zone-hook"``. It is still an environment-derived identity, not an
   authenticated principal — the residual is recorded in the receipt as
   ``attribution_source`` rather than papered over.

**Boundary statement.** ``execute_with_receipt`` is *not* called here: the host
runtime performs the side effect. What this hook produces is a minted,
verifiable Decision Receipt for the *decision*. It is not receipt-gated
execution — only ``UniversalGateway.invoke`` closes that loop.

Output protocol: a JSON ``hookSpecificOutput`` object on stdout with exit 0.
Exit 2 remains the fail-closed channel for a hook that cannot decide at all.

**A policy ALLOW defers to host permissions.** The Claude Code PreToolUse
contract defines ``permissionDecision: "allow"`` as *bypassing* the host's own
permission system, so echoing every policy ALLOW would silently override the
explicit deny entries in ``.claude/settings.json``. This hook therefore only
ever tightens: ``deny``/``ask`` verdicts are returned as-is, while an ALLOW
strips the permission decision from the response (see :func:`_defer_allow`),
leaving the receipt anchors attached and the host permission flow live.

Gate mode (``gove_zone.integration.current_gate_mode`` — env var, then
``.gove-zone/gate.mode``, then the fail-closed ``enforce`` default):

* ``enforce`` (default): a deny/ask verdict is returned as-is; an import,
  parse, or governance failure exits 2 and blocks the call.
* ``observe`` (explicit, time-boxed opt-in): the decision is still evaluated,
  recorded, and receipted, but the permission decision is withheld so the host
  permission system alone decides — never an explicit ``allow``, which would
  bypass configured denials. Per ADR-0010 D6 an indefinitely-observing gate is
  the failure this layer exists to correct — this mode is for cutover only.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any


def _gate_enforce() -> bool:
    """Delegate to the library resolver; fail closed when it cannot be loaded."""
    try:
        from gove_zone.integration import GateMode, current_gate_mode
    except Exception:
        return True
    return current_gate_mode() is GateMode.ENFORCE


def _emit(response: dict[str, Any]) -> int:
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


def _defer_allow(response: dict[str, Any]) -> dict[str, Any]:
    """Strip an explicit ``allow`` so the host permission system stays live.

    The PreToolUse contract treats ``permissionDecision: "allow"`` as bypassing
    the host's configured permissions, so an echoed policy ALLOW would override
    the explicit deny entries in ``.claude/settings.json`` (``git add .``,
    ``git reset --hard``, ...). A policy ALLOW is a governance statement, not a
    permission grant: keep the receipt anchors, omit the permission decision,
    and let the host decide. Deny/ask verdicts pass through untouched.
    """
    block = dict(response.get("hookSpecificOutput") or {})
    if str(block.get("permissionDecision", "")) != "allow":
        return response
    block.pop("permissionDecision", None)
    block.pop("permissionDecisionReason", None)
    deferred = dict(response)
    deferred["hookSpecificOutput"] = block
    return deferred


def _observe_downgrade(response: dict[str, Any]) -> dict[str, Any]:
    block = dict(response.get("hookSpecificOutput") or {})
    verdict = str(block.get("permissionDecision", "allow"))
    if verdict == "allow":
        return _defer_allow(response)
    # Withhold the verdict rather than rewriting it to "allow": an explicit
    # allow would bypass the host permission system, which observe mode must
    # leave fully in charge.
    block.pop("permissionDecision", None)
    block.pop("permissionDecisionReason", None)
    downgraded = dict(response)
    downgraded["hookSpecificOutput"] = block
    print(
        f"gove-zone hook (observe): decision {verdict!r} recorded but not enforced "
        "(deferred to host permissions)",
        file=sys.stderr,
    )
    return downgraded


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

    if not isinstance(payload, dict):
        if enforce:
            print("gove-zone hook: payload is not a JSON object", file=sys.stderr)
            return 2
        return 0

    try:
        from gove_zone.execution import (
            build_execution_gateway,
            declared_package_manager,
            make_execution_call_factory,
            resolve_execution_actor,
        )
    except ImportError as exc:
        if enforce:
            print(
                "gove-zone hook: cannot import gove_zone.execution "
                f"({exc}). Install with `uv sync` or `pip install -e packages/gove-zone`.",
                file=sys.stderr,
            )
            return 2
        return 0

    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    actor, attribution_source = resolve_execution_actor()
    run_id = (
        os.environ.get("PAPERCLIP_RUN_ID")
        or (payload.get("session_id") if isinstance(payload.get("session_id"), str) else "")
        or ""
    )

    try:
        gateway = build_execution_gateway()
        response = gateway.handle_claude_hook(
            payload,
            actor=actor,
            action_kind=str(payload.get("hook_event_name") or "PreToolUse"),
            call_factory=make_execution_call_factory(
                declared_package_manager(project_dir),
                run_context={"run_id": run_id, "attribution_source": attribution_source},
            ),
        )
    except Exception as exc:
        if enforce:
            print(f"gove-zone hook (enforce): governance unavailable: {exc!r}", file=sys.stderr)
            return 2
        return 0

    response = _defer_allow(response) if enforce else _observe_downgrade(response)
    return _emit(response)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # last-resort guard — fail closed, do not guess
        print(f"gove-zone hook: top-level failure: {exc!r}", file=sys.stderr)
        sys.exit(2)
