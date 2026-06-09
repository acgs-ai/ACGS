"""End-to-end demo: a Claude Code ``PreToolUse`` Edit event passes through
the gove-zone runtime-hook gate and lands in the audit chain.

Run from the repo root::

    uv run --package gove-zone python packages/gove-zone/examples/runtime_hook_demo.py

What this demonstrates:

1. The runtime sends an opaque hook payload (``tool_name`` + ``tool_input``).
2. :func:`gove_zone.integration.emit_receipt_for_hook` translates it into a
   governance :class:`Receipt` and appends to the audit JSONL chain.
3. :func:`ChainHashAuditStore.verify_chain` confirms tamper-evident integrity.
4. In ``GOVE_ZONE_GATE_MODE=enforce``, the same flow fails closed when the
   audit path is unwritable — proving the gate has teeth.

No real Claude Code session is required.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.integration import (
    GateMode,
    GateModeError,
    current_gate_mode,
    emit_receipt_for_hook,
    resolve_audit_path,
)


def _synthetic_edit_payload() -> dict[str, Any]:
    return {
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/repo/README.md",
            "old_string": "old line",
            "new_string": "new line",
        },
    }


def _banner(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gove-zone-demo-") as scratch:
        os.environ["CLAUDE_PROJECT_DIR"] = scratch
        os.environ.pop("GOVE_ZONE_AUDIT_PATH", None)
        os.environ.pop("GOVE_ZONE_GATE_MODE", None)

        audit_path = resolve_audit_path()
        _banner("1. Observe mode: append a receipt for an Edit event")
        print(f"audit path : {audit_path}")
        print(f"gate mode  : {current_gate_mode().value}")

        receipt = emit_receipt_for_hook(
            _synthetic_edit_payload(),
            action_kind="edit",
            actor="demo-actor",
            run_id="demo-run-001",
        )
        assert receipt is not None, "observe-mode emission should succeed"
        print("receipt    :")
        print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))

        _banner("2. Verify the audit chain")
        store = ChainHashAuditStore(audit_path)
        verdict = store.verify_chain()
        print(json.dumps(verdict, indent=2, sort_keys=True))
        assert verdict["valid"] is True

        _banner("3. Enforce mode + bad audit path: fail closed")
        os.environ["GOVE_ZONE_GATE_MODE"] = "enforce"
        # The passive runtime-hook auditor emits unsigned audit-anchor Receipts.
        # Under the production profile (the default), ENFORCE mode would fail closed
        # loud because no signer is threaded into emit_receipt_for_hook. This beat
        # isolates the GateMode emission-failure behavior, so explicitly select the
        # dev profile — signing is orthogonal to GateMode.
        os.environ["GOVE_ZONE_PROFILE"] = "dev"
        os.environ["GOVE_ZONE_AUDIT_PATH"] = "/proc/1/cannot/write/audit.jsonl"
        print(f"gate mode  : {current_gate_mode().value}")
        try:
            emit_receipt_for_hook(
                _synthetic_edit_payload(),
                action_kind="edit",
                actor="demo-actor",
            )
        except GateModeError as exc:
            print(f"raised     : {type(exc).__name__}: {exc}")
        else:
            raise SystemExit("enforce mode failed to fail-closed")

        _banner("4. Enforce mode + writable path: still passes")
        os.environ.pop("GOVE_ZONE_AUDIT_PATH", None)
        os.environ["CLAUDE_PROJECT_DIR"] = scratch
        receipt2 = emit_receipt_for_hook(
            _synthetic_edit_payload(),
            action_kind="edit",
            actor="demo-actor",
        )
        assert receipt2 is not None
        assert current_gate_mode() is GateMode.ENFORCE
        print(f"enforce-mode receipt audit_hash: {receipt2.audit_hash[:16]}…")

        print("\nAll demo assertions passed.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
