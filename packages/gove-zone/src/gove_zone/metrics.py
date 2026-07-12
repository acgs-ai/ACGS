"""Opt-in, default-OFF receipt-emission metrics — a boundary wrapper.

This module derives operational signals (time-to-first-receipt, activation)
from the kernel's *observable* behavior without touching the kernel. The kernel
remains the source of truth: :meth:`gove_zone.kernel.Kernel.dispatch` returns
``(result, receipt)`` on ALLOW/TRANSFORM and raises
:class:`~gove_zone.errors.DeniedError` / :class:`~gove_zone.errors.EscalateError`
*before* a receipt is minted on DENY/ESCALATE. The wrapper observes both shapes,
records one leak-safe metric event, and otherwise behaves identically.

Three hard rules govern this layer:

1. **Default OFF.** Nothing is written and the wrapper is a transparent
   pass-through unless ``GOVE_ZONE_METRICS`` is truthy. The sink file is created
   only when the flag is on.
2. **Fail-closed for decisions.** A metrics or I/O failure must NEVER alter or
   block a governance decision. The ``_record`` write is wrapped in
   :func:`contextlib.suppress`; the governance call and the re-raise are not.
   Governance exceptions are recorded *then re-raised*, never swallowed.
3. **Leak-safe.** The event carries timestamp + decision + tool +
   ``argument_hash`` + ``event_id`` only — never raw args, argument values,
   ``goal``/``reason`` (which can echo argument content), receipt payload, or
   transformed args.

Zero new dependencies: stdlib only.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gove_zone.decision import DecisionRecord
    from gove_zone.kernel import Kernel

# Imported lazily inside the wrapper so this module has no import-time coupling
# to the kernel and stays safe to import even where the kernel is not used.

#: Env flag that gates ALL behavior. Unset/empty/``0``/``false`` => OFF.
METRICS_ENV = "GOVE_ZONE_METRICS"
#: Env override for the JSONL sink path. Unset => :data:`DEFAULT_SINK_PATH`.
METRICS_PATH_ENV = "GOVE_ZONE_METRICS_PATH"
#: Sane local default; created only when the flag is on.
DEFAULT_SINK_PATH = ".gove-zone/metrics.jsonl"

_TRUTHY = {"1", "true", "yes", "on"}


def _enabled() -> bool:
    """Read the gate at call time (never cached) so tests can toggle per case."""
    return os.environ.get(METRICS_ENV, "").strip().lower() in _TRUTHY


def _sink_path() -> Path:
    """Resolve the JSONL sink path at call time from the environment."""
    return Path(os.environ.get(METRICS_PATH_ENV, DEFAULT_SINK_PATH))


def _event(record: DecisionRecord) -> dict[str, Any]:
    """Build the leak-safe metric event from a decision record.

    Only non-sensitive, hash-or-id fields are included. Crucially this excludes
    raw args, ``goal``, ``reason``, ``transformed_args``, and any receipt/result
    payload — those can echo argument values.
    """
    return {
        "ts": time.time(),
        "decision": record.decision.value,
        "tool": record.tool,
        "argument_hash": record.argument_hash,
        "event_id": record.event_id,
    }


def _record(event: dict[str, Any]) -> None:
    """Append one metric event as a JSONL line to the sink.

    Isolated as the single raisable I/O point so it can be monkeypatched in
    tests and so the caller can suppress its failures without affecting the
    governance decision. Creates the parent directory and file lazily — only
    reached when the flag is on.
    """
    path = _sink_path()
    parent = path.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def metered_dispatch(kernel: Kernel, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
    """Dispatch through *kernel* and record one leak-safe metric event.

    A boundary wrapper around :meth:`gove_zone.kernel.Kernel.dispatch`:

    - When ``GOVE_ZONE_METRICS`` is unset/falsey, this is a transparent
      pass-through — no file is written and behavior is byte-for-byte identical
      to calling ``kernel.dispatch`` directly.
    - On ALLOW/TRANSFORM, ``dispatch`` returns ``(result, receipt)``; the event
      is derived from ``receipt.record`` and the tuple is returned unchanged.
    - On DENY/ESCALATE, ``dispatch`` raises ``DeniedError``/``EscalateError``;
      the event is derived from ``err.record``, then the exception is re-raised.

    A metrics/I/O failure is suppressed and never blocks or alters the decision.
    Non-governance exceptions (``UnknownToolError``, ``AuditError``, execution
    failures) propagate untouched and are not recorded.
    """
    if not _enabled():
        return kernel.dispatch(*args, **kwargs)

    from gove_zone.errors import DeniedError, EscalateError

    try:
        result = kernel.dispatch(*args, **kwargs)
    except (DeniedError, EscalateError) as err:
        with contextlib.suppress(Exception):
            _record(_event(err.record))
        raise

    _, receipt = result
    with contextlib.suppress(Exception):
        _record(_event(receipt.record))
    return result
