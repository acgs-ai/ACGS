"""Wiring defect detection — US2 scope (T038-T041).

Three public surfaces:

    sample_registry(bus, gove_zone_kernel=None) -> HandlerRegistrySnapshot
        Reflect the runtime's registered handler table into a snapshot.

    static_declared_handlers(roots) -> set[str]
        AST-scan allowlisted roots for ``@kernel.tool(...)`` and
        ``@bus.handler(...)`` decorator usages, returning the handler names
        the source declares.

    compute_findings(snapshot, recent_events, window_seconds) -> WiringDefectSummary
        Join snapshot against events; produce ``unwired_dispatch`` and
        ``declared_but_unrouted`` findings. Idempotent on (kind, handler_name).

Constitution Principle II: ``static_declared_handlers`` REFUSES to descend
into any root that contains a ``.git`` file or directory — submodule
boundaries are hard stops.
"""

from __future__ import annotations

import ast
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agent_bus_analyzer.models import (
    HandlerDescriptor,
    HandlerRegistrySnapshot,
    WiringDefectFinding,
    WiringDefectSummary,
)

log = logging.getLogger("agent_bus_analyzer.wiring")

# ---- allowlisted roots for static scan ------------------------------------

_SCAN_ROOTS_REL: list[str] = [
    "packages/agent-bus-analyzer",
    "packages/gove-zone",
    "acgi-ai/src/api",
]


# ---- runtime bus protocol -------------------------------------------------


@runtime_checkable
class BusWithHandlers(Protocol):
    """Minimal surface we consume on the bus for registry sampling."""

    def get_registered_handlers(self) -> dict[str, Any]: ...


@runtime_checkable
class KernelWithTools(Protocol):
    """Minimal surface we consume on the gove-zone kernel for tool sampling."""

    def get_registered_tools(self) -> dict[str, Any]: ...


# ---- registry sampling ----------------------------------------------------


def sample_registry(
    bus: Any,
    gove_zone_kernel: Any = None,
) -> HandlerRegistrySnapshot:
    """Reflect runtime handler registrations into a ``HandlerRegistrySnapshot``.

    Accepts any object that exposes ``get_registered_handlers()``
    (BusWithHandlers) and optionally a gove-zone kernel exposing
    ``get_registered_tools()`` (KernelWithTools). Both are structural — no
    import of the real bus/kernel packages is required.

    If neither surface is available the snapshot is empty (not an error);
    callers can use the static-scan path instead.
    """
    now = datetime.now(UTC)
    handlers: dict[str, HandlerDescriptor] = {}

    source: str = "enhanced_agent_bus"

    if isinstance(bus, BusWithHandlers):
        try:
            raw = bus.get_registered_handlers()
            for name, entry in raw.items():
                last_seen: datetime | None = None
                ts = getattr(entry, "last_seen_at", None) or (
                    entry.get("last_seen_at") if isinstance(entry, dict) else None
                )
                if ts is not None:
                    if isinstance(ts, datetime):
                        last_seen = ts
                    else:
                        try:
                            last_seen = datetime.fromisoformat(str(ts))
                        except ValueError:
                            pass
                handlers[name] = HandlerDescriptor(
                    name=name,
                    declared_in_source=False,
                    registered_in_runtime=True,
                    last_seen_at=last_seen,
                )
        except Exception:
            log.warning(
                "wiring.sample_registry: bus.get_registered_handlers() failed",
                exc_info=True,
            )

    if gove_zone_kernel is not None and isinstance(gove_zone_kernel, KernelWithTools):
        source = "gove_zone_kernel"
        try:
            raw = gove_zone_kernel.get_registered_tools()
            for name, _entry in raw.items():
                if name not in handlers:
                    handlers[name] = HandlerDescriptor(
                        name=name,
                        declared_in_source=False,
                        registered_in_runtime=True,
                        last_seen_at=None,
                    )
        except Exception:
            log.warning(
                "wiring.sample_registry: kernel.get_registered_tools() failed",
                exc_info=True,
            )

    return HandlerRegistrySnapshot(
        snapshot_id=str(uuid.uuid4()),
        sampled_at=now,
        handlers=handlers,
        source=source,  # type: ignore[arg-type]
    )


# ---- AST static analysis --------------------------------------------------


def _is_submodule_root(root: Path) -> bool:
    """Return True if *root* contains a .git entry — submodule boundary."""
    git_candidate = root / ".git"
    return git_candidate.exists()


def _extract_names_from_decorator(
    node: ast.expr,
    func_name: str,
    attr_names: frozenset[str],
) -> list[str]:
    """Extract handler/tool names from a single decorator expression.

    Handles:
      @bus.handler("name")   -> "name"
      @kernel.tool("name")   -> "name"
      @bus.handler           -> func_name  (bare attribute ref, no call)
      @kernel.tool()         -> func_name  (call with no args)
    """
    names: list[str] = []

    # @obj.attr("name", ...) or @obj.attr()
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in attr_names
            and isinstance(func.value, ast.Name)
        ):
            # First positional string arg is the registered name.
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                names.append(first.value)
            else:
                # No explicit name → fall back to function name.
                names.append(func_name)
    # @obj.attr  (bare ref, no call parens)
    elif (
        isinstance(node, ast.Attribute)
        and node.attr in attr_names
        and isinstance(node.value, ast.Name)
    ):
        names.append(func_name)

    return names


_DECORATOR_ATTRS = frozenset({"tool", "handler"})


def _scan_file(path: Path) -> set[str]:
    """Return all handler/tool names declared in *path* via decorators."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError, ValueError):
        log.debug("wiring.static_scan: skipping unparseable file %s", path)
        return set()

    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            found.update(_extract_names_from_decorator(dec, node.name, _DECORATOR_ATTRS))
    return found


def static_declared_handlers(roots: list[Path]) -> set[str]:
    """AST-scan *roots* for handler/tool decorator declarations.

    Constitution Principle II: refuses to descend into any root whose
    direct path contains a ``.git`` file or directory (submodule boundary).

    Only ``.py`` files are scanned; symlinks are not followed across
    resolved boundaries.
    """
    declared: set[str] = set()
    for root in roots:
        root = root.resolve()
        if not root.exists():
            log.debug("wiring.static_scan: root does not exist: %s", root)
            continue
        if _is_submodule_root(root):
            log.warning(
                "wiring.static_scan: REFUSING root with .git (submodule boundary): %s",
                root,
            )
            continue
        for py_file in root.rglob("*.py"):
            # Prevent symlink escape: verify the resolved path is still under root.
            try:
                resolved = py_file.resolve()
            except OSError:
                continue
            if not str(resolved).startswith(str(root)):
                log.debug("wiring.static_scan: skipping symlink escape %s", py_file)
                continue
            found = _scan_file(py_file)
            declared.update(found)
    return declared


# ---- defect computation ---------------------------------------------------


def compute_findings(
    snapshot: HandlerRegistrySnapshot,
    recent_events: list[dict[str, Any]],
    window_seconds: float = 60.0,
) -> WiringDefectSummary:
    """Join snapshot against events to produce a WiringDefectSummary.

    Two defect kinds:

    ``unwired_dispatch``
        A dispatch event targets a handler that is NOT in the registry
        snapshot (i.e. the handler was never registered at runtime).

    ``declared_but_unrouted``
        A handler appears in the registry snapshot but received NO dispatch
        events in the observation window.

    Deduplication: one finding per (kind, handler_name). Up to 5 example
    event_ids per finding (Pydantic max_length=5 on the field).

    The function is pure / idempotent on its inputs.
    """
    now = datetime.now(UTC)
    cutoff_ts = now.timestamp() - window_seconds

    registry_names = set(snapshot.handlers.keys())

    # --- pass 1: dispatched handler names in window -----------------------
    dispatched: dict[str, list[str]] = {}  # handler_name -> [event_ids]
    for ev in recent_events:
        try:
            recorded_at_raw = ev.get("recorded_at")
            if recorded_at_raw is None:
                continue
            recorded_dt = datetime.fromisoformat(str(recorded_at_raw))
            # normalise to UTC timestamp for comparison
            if recorded_dt.tzinfo is None:
                ev_ts = recorded_dt.timestamp()
            else:
                ev_ts = recorded_dt.timestamp()
            if ev_ts < cutoff_ts:
                continue
        except (ValueError, TypeError):
            continue

        if ev.get("kind") != "dispatch":
            continue

        target = ev.get("target_handler_declared") or ev.get("target_handler_resolved")
        if not target:
            continue
        event_id = str(ev.get("event_id", ""))
        dispatched.setdefault(target, []).append(event_id)

    # --- pass 2: build findings -------------------------------------------
    # Dedup key: (kind, handler_name) → WiringDefectFinding
    findings_map: dict[tuple[str, str], WiringDefectFinding] = {}

    # unwired_dispatch: dispatched but not in registry
    for handler_name, event_ids in dispatched.items():
        if handler_name not in registry_names:
            key = ("unwired_dispatch", handler_name)
            if key not in findings_map:
                findings_map[key] = WiringDefectFinding(
                    finding_id=str(uuid.uuid4()),
                    detected_at=now,
                    kind="unwired_dispatch",
                    handler_name=handler_name,
                    expected_role="registered handler",
                    example_event_ids=event_ids[:5],
                )

    # declared_but_unrouted: in registry but received no dispatches in window
    for handler_name in registry_names:
        if handler_name not in dispatched:
            key = ("declared_but_unrouted", handler_name)
            if key not in findings_map:
                findings_map[key] = WiringDefectFinding(
                    finding_id=str(uuid.uuid4()),
                    detected_at=now,
                    kind="declared_but_unrouted",
                    handler_name=handler_name,
                    expected_role=None,
                    example_event_ids=[],
                )

    return WiringDefectSummary(
        refreshed_at=now,
        findings=list(findings_map.values()),
    )
