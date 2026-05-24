"""CLI entry point: ``python -m agent_bus_analyzer <subcommand>``."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.config import load_config
from agent_bus_analyzer.errors import IntegrityStoreUnavailable
from agent_bus_analyzer.observer import follow_audit_file, project_audit_record
from agent_bus_analyzer.store import open_store

log = logging.getLogger("agent_bus_analyzer.cli")


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "agent_bus_analyzer.api:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )
    return 0


def _cmd_export_openapi(args: argparse.Namespace) -> int:
    from agent_bus_analyzer.api import create_app

    payload = json.dumps(create_app().openapi(), indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(payload)
        return 0

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload, encoding="utf-8")
    return 0


async def _observer_main(args: argparse.Namespace) -> int:
    """Async core of the observer subcommand.

    Fail-closed contract (FR-008): if ``--audit-file`` does not exist or is
    not readable, exit 1 with ``IntegrityStoreUnavailable``. No partial
    startup; no hash-less events ever recorded.
    """
    cfg = load_config(
        bus_endpoint=args.bus_endpoint,
        audit_file=args.audit_file,
        store_dir=args.store_dir,
        queue_capacity=args.queue_capacity,
        registry_poll_seconds=args.registry_poll_seconds,
    )
    if not cfg.audit_file.exists():
        raise IntegrityStoreUnavailable(f"audit file not present: {cfg.audit_file}")
    store = open_store(cfg.store_dir)
    queue = CaptureQueue(capacity=cfg.queue_capacity)

    log.info(
        "observer.boot bus_endpoint=%s audit_file=%s store_dir=%s hash=%s",
        cfg.bus_endpoint,
        cfg.audit_file,
        cfg.store_dir,
        cfg.constitutional_hash,
    )

    async def _on_audit(record: dict[str, Any]) -> None:
        projected = project_audit_record(record, cfg.constitutional_hash)
        queue.try_put(projected)

    stop = asyncio.Event()
    # NOTE: Live bus subscription is exercised by the dispatcher-level test
    # (T016); orchestrating an in-process LocalEventBus from this CLI is a
    # follow-up — the audit-tail follower and writer loop ARE wired here.
    tasks = [
        asyncio.create_task(store.writer_loop(queue)),
        asyncio.create_task(
            follow_audit_file(cfg.audit_file, on_record=_on_audit, stop_event=stop)
        ),
        asyncio.create_task(_status_lines(queue, stop)),
    ]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        stop.set()
    return 0


async def _status_lines(queue: CaptureQueue, stop: asyncio.Event) -> None:
    """Emit the one-line-per-second status format documented in quickstart §2."""
    while not stop.is_set():
        gap_state = "open" if queue.gap_open() else "closed"
        sys.stdout.write(
            f"[observer] queue={queue.qsize()}/{queue.capacity} ingest_gap={gap_state}\n"
        )
        sys.stdout.flush()
        try:
            await asyncio.wait_for(stop.wait(), timeout=1.0)
        except TimeoutError:
            continue


def _cmd_observer(args: argparse.Namespace) -> int:
    try:
        return asyncio.run(_observer_main(args))
    except IntegrityStoreUnavailable as exc:
        print(f"observer: fail-closed: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent_bus_analyzer")
    subs = parser.add_subparsers(dest="cmd", required=True)

    p_serve = subs.add_parser("serve", help="Run the FastAPI HTTP server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8042)
    p_serve.add_argument("--log-level", default="info")
    p_serve.set_defaults(func=_cmd_serve)

    p_openapi = subs.add_parser("export-openapi", help="Export the FastAPI OpenAPI document")
    p_openapi.add_argument("--output", required=True, help="Output path, or '-' for stdout")
    p_openapi.set_defaults(func=_cmd_export_openapi)

    p_obs = subs.add_parser("observer", help="Run the bus observer + audit-tail follower")
    p_obs.add_argument("--bus-endpoint", required=True)
    p_obs.add_argument("--audit-file", required=True, type=Path)
    p_obs.add_argument("--store-dir", required=True, type=Path)
    p_obs.add_argument("--queue-capacity", type=int, default=10_000)
    p_obs.add_argument("--registry-poll-seconds", type=int, default=30)
    p_obs.set_defaults(func=_cmd_observer)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
