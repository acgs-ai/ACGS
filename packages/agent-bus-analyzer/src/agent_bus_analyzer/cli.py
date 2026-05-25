"""CLI entry point: ``python -m agent_bus_analyzer <subcommand>``."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.config import load_config
from agent_bus_analyzer.errors import IntegrityStoreUnavailable
from agent_bus_analyzer.observer import follow_audit_file, project_audit_record
from agent_bus_analyzer.store import open_store

log = logging.getLogger("agent_bus_analyzer.cli")


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    store_dir = args.store_dir or os.getenv("AGENT_BUS_ANALYZER_STORE_DIR")
    app_target: Any
    if store_dir:
        from agent_bus_analyzer.api import create_app

        app_target = create_app(store=open_store(store_dir))
    else:
        app_target = "agent_bus_analyzer.api:create_app"

    uvicorn.run(
        app_target,
        factory=store_dir is None,
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


def _cmd_import_audit(args: argparse.Namespace) -> int:
    """Backfill a gove-zone audit JSONL into the analyzer trace store.

    This one-shot path complements the long-running ``observer`` tailer. It is
    useful for deploy smoke checks and historical backfills because it exits
    after proving canonical gove-zone audit records can produce bus-owned
    receipt proofs.
    """
    audit_file: Path = args.audit_file
    if not audit_file.exists():
        print(f"import-audit: fail-closed: audit file not present: {audit_file}", file=sys.stderr)
        return 1

    store = open_store(args.store_dir)
    imported = 0
    try:
        with audit_file.open("r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                clean = line.strip()
                if not clean:
                    continue
                try:
                    record = json.loads(clean)
                except json.JSONDecodeError as exc:
                    print(
                        f"import-audit: fail-closed: malformed JSONL at "
                        f"{audit_file}:{line_number}: {exc}",
                        file=sys.stderr,
                    )
                    return 1
                store.append(project_audit_record(record, args.constitutional_hash))
                imported += 1
    finally:
        store.close()

    print(
        json.dumps(
            {
                "status": "ok",
                "audit_file": str(audit_file),
                "store_dir": str(args.store_dir),
                "imported": imported,
            },
            sort_keys=True,
        )
    )
    return 0


def _fetch_json(url: str, *, token: str | None = None, timeout_seconds: float) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object from {url}")
    return payload


def _cmd_postdeploy_smoke(args: argparse.Namespace) -> int:
    """Verify a deployed analyzer API can expose a signed receipt proof.

    This command is deliberately read-only against the deployed API. The
    import/backfill job owns writes into the mounted trace store; this smoke
    check proves the running service can read that receipt, verify its chain,
    and export deployment-managed signature metadata.
    """
    token = args.token or os.getenv("ANALYZER_REVIEWER_TOKEN")
    if not token:
        print(
            "postdeploy-smoke: fail-closed: provide --token or ANALYZER_REVIEWER_TOKEN",
            file=sys.stderr,
        )
        return 1

    base_url = args.base_url.rstrip("/")
    receipt_id = args.receipt_id
    receipt_url = f"{base_url}/api/bus/receipts/{quote(receipt_id, safe='')}"

    try:
        health = _fetch_json(
            f"{base_url}/api/bus/healthz",
            timeout_seconds=args.timeout_seconds,
        )
        if health.get("status") != "ok":
            raise ValueError(f"health status is not ok: {health.get('status')!r}")

        proof = _fetch_json(
            receipt_url,
            token=token,
            timeout_seconds=args.timeout_seconds,
        )
        if proof.get("kind") != "receipt-proof":
            raise ValueError(f"unexpected proof kind: {proof.get('kind')!r}")
        if proof.get("hash_chain_verified") is not True:
            raise ValueError("receipt proof hash chain is not verified")

        packet_raw = proof.get("signed_evidence_packet")
        if not isinstance(packet_raw, str):
            raise ValueError("receipt proof is missing signed_evidence_packet JSON")
        packet = json.loads(packet_raw)
        if not isinstance(packet, dict):
            raise ValueError("signed_evidence_packet is not a JSON object")
        signature = packet.get("export_signature")
        if not isinstance(signature, dict):
            raise ValueError("signed_evidence_packet is missing export_signature")

        signature_status = signature.get("status")
        if not args.allow_unsigned_local and signature_status != "signed":
            raise ValueError(f"signature status is not deployment signed: {signature_status!r}")

        print(
            json.dumps(
                {
                    "status": "ok",
                    "base_url": base_url,
                    "receipt_id": receipt_id,
                    "hash_chain_verified": True,
                    "signature_status": signature_status,
                    "signature_key_id": signature.get("key_id"),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"postdeploy-smoke: fail-closed: {exc}", file=sys.stderr)
        return 1


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


def _cmd_expire(args: argparse.Namespace) -> int:
    """Move traces older than --days into ``expired/``. T059 / FR-012."""
    store = open_store(args.store_dir)
    try:
        expired_ids = store.expire_older_than(days=args.days)
    finally:
        store.close()
    print(
        json.dumps(
            {"status": "ok", "expired_count": len(expired_ids), "correlation_ids": expired_ids},
            sort_keys=True,
        )
    )
    return 0


def _cmd_observer(args: argparse.Namespace) -> int:
    try:
        return asyncio.run(_observer_main(args))
    except IntegrityStoreUnavailable as exc:
        print(f"observer: fail-closed: {exc}", file=sys.stderr)
        return 1


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify hash-chain integrity for a single correlation_id.

    Output: structured JSON to stdout.
    Exit 0 for intact, 1 for tampered/unknown/missing.
    """
    store = open_store(args.store_dir)
    try:
        trace = store.get_trace(args.correlation_id)
    finally:
        store.close()

    if trace is None:
        print(
            json.dumps(
                {
                    "correlation_id": args.correlation_id,
                    "integrity_status": "unknown",
                    "broken_event_id": None,
                    "event_count": 0,
                },
                sort_keys=True,
            )
        )
        return 1

    broken_event_id: str | None = None
    if trace.integrity_status == "tampered":
        # Re-walk the events to find the first offending event_id.
        from agent_bus_analyzer.hashing import compute_event_hash
        from agent_bus_analyzer.store import iter_trace_events

        prev: str | None = None
        for ev in iter_trace_events(args.store_dir, args.correlation_id):
            if ev.get("status") == "ingest-gap":
                continue
            if ev.get("prev_hash") != prev or compute_event_hash(ev) != ev.get("event_hash"):
                broken_event_id = str(ev.get("event_id", ""))
                break
            prev = ev.get("event_hash")

    print(
        json.dumps(
            {
                "correlation_id": args.correlation_id,
                "integrity_status": trace.integrity_status,
                "broken_event_id": broken_event_id,
                "event_count": len(trace.events),
            },
            sort_keys=True,
        )
    )
    return 0 if trace.integrity_status == "intact" else 1


def _cmd_dev_traffic(args: argparse.Namespace) -> int:
    """Write synthetic events directly to the trace store for offline quickstart traffic.

    Generates *count* ``kind=dispatch`` events for the given *target* handler,
    writing each through the public ``TraceStore.append`` path (no bus required).
    When ``--include-unwired-handler`` is set, approximately 10 % of events use
    ``status="unwired-handler"`` to exercise the wiring-defect detection path.

    This helper is intentionally NOT on the authorization path (FR-010).
    """
    import uuid
    from datetime import UTC, datetime

    store = open_store(args.store_dir)
    written = 0
    try:
        for i in range(args.count):
            use_unwired = args.include_unwired_handler and (i % 10 == 9)
            status = "unwired-handler" if use_unwired else "completed"
            target_resolved = None if use_unwired else args.target
            event: dict[str, Any] = {
                "event_id": str(uuid.uuid4()),
                "correlation_id": f"dev-traffic-{args.target}-{i:04d}",
                "recorded_at": datetime.now(UTC).isoformat(),
                "source_agent": "dev-traffic-generator",
                "target_handler_declared": args.target,
                "target_handler_resolved": target_resolved,
                "payload_ref": f"sha256:{'0' * 64}",
                "kind": "dispatch",
                "decision": None,
                "flagged_rule": None,
                "audit_receipt_hash": None,
                "constitutional_hash": "a1b2c3d4e5f60718",
                "status": status,
            }
            store.append(event)
            written += 1
    finally:
        store.close()

    print(
        json.dumps(
            {
                "status": "ok",
                "store_dir": str(args.store_dir),
                "target": args.target,
                "written": written,
                "include_unwired_handler": args.include_unwired_handler,
            },
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent_bus_analyzer")
    subs = parser.add_subparsers(dest="cmd", required=True)

    p_serve = subs.add_parser("serve", help="Run the FastAPI HTTP server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8042)
    p_serve.add_argument("--log-level", default="info")
    p_serve.add_argument(
        "--store-dir",
        type=Path,
        default=None,
        help=(
            "Trace store directory to serve. Defaults to "
            "AGENT_BUS_ANALYZER_STORE_DIR when set; without a store, trace "
            "endpoints fail closed with 503."
        ),
    )
    p_serve.set_defaults(func=_cmd_serve)

    p_openapi = subs.add_parser("export-openapi", help="Export the FastAPI OpenAPI document")
    p_openapi.add_argument("--output", required=True, help="Output path, or '-' for stdout")
    p_openapi.set_defaults(func=_cmd_export_openapi)

    p_import = subs.add_parser(
        "import-audit",
        help="One-shot import of a gove-zone audit JSONL into the analyzer store",
    )
    p_import.add_argument("--audit-file", required=True, type=Path)
    p_import.add_argument("--store-dir", required=True, type=Path)
    p_import.add_argument("--constitutional-hash", required=True)
    p_import.set_defaults(func=_cmd_import_audit)

    p_smoke = subs.add_parser(
        "postdeploy-smoke",
        help="Verify deployed health and one signed receipt proof",
    )
    p_smoke.add_argument("--base-url", required=True)
    p_smoke.add_argument("--receipt-id", required=True)
    p_smoke.add_argument(
        "--token",
        default=None,
        help="Reviewer bearer token; defaults to ANALYZER_REVIEWER_TOKEN",
    )
    p_smoke.add_argument("--timeout-seconds", type=float, default=10.0)
    p_smoke.add_argument(
        "--allow-unsigned-local",
        action="store_true",
        help="Allow unsigned-local-digest packets for local smoke tests only",
    )
    p_smoke.set_defaults(func=_cmd_postdeploy_smoke)

    p_obs = subs.add_parser("observer", help="Run the bus observer + audit-tail follower")
    p_obs.add_argument("--bus-endpoint", required=True)
    p_obs.add_argument("--audit-file", required=True, type=Path)
    p_obs.add_argument("--store-dir", required=True, type=Path)
    p_obs.add_argument("--queue-capacity", type=int, default=10_000)
    p_obs.add_argument("--registry-poll-seconds", type=int, default=30)
    p_obs.set_defaults(func=_cmd_observer)

    p_verify = subs.add_parser(
        "verify",
        help="Verify hash-chain integrity for a single trace",
    )
    p_verify.add_argument("correlation_id", help="Correlation ID of the trace to verify")
    p_verify.add_argument("--store-dir", required=True, type=Path)
    p_verify.set_defaults(func=_cmd_verify)

    p_expire = subs.add_parser(
        "expire",
        help="Move traces older than --days into the expired/ subdir (FR-012)",
    )
    p_expire.add_argument("--store-dir", required=True, type=Path)
    p_expire.add_argument("--days", type=int, default=90, help="Retention window (default: 90)")
    p_expire.set_defaults(func=_cmd_expire)

    p_dev = subs.add_parser(
        "dev-traffic",
        help="Write synthetic events to the trace store for offline dev/quickstart use",
    )
    p_dev.add_argument("--store-dir", required=True, type=Path, help="Trace store directory")
    p_dev.add_argument(
        "--target",
        required=True,
        help="Handler name to use as target_handler_declared",
    )
    p_dev.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of events to write (default: 10)",
    )
    p_dev.add_argument(
        "--include-unwired-handler",
        action="store_true",
        help="Make ~10 %% of events use status='unwired-handler' (every 10th event)",
    )
    p_dev.set_defaults(func=_cmd_dev_traffic)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
