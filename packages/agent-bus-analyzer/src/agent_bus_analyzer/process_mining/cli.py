"""Observer-only Process Intelligence CLI integration.

This slice exposes audit ingest plus read-only discover/conform/verify.
It does not register agent/api/trajectory collectors, flywheel, or simulation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_bus_analyzer.io_boundaries import (
    InputLimits,
    add_input_limit_arguments,
    input_limits_from_namespace,
    iter_jsonl_objects,
)
from agent_bus_analyzer.process_mining.collectors.audit_collector import AuditCollector
from agent_bus_analyzer.process_mining.errors import ProcessMiningError
from agent_bus_analyzer.process_mining.schemas.process_event import (
    CompletenessStatus,
    ProcessEvent,
)
from agent_bus_analyzer.process_mining.service import (
    DEFAULT_PROCESS_ID,
    ProcessIntelligenceService,
)
from agent_bus_analyzer.process_mining.storage.event_store import AppendStatus, EventStore

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_NOT_CLEAN = 2


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"cannot serialize {type(value).__name__}")


def _write_json(value: object) -> None:
    sys.stdout.write(json.dumps(value, default=_json_default, sort_keys=True) + "\n")


def _read_jsonl(path: str, *, limits: InputLimits) -> list[dict[str, object]]:
    records = [
        dict(record)
        for _, record in iter_jsonl_objects(
            path,
            limits=limits,
            purpose="process JSONL input",
            allow_stdin=True,
        )
    ]
    if not records:
        source = "stdin" if path == "-" else path
        raise ValueError(f"input contains no JSON records: {source}")
    return records


def _load_normalized(
    path: str,
    *,
    tenant_id: str,
    limits: InputLimits,
) -> tuple[ProcessEvent, ...]:
    # ``ProcessEvent`` is strict, while JSON naturally represents timestamps as
    # strings. Validate through Pydantic's JSON path so strict Python callers
    # cannot smuggle coercible values into this boundary.
    events = tuple(
        ProcessEvent.model_validate_json(json.dumps(record, sort_keys=True))
        for record in _read_jsonl(path, limits=limits)
    )
    mismatches = sorted({event.tenant_id for event in events if event.tenant_id != tenant_id})
    if mismatches:
        raise ValueError("normalized input tenant does not match --tenant-id")
    return events


def _select_process_id(events: Iterable[ProcessEvent], requested: str | None) -> str:
    if requested is not None:
        return requested
    process_ids = {event.process_id or DEFAULT_PROCESS_ID for event in events}
    if len(process_ids) != 1:
        raise ValueError("input contains multiple processes; provide --process-id")
    return next(iter(process_ids))


def _collect_raw_records(args: argparse.Namespace) -> tuple[ProcessEvent, ...]:
    records = _read_jsonl(args.input, limits=input_limits_from_namespace(args))
    if args.source != "audit":
        raise ValueError("this slice accepts only --source audit")
    return AuditCollector().collect_many(records, tenant_id=args.tenant_id)


def _cmd_ingest(args: argparse.Namespace) -> int:
    events = _collect_raw_records(args)
    seen: dict[str, str] = {}
    for event in events:
        previous = seen.get(event.event_id)
        if previous is not None and previous != event.normalization_hash:
            raise ValueError(f"input has conflicting duplicate event_id: {event.event_id}")
        seen[event.event_id] = event.normalization_hash
    incomplete = tuple(
        event.event_id
        for event in events
        if event.completeness.status is CompletenessStatus.INCOMPLETE
    )
    if incomplete and not args.accept_incomplete_evidence:
        raise ValueError(
            "incomplete governance evidence; use --accept-incomplete-evidence "
            "to retain the observation for conformance analysis"
        )

    store = EventStore(args.event_store_dir)
    # Preflight all conflicts before the first append to prevent partial writes
    # from a known duplicate-content conflict.
    for event in events:
        existing = store.get_event(tenant_id=args.tenant_id, event_id=event.event_id)
        if existing is not None and existing.normalization_hash != event.normalization_hash:
            raise ValueError(f"stored event_id has conflicting content: {event.event_id}")
    service = ProcessIntelligenceService(event_store=store)
    appended = 0
    duplicates = 0
    for event in events:
        result = service.ingest_event(event)
        assert result is not None
        if result.status is AppendStatus.APPENDED:
            appended += 1
        else:
            duplicates += 1
    _write_json(
        {
            "analytical_only": True,
            "appended": appended,
            "duplicates": duplicates,
            "evidence_incomplete": len(incomplete),
            "executable_authority": False,
            "status": "ok",
            "tenant_id": args.tenant_id,
        }
    )
    return EXIT_OK


def _service_for_input(args: argparse.Namespace) -> tuple[ProcessIntelligenceService, str]:
    events = _load_normalized(
        args.input,
        tenant_id=args.tenant_id,
        limits=input_limits_from_namespace(args),
    )
    process_id = _select_process_id(events, args.process_id)
    return ProcessIntelligenceService(events), process_id


def _cmd_discover(args: argparse.Namespace) -> int:
    service, process_id = _service_for_input(args)
    detail = service.get_process(tenant_id=args.tenant_id, process_id=process_id)
    if detail is None:
        raise ValueError("requested process was not present in normalized input")
    _write_json(detail.model_dump(mode="json"))
    return EXIT_OK


def _cmd_conform(args: argparse.Namespace) -> int:
    service, process_id = _service_for_input(args)
    report = service.get_compliance(tenant_id=args.tenant_id, process_id=process_id)
    if report is None:
        raise ValueError("requested process was not present in normalized input")
    _write_json(report.model_dump(mode="json"))
    return EXIT_OK if report.deny_count == 0 and report.investigate_count == 0 else EXIT_NOT_CLEAN


def _cmd_verify(args: argparse.Namespace) -> int:
    store = EventStore(args.event_store_dir)
    verification = store.verify_chain(args.tenant_id)
    _write_json(
        {
            "analytical_only": True,
            "executable_authority": False,
            "tenant_id": args.tenant_id,
            "verification": verification.model_dump(mode="json"),
        }
    )
    # An absent tenant log proves nothing. Treat it as unknown rather than a
    # successful integrity claim.
    return EXIT_OK if verification.valid and verification.checked > 0 else EXIT_FAILED


def run_process_command(args: argparse.Namespace) -> int:
    """Run one process command with one fail-closed error surface."""
    try:
        return int(args.process_func(args))
    except (OSError, TypeError, ValueError, ValidationError, ProcessMiningError) as exc:
        print(f"process {args.process_cmd}: fail-closed: {exc}", file=sys.stderr)
        return EXIT_FAILED


def add_process_parser(subparsers: Any) -> None:
    """Register a backward-compatible nested ``process`` command group."""
    parser = subparsers.add_parser(
        "process",
        help="Observer-only process evidence reconstruction",
    )
    commands = parser.add_subparsers(dest="process_cmd", required=True)

    ingest = commands.add_parser("ingest", help="Normalize and append audit-chain JSONL")
    ingest.add_argument("--input", required=True, help="JSONL path, or '-' for stdin")
    ingest.add_argument("--tenant-id", required=True)
    ingest.add_argument("--event-store-dir", required=True, type=Path)
    ingest.add_argument("--source", choices=("audit",), default="audit")
    ingest.add_argument("--source-system", default="process-cli")
    ingest.add_argument("--accept-incomplete-evidence", action="store_true")
    add_input_limit_arguments(ingest)
    ingest.set_defaults(process_func=_cmd_ingest, func=run_process_command)

    def add_input_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--input", required=True, help="Normalized ProcessEvent JSONL")
        command.add_argument("--tenant-id", required=True)
        command.add_argument("--process-id", default=None)
        add_input_limit_arguments(command)

    discover = commands.add_parser("discover", help="Discover a deterministic process graph")
    add_input_options(discover)
    discover.set_defaults(process_func=_cmd_discover, func=run_process_command)

    conform = commands.add_parser("conform", help="Run analytical conformance checks")
    add_input_options(conform)
    conform.set_defaults(process_func=_cmd_conform, func=run_process_command)

    verify = commands.add_parser("verify", help="Verify one tenant event chain")
    verify.add_argument("--tenant-id", required=True)
    verify.add_argument("--event-store-dir", required=True, type=Path)
    verify.set_defaults(process_func=_cmd_verify, func=run_process_command)
