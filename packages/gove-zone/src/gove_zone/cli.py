"""Installed command-line tools for Gove Zone runtime evidence."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from gove_zone.audit import ChainHashAuditStore


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False))


def _find_event(
    store: ChainHashAuditStore,
    event_id: str,
) -> dict[str, Any] | None:
    for event in store.iter_events():
        if event.get("event_id") == event_id:
            return event
    return None


def _replay(args: argparse.Namespace) -> int:
    base: dict[str, Any] = {
        "event_id": args.event,
        "expected_audit_hash": args.audit_hash,
    }

    if args.audit is None:
        _emit(
            {
                **base,
                "status": "hash-only",
                "verified": False,
                "reason": "provide --audit PATH to verify the full chain",
            }
        )
        return 0

    audit_path = Path(args.audit)
    store = ChainHashAuditStore(audit_path)
    chain = store.verify_chain()
    event = _find_event(store, args.event)
    actual_hash = event.get("event_hash") if event is not None else None
    hash_matches = args.audit_hash is None or actual_hash == args.audit_hash
    verified = bool(chain["valid"] and event is not None and hash_matches)

    _emit(
        {
            **base,
            "audit": str(audit_path),
            "status": "verified" if verified else "failed",
            "verified": verified,
            "chain_valid": chain["valid"],
            "checked": chain["checked"],
            "event_found": event is not None,
            "actual_audit_hash": actual_hash,
            "decision": event.get("decision") if event is not None else None,
            "policy_version": (
                event.get("policy_version") if event is not None else None
            ),
            "failures": chain["failures"],
        }
    )
    return 0 if verified else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gove-zone",
        description="Replay and verify Gove Zone audit evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    replay = subparsers.add_parser(
        "replay",
        help="verify a governed action against an audit JSONL chain",
    )
    replay.add_argument("--event", required=True, help="event_id to replay")
    replay.add_argument(
        "--audit",
        help="path to audit.jsonl; omitted command returns hash-only evidence",
    )
    replay.add_argument(
        "--audit-hash",
        help="expected audit event hash from a receipt or console action",
    )
    replay.set_defaults(func=_replay)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
