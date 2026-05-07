#!/usr/bin/env python3
"""Append-only JSONL audit logging for automation decisions."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_LOG_PATH = Path("automation/logs/audit.jsonl")


def append_event(
    *,
    actor: str,
    action: str,
    automation_id: str,
    files_changed: list[str] | None = None,
    validation_result: str = "not_run",
    decision: str = "recorded",
    log_path: Path = DEFAULT_LOG_PATH,
) -> dict[str, Any]:
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "actor": actor,
        "action": action,
        "automation_id": automation_id,
        "files_changed": files_changed or [],
        "validation_result": validation_result,
        "decision": decision,
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def main() -> int:
    parser = argparse.ArgumentParser(description="Append an automation audit event.")
    parser.add_argument("--actor", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--automation-id", required=True)
    parser.add_argument("--files-changed", nargs="*", default=[])
    parser.add_argument("--validation-result", default="not_run")
    parser.add_argument("--decision", default="recorded")
    parser.add_argument("--log-path", type=Path, default=DEFAULT_LOG_PATH)
    args = parser.parse_args()

    event = append_event(
        actor=args.actor,
        action=args.action,
        automation_id=args.automation_id,
        files_changed=args.files_changed,
        validation_result=args.validation_result,
        decision=args.decision,
        log_path=args.log_path,
    )
    print(json.dumps(event, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

