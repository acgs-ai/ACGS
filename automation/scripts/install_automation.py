#!/usr/bin/env python3
"""Install approved automations as reviewable workflow manifests."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_log import append_event


APPROVED_DIR = Path("automation/approved")
WORKFLOWS_DIR = Path("automation/workflows")


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return data if data is not None else {}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def find_registry_entry(registry: dict[str, Any], automation_id: str) -> dict[str, Any] | None:
    for entry in registry.get("automations", []):
        if entry.get("id") == automation_id:
            return entry
    return None


def install_automation(automation_id: str, registry_path: Path) -> Path:
    registry = load_yaml(registry_path)
    entry = find_registry_entry(registry, automation_id)
    if entry is None:
        raise SystemExit(f"fail_closed: {automation_id} is not in registry")
    if entry.get("status") != "approved":
        raise SystemExit(f"fail_closed: {automation_id} status is {entry.get('status')}, not approved")

    approved_path = APPROVED_DIR / f"{automation_id}.yaml"
    if not approved_path.exists():
        raise SystemExit(f"fail_closed: approved spec missing: {approved_path}")

    approved_spec = load_yaml(approved_path)
    workflow_path = WORKFLOWS_DIR / f"{automation_id}.yaml"
    workflow_manifest = {
        "id": automation_id,
        "name": entry.get("name"),
        "installed_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source": str(approved_path),
        "trigger": entry.get("trigger"),
        "actions": entry.get("actions", []),
        "rollback_plan": entry.get("rollback_plan"),
        "approval_required": entry.get("approval_required", True),
        "spec": approved_spec,
    }
    write_yaml(workflow_path, workflow_manifest)

    entry["status"] = "installed"
    entry["last_run"] = None
    write_yaml(registry_path, registry)
    append_event(
        actor="automation-installer",
        action="install",
        automation_id=automation_id,
        files_changed=[str(workflow_path), str(registry_path)],
        validation_result="approved",
        decision="installed",
    )
    return workflow_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Install only approved automations.")
    parser.add_argument("--automation-id", required=True)
    parser.add_argument("--registry", type=Path, default=Path("automation/registry.yaml"))
    args = parser.parse_args()

    workflow_path = install_automation(args.automation_id, args.registry)
    print(workflow_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

