"""Generated ProcessEvent contract packaging regressions."""

from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from agent_bus_analyzer.process_mining.resources import process_event_schema_bytes
from agent_bus_analyzer.process_mining.schemas.generate_schema import main as generate_schema


def test_generated_schema_is_available_through_importlib_resources() -> None:
    package_root = Path(__file__).parents[1]
    contract = package_root / "contracts" / "process-event.schema.json"
    assert generate_schema(["--check", "--output", str(contract)]) == 0
    assert process_event_schema_bytes() == contract.read_bytes()
    assert json.loads(process_event_schema_bytes())["title"] == "ACGS ProcessEvent v1.0"


def test_built_wheel_contains_importable_generated_schema(tmp_path: Path) -> None:
    package_root = Path(__file__).parents[1]
    subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(tmp_path),
        ],
        cwd=package_root,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(tmp_path.glob("agent_bus_analyzer-*.whl"))
    resource_path = "agent_bus_analyzer/process_mining/resources/process-event.schema.json"
    excluded_migrations = (
        "agent_bus_analyzer/process_mining/storage/migrations/0001_event_ledger.sql",
        "agent_bus_analyzer/process_mining/storage/migrations/0002_transactional_ingest.sql",
        "agent_bus_analyzer/process_mining/storage/migrations/0003_transactional_ingest_v2.sql",
    )
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert resource_path in names
        assert all(path not in names for path in excluded_migrations)
        packaged = archive.read(resource_path)
    assert packaged == process_event_schema_bytes()
