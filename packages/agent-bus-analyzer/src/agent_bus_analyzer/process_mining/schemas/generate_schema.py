"""Generate/check the versioned ProcessEvent JSON Schema contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agent_bus_analyzer.process_mining.schemas.process_event import ProcessEvent


def schema_document() -> dict[str, Any]:
    document = ProcessEvent.model_json_schema(mode="serialization")
    document["$id"] = "https://acgs.dev/schemas/process-event/v1.0.json"
    document["title"] = "ACGS ProcessEvent v1.0"
    document["x-generated-by"] = "agent_bus_analyzer.process_mining.schemas.generate_schema"
    return document


def rendered_schema() -> str:
    return json.dumps(schema_document(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def default_output_path() -> Path:
    return Path(__file__).resolve().parents[4] / "contracts" / "process-event.schema.json"


def default_resource_output_path() -> Path:
    return Path(__file__).resolve().parents[1] / "resources" / "process-event.schema.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=default_output_path())
    parser.add_argument(
        "--resource-output",
        type=Path,
        default=default_resource_output_path(),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    expected = rendered_schema()
    output: Path = args.output
    resource_output: Path = args.resource_output
    if args.check:
        return int(
            any(
                not destination.exists() or destination.read_text(encoding="utf-8") != expected
                for destination in (output, resource_output)
            )
        )
    for destination in (output, resource_output):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
