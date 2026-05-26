from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

JsonDict = dict[str, Any]


def load_policies(policy_dir: Path | str | None = None, policy_files: list[Path] | None = None) -> list[JsonDict]:
    paths: list[Path] = []
    if policy_dir:
        root = Path(policy_dir)
        if root.exists():
            paths.extend(sorted(root.glob("*.yaml")))
            paths.extend(sorted(root.glob("*.yml")))
    paths.extend(policy_files or [])

    policies: list[JsonDict] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Policy file {path} must contain a mapping.")
        loaded.setdefault("source", str(path))
        policies.append(loaded)
    if not policies:
        raise ValueError("No policy files found.")
    return policies


def write_evidence_jsonl(path: Path, event: JsonDict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")))
        handle.write("\n")
