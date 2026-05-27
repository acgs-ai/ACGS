from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover - fallback for environments without PyYAML
    yaml = None


def load_structured_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load YAML policy files")
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{p} must contain a mapping/object")
    return data


def load_roles(path: str | Path) -> dict[str, Any]:
    roles = load_structured_file(path)
    if "roles" not in roles:
        raise ValueError("roles file must contain a top-level 'roles' object")
    return roles


def load_policy_bundle(path_or_dir: str | Path) -> dict[str, Any]:
    p = Path(path_or_dir)
    if p.is_file():
        bundle = load_structured_file(p)
        if "policies" not in bundle:
            raise ValueError("policy bundle must contain a top-level 'policies' array")
        return bundle

    policies: list[dict[str, Any]] = []
    versions: list[str] = []
    for child in sorted(p.glob("*")):
        if child.suffix.lower() not in {".yaml", ".yml", ".json"}:
            continue
        bundle = load_structured_file(child)
        versions.append(str(bundle.get("version", child.stem)))
        policies.extend(bundle.get("policies", []))

    if not policies:
        raise ValueError(f"no policies found in {p}")

    return {
        "version": "+".join(versions),
        "policies": policies,
    }
