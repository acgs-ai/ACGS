"""Annotation persistence (Phase 2).

Derived layer — rebuildable, never authoritative. Stores governance_annotation/v1
documents content-addressed by annotation_id, with a hash-chained registry
(tamper-evident) that binds each annotation to the exact frozen trajectory it
scored. Deleting this whole layer loses nothing: annotations recompute from the
frozen trajectories + evaluator_version.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex


class AnnotationStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.ann_dir = self.root / "annotations"
        self.registry_path = self.root / "annotation_registry.jsonl"
        self.ann_dir.mkdir(parents=True, exist_ok=True)

    def put(self, annotation: dict[str, Any]) -> str:
        """Write the annotation JSON content-addressed by annotation_id. Idempotent."""
        aid = annotation["annotation_id"]
        d = self.ann_dir / aid[:2]
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{aid}.json"
        body = json.dumps(annotation, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
        if not path.exists():
            path.write_text(body, encoding="utf-8")
            os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return str(path.relative_to(self.root))

    def _last_entry_hash(self) -> str | None:
        if not self.registry_path.exists():
            return None
        last = None
        for line in self.registry_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        return json.loads(last).get("entry_sha256") if last else None

    def append_registry(self, annotation: dict[str, Any], uri: str) -> dict[str, Any]:
        prev = self._last_entry_hash()
        body = {
            "annotation_id": annotation["annotation_id"],
            "trajectory_id": annotation["trajectory_ref"]["trajectory_id"],
            "normalized_sha256": annotation["trajectory_ref"]["normalized_sha256"],
            "annotation_sha256": annotation["integrity"]["annotation_sha256"],
            "evaluator_version": annotation["evaluator_version"],
            "tier": annotation["tier"]["assigned"],
            "uri": uri,
            "prev_entry_sha256": prev,
        }
        body["entry_sha256"] = sha256_hex(canonical_bytes(body))
        with self.registry_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True, ensure_ascii=False) + "\n")
        return body

    def verify_chain(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev: str | None = None
        if not self.registry_path.exists():
            return True, errors
        for i, line in enumerate(self.registry_path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            entry = json.loads(line)
            claimed = entry.get("entry_sha256")
            if entry.get("prev_entry_sha256") != prev:
                errors.append(f"entry {i}: broken prev link")
            body = {k: v for k, v in entry.items() if k != "entry_sha256"}
            if sha256_hex(canonical_bytes(body)) != claimed:
                errors.append(f"entry {i}: entry hash mismatch")
            prev = claimed
        return (not errors), errors

    def annotate(self, annotation: dict[str, Any]) -> dict[str, Any]:
        """Persist annotation + registry entry in one call."""
        uri = self.put(annotation)
        return self.append_registry(annotation, uri)
