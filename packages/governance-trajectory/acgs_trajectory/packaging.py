"""Release packaging (Phase 4).

Tiered dataset packages = hash-content manifests that reference members by
id + digest. NO raw content is copied into a package (separation preserved);
a consumer resolves members against the frozen raw/annotation/outcome stores.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex
from .index import Index

MANIFEST_VERSION = "acgs_dataset_manifest/v1"


def _member(index: Index, trajectory_id: str) -> dict[str, Any] | None:
    ann = index.annotation_for(trajectory_id)
    row = index.conn.execute("SELECT normalized_sha256 FROM trajectories WHERE trajectory_id=?",
                             (trajectory_id,)).fetchone()
    if not row:
        return None
    out = index.conn.execute("SELECT outcome_id FROM outcomes WHERE trajectory_id=? ORDER BY outcome_id LIMIT 1",
                             (trajectory_id,)).fetchone()
    return {
        "trajectory_id": trajectory_id,
        "normalized_sha256": row["normalized_sha256"],
        "annotation_id": ann["annotation_id"] if ann else None,
        "outcome_id": out["outcome_id"] if out else None,
        "effective_tier": index.effective_tier(trajectory_id),
    }


def build_manifest(kind: str, name: str, description: str, index: Index,
                   trajectory_ids: list[str], selection_criteria: dict[str, Any],
                   *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a content-hashed dataset/release manifest. Members referenced by id+digest."""
    members = [m for m in (_member(index, tid) for tid in sorted(trajectory_ids)) if m]
    tier_counts: dict[str, int] = {}
    for m in members:
        tier_counts[m["effective_tier"]] = tier_counts.get(m["effective_tier"], 0) + 1
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "kind": kind,  # "release" | "dataset"
        "name": name,
        "description": description,
        "selection_criteria": selection_criteria,
        "schema_refs": {
            "trajectory": "governance_trajectory/v2",
            "annotation": "governance_annotation/v1",
            "outcome": "governance_outcome/v1",
        },
        "members": members,
        "counts": {"members": len(members), "by_tier": tier_counts},
        "content_sha256": "0" * 64,
    }
    if extra:
        manifest.update(extra)
    # content hash over everything except the content_sha256 field itself
    clone = dict(manifest)
    clone["content_sha256"] = "0" * 64
    manifest["content_sha256"] = sha256_hex(canonical_bytes(clone))
    return manifest


def build_tiered_release(index: Index, tier: str) -> dict[str, Any]:
    ids = index.by_effective_tier((tier,))
    return build_manifest(
        "release", f"acgs-release-tier-{tier}", f"All trajectories at effective tier {tier}.",
        index, ids, {"effective_tier": tier},
    )


class ReleaseStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.dir = self.root / "releases"
        self.registry_path = self.root / "release_registry.jsonl"
        self.dir.mkdir(parents=True, exist_ok=True)

    def put(self, manifest: dict[str, Any]) -> str:
        cid = manifest["content_sha256"]
        path = self.dir / f"{manifest['name']}-{cid[:12]}.json"
        if not path.exists():
            path.write_text(json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return str(path.relative_to(self.root))

    def _last(self) -> str | None:
        if not self.registry_path.exists():
            return None
        last = None
        for line in self.registry_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        return json.loads(last).get("entry_sha256") if last else None

    def publish(self, manifest: dict[str, Any]) -> dict[str, Any]:
        uri = self.put(manifest)
        body = {
            "name": manifest["name"],
            "kind": manifest["kind"],
            "content_sha256": manifest["content_sha256"],
            "members": manifest["counts"]["members"],
            "uri": uri,
            "prev_entry_sha256": self._last(),
        }
        body["entry_sha256"] = sha256_hex(canonical_bytes(body))
        with self.registry_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True, ensure_ascii=False) + "\n")
        return body

    def verify_chain(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev = None
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
                errors.append(f"entry {i}: hash mismatch")
            prev = claimed
        return (not errors), errors
