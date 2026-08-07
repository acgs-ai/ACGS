"""Annotation writer (Phase 2, ADR 0003 §6).

Writes a ``governance_annotation/v1`` document to a DERIVED path and appends a
hash-chained registry entry, mirroring the manifest pattern in ``raw_store.py``.

Separation guarantee (ADR 0003 §1): annotations are a SEPARATE, rebuildable
artifact. They live under ``<root>/annotations/<ab>/<annotation_id>.json`` and
NEVER under ``raw/``. The frozen v2 record + raw bytes are never touched.

Rebuild guarantee (ADR 0003 §6, acceptance P2-7): the annotation JSON and every
registry entry are PURELY DERIVED from the annotation content + evaluator
version. There is NO wall-clock, no randomness, and no ``captured_at`` in the
registry body, so deleting all annotations and re-running reproduces
byte-identical files and an identical chain.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex
from .evaluate import evaluate


class AnnotationStore:
    """Derived-layer store for governance annotations + a hash-chained registry.

    Constructed with a root path (like ``RawStore``) so tests point it at a
    ``tmp_path``. All writes are idempotent and content-addressed by
    ``annotation_id``.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.annotations_dir = self.root / "annotations"
        self.registry_path = self.root / "annotation_registry.jsonl"
        # Fix 5 (SEC-MED): head/length commitment anchor. Persists the newest
        # entry_sha256 + entry count so tail-truncation (dropping the newest
        # entries) is detectable — the plain hash-chain only catches
        # reorder/edit, not truncation. Written idempotently (overwrite, never
        # append) so a delete+rebuild reproduces an identical anchor (P2-7).
        self.head_anchor_path = self.root / "annotation_registry_head.json"
        self.annotations_dir.mkdir(parents=True, exist_ok=True)

    # ---- derived path (NEVER under raw/) -----------------------------------

    def _path_for(self, annotation_id: str) -> Path:
        d = self.annotations_dir / annotation_id[:2]
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{annotation_id}.json"

    def path_for(self, annotation_id: str) -> Path:
        return self._path_for(annotation_id)

    # ---- write an annotation (idempotent, content-addressed) ---------------

    def write_annotation(self, annotation: dict[str, Any]) -> Path:
        """Write the annotation JSON in canonical bytes. Idempotent: identical
        content is a no-op; a differing payload at the same id is a tamper
        backstop (cannot happen for a pure evaluator, but the check is cheap)."""
        annotation_id = annotation["annotation_id"]
        path = self._path_for(annotation_id)
        data = canonical_bytes(annotation)
        if path.exists():
            if path.read_bytes() != data:
                raise FileExistsError(
                    f"annotation id collision / tampered object at {path}"
                )
        else:
            path.write_bytes(data)
        return path

    # ---- hash-chained registry (mirror raw_store.append_manifest) ----------

    def _last_entry_hash(self) -> str | None:
        if not self.registry_path.exists():
            return None
        last = None
        for line in self.registry_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        if last is None:
            return None
        return json.loads(last).get("entry_sha256")

    def append_registry(self, annotation: dict[str, Any]) -> dict[str, Any]:
        """Append a hash-chained registry entry for this annotation. The entry
        body is purely derived (no timestamp) so the chain rebuilds identically.
        Returns the sealed entry."""
        prev = self._last_entry_hash()
        body: dict[str, Any] = {
            "annotation_id": annotation["annotation_id"],
            "trajectory_id": annotation["trajectory_ref"]["trajectory_id"],
            "normalized_sha256": annotation["trajectory_ref"]["normalized_sha256"],
            "evaluator_version": annotation["evaluator_version"],
            "annotation_sha256": annotation["integrity"]["annotation_sha256"],
            "prev_entry_sha256": prev,
        }
        entry_hash = sha256_hex(canonical_bytes(body))
        body["entry_sha256"] = entry_hash
        with self.registry_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True, ensure_ascii=False) + "\n")
        # Fix 5: (re)write the head/length commitment anchor from the full
        # registry so it always reflects the true tail (idempotent overwrite).
        self._write_head_anchor()
        return body

    def _count_and_head(self) -> tuple[int, str | None]:
        """Return (entry_count, last_entry_sha256) from the registry file."""
        if not self.registry_path.exists():
            return 0, None
        count = 0
        last: str | None = None
        for line in self.registry_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                count += 1
                last = json.loads(line).get("entry_sha256")
        return count, last

    def _write_head_anchor(self) -> dict[str, Any]:
        """Fix 5: persist the newest entry_sha256 + entry count. Overwrite (never
        append) so a delete+rebuild reproduces byte-identical content (P2-7). The
        body is purely derived (no timestamp)."""
        count, head = self._count_and_head()
        anchor = {"count": count, "head_entry_sha256": head}
        self.head_anchor_path.write_text(
            json.dumps(anchor, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return anchor

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify registry hash-chain integrity (tamper-evidence).

        Fix 5: in addition to the per-link hash chain (which catches
        reorder/edit), assert the head/length commitment anchor — the last
        entry's sha256 and the entry count must match the committed anchor. This
        detects TAIL-TRUNCATION (dropping the newest entries), which the plain
        chain cannot see because a truncated prefix is still internally
        consistent."""
        errors: list[str] = []
        prev: str | None = None
        count = 0
        last: str | None = None
        if not self.registry_path.exists():
            # no registry: still consistent only if no anchor claims entries.
            if self.head_anchor_path.exists():
                anchor = json.loads(self.head_anchor_path.read_text(encoding="utf-8"))
                if anchor.get("count"):
                    errors.append("registry missing but head anchor claims entries")
            return (not errors), errors
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
            count += 1
            last = claimed

        # head/length commitment check (Fix 5, tail-truncation detection)
        if self.head_anchor_path.exists():
            anchor = json.loads(self.head_anchor_path.read_text(encoding="utf-8"))
            if anchor.get("count") != count:
                errors.append(
                    f"head anchor count mismatch: anchor={anchor.get('count')} "
                    f"actual={count} (tail-truncation?)"
                )
            if anchor.get("head_entry_sha256") != last:
                errors.append(
                    "head anchor entry mismatch: last registry entry does not "
                    "match committed head (tail-truncation?)"
                )
        else:
            errors.append("missing head anchor commitment")
        return (not errors), errors

    # ---- convenience: evaluate a record and persist it ---------------------

    def annotate_record(self, record: dict[str, Any]) -> dict[str, Any]:
        """Evaluate a v2 record, write the annotation, and append the registry
        entry. Returns the annotation dict."""
        annotation = evaluate(record)
        self.write_annotation(annotation)
        self.append_registry(annotation)
        return annotation
