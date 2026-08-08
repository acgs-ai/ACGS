"""Raw preservation layer (Phase 1, section 2).

Content-addressed, write-once raw archive + a hash-chained manifest (the SHA-256
provenance registry). The raw source stays authoritative and is never
transformed; normalized output references it by digest (ADR 0002 D6).

Layout::

    <root>/raw/<ab>/<sha256>.jsonl      immutable, mode 0444
    <root>/quarantine/<ab>/<sha256>.jsonl  restricted (0400), secret-bearing/unparseable
    <root>/manifest.jsonl               append-only, hash-chained
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex


@dataclass(frozen=True)
class RawRef:
    uri: str
    sha256: str
    byte_len: int
    record_count: int


class RawStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.raw_dir = self.root / "raw"
        self.quarantine_dir = self.root / "quarantine"
        self.manifest_path = self.root / "manifest.jsonl"
        self.incident_log = self.root / "incidents.log"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    # ---- content-addressed raw write (WORM) --------------------------------

    def _path_for(self, base: Path, digest: str) -> Path:
        d = base / digest[:2]
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{digest}.jsonl"

    def put_raw(self, raw_bytes: bytes, record_count: int, *, quarantine: bool = False) -> RawRef:
        """Write raw bytes immutably. Idempotent: identical content is a no-op.

        Raises FileExistsError only if a *different* payload somehow collides
        (cannot happen with SHA-256, but the check is a tamper backstop).
        """
        digest = sha256_hex(raw_bytes)
        base = self.quarantine_dir if quarantine else self.raw_dir
        path = self._path_for(base, digest)
        if path.exists():
            if path.read_bytes() != raw_bytes:
                raise FileExistsError(f"hash collision / tampered object at {path}")
        else:
            # write then seal read-only
            path.write_bytes(raw_bytes)
            mode = stat.S_IRUSR if quarantine else (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            os.chmod(path, mode)
        return RawRef(
            uri=str(path.relative_to(self.root)),
            sha256=digest,
            byte_len=len(raw_bytes),
            record_count=record_count,
        )

    def verify_raw(self, ref: RawRef) -> bool:
        """Recompute the digest of the stored object and compare (V4)."""
        path = self.root / ref.uri
        if not path.exists():
            return False
        return sha256_hex(path.read_bytes()) == ref.sha256

    # ---- hash-chained manifest (provenance registry) -----------------------

    def _last_entry_hash(self) -> str | None:
        if not self.manifest_path.exists():
            return None
        last = None
        for line in self.manifest_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        if last is None:
            return None
        return json.loads(last).get("entry_sha256")

    def append_manifest(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Append a hash-chained manifest entry. Returns the sealed entry."""
        prev = self._last_entry_hash()
        body = dict(entry)
        body["prev_entry_sha256"] = prev
        body.pop("entry_sha256", None)
        entry_hash = sha256_hex(canonical_bytes(body))
        body["entry_sha256"] = entry_hash
        with self.manifest_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True, ensure_ascii=False) + "\n")
        return body

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify manifest hash-chain integrity (tamper-evidence)."""
        errors: list[str] = []
        prev: str | None = None
        if not self.manifest_path.exists():
            return True, errors
        for i, line in enumerate(self.manifest_path.read_text(encoding="utf-8").splitlines()):
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

    def log_incident(self, message: str) -> None:
        with self.incident_log.open("a", encoding="utf-8") as fh:
            fh.write(message.rstrip("\n") + "\n")
