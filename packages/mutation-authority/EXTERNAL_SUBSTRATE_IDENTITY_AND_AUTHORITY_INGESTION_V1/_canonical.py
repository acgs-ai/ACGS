"""Canonical serialization, hashing, and HMAC primitives (stdlib only).

Mirrors `mutation_authority/canonical.py` so every digest this package
computes is reproducible across processes and consistent with the
mutation-authority kernel (`hash_file` is substrate-specific: pure content
digests, no mode binding, symlinks refused). Vendored (not imported) to keep
EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1 a self-contained package
that runs from its own directory with no PYTHONPATH assumptions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Any

# Sentinel for a resource absent on disk. Distinct from sha256(b"") so an empty
# file and an absent file are different states — an absent critical object must
# never hash-match an empty one.
ABSENT = "ABSENT"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_json(obj).encode("utf-8"))


def hash_file(path: Path) -> str:
    """Streamed sha256 of a REGULAR file's bytes, pinned against symlinks.

    Substrate identity binds the in-tree object itself, so a critical object
    (or checksum-listed file) replaced by a symlink — even one pointing at
    external content with the expected bytes — must never verify: a symlink
    yields a non-matching ``UNHASHABLE:symlink`` marker, never a content
    digest. The entry is classified via ``lstat``, opened with ``O_NOFOLLOW``,
    and re-classified via ``fstat`` on the open descriptor, so a symlink
    swapped in between the calls cannot be laundered into the authorized
    digest either. A directory or other non-regular object in a slot returns
    ABSENT (fail closed), and absence is ABSENT. Streamed so a large critical
    object (a multi-MB registry) is never read fully into memory.
    """
    try:
        st = path.lstat()
    except OSError:
        return ABSENT
    if stat.S_ISLNK(st.st_mode):
        return "UNHASHABLE:symlink"
    if not stat.S_ISREG(st.st_mode):
        return ABSENT
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return ABSENT
    except OSError:
        # ELOOP: the entry became a symlink after lstat — never a content
        # digest (and never followed).
        return "UNHASHABLE:symlink"
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as fh:
        fst = os.fstat(fh.fileno())
        if not stat.S_ISREG(fst.st_mode):
            return "UNHASHABLE:" + stat.filemode(fst.st_mode)
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hmac_sign(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature)
