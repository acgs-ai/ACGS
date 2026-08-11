"""Canonical serialization, hashing, and HMAC primitives (stdlib only).

Byte-for-byte identical to `mutation_authority/canonical.py` so every digest
this package computes is reproducible across processes and consistent with the
mutation-authority kernel. Vendored (not imported) to keep
EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1 a self-contained package
that runs from its own directory with no PYTHONPATH assumptions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
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
    """Streamed sha256 of the file's bytes, or ABSENT if it is not a file.

    Streamed so a large critical object (a multi-MB registry) is never read
    fully into memory. A directory in a critical-object slot returns ABSENT
    (fail closed), not a crash.
    """
    if not path.is_file():
        return ABSENT
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hmac_sign(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature)
