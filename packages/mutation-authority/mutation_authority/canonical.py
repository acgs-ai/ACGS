"""Canonical serialization and hashing primitives.

Every hash in the mutation-authority layer is computed over the canonical
JSON form (sorted keys, no whitespace) so that hashes are reproducible
across processes and platforms.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

# Sentinel hash for a resource that does not exist on disk. Distinct from
# sha256(b"") so an empty file and an absent file are different states.
ABSENT = "ABSENT"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_json(obj).encode("utf-8"))


def hash_file(path: Path) -> str:
    """Hash of the file's bytes, or ABSENT if the file does not exist."""
    if not path.exists():
        return ABSENT
    return sha256_hex(path.read_bytes())


def hmac_sign(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature)
