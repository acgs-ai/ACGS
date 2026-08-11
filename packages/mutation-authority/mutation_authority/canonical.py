"""Canonical serialization and hashing primitives.

Every hash in the mutation-authority layer is computed over the canonical
JSON form (sorted keys, no whitespace) so that hashes are reproducible
across processes and platforms.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
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
    """State digest binding content AND security-relevant file metadata.

    A plain, non-executable regular file hashes to the sha256 of its bytes
    (the historical value, so existing baselines stay valid). Everything
    else yields a distinct digest, so two byte-identical states with
    different metadata never collide:

    - symlink            -> sha256 of the link target string + ":symlink"
      (replacing a governed file with a symlink to identical content is a
      state change, and a symlink can never match a content-authorized state);
    - executable regular -> content sha256 + ":exec" (an exec-bit flip on a
      byte-identical file is a state change);
    - any other type     -> a non-matching "UNHASHABLE:" marker (fail closed);
    - absent             -> ABSENT.

    `lstat` is used so the symlink itself is classified, never its target.
    """
    try:
        st = path.lstat()
    except OSError:
        return ABSENT
    if stat.S_ISLNK(st.st_mode):
        return sha256_hex(os.readlink(path).encode("utf-8")) + ":symlink"
    if not stat.S_ISREG(st.st_mode):
        return "UNHASHABLE:" + stat.filemode(st.st_mode)
    digest = sha256_hex(path.read_bytes())
    if st.st_mode & 0o111:
        return digest + ":exec"
    return digest


def hmac_sign(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature)
