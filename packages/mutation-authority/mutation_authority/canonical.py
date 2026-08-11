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


def state_mode_suffix(mode: int) -> str:
    """Digest suffix binding the full permission bits of a regular file.

    A plain 0644 file keeps the historical suffix-free digest so existing
    baselines stay valid; every other permission set (exec bits, setuid,
    group/world writability, restrictive modes like 0600) yields a distinct
    suffix, so two byte-identical states with different permissions never
    collide.
    """
    perms = stat.S_IMODE(mode)
    if perms == 0o644:
        return ""
    return f":mode={perms:04o}"


def hash_file(path: Path) -> str:
    """State digest binding content AND security-relevant file metadata.

    A plain 0644 regular file hashes to the sha256 of its bytes (the
    historical value, so existing baselines stay valid). Everything else
    yields a distinct digest, so two byte-identical states with different
    metadata never collide:

    - symlink            -> sha256 of the link target string + ":symlink"
      (replacing a governed file with a symlink to identical content is a
      state change, and a symlink can never match a content-authorized state);
    - other permissions  -> content sha256 + ":mode=NNNN" (a permission flip
      on a byte-identical file is a state change);
    - any other type     -> a non-matching "UNHASHABLE:" marker (fail closed);
    - absent             -> ABSENT.

    The file is classified via `lstat`, then opened with `O_NOFOLLOW` and
    re-classified via `fstat` on the open descriptor, so a symlink swapped
    in between the two calls can never yield a plain content digest.
    """
    try:
        st = path.lstat()
    except OSError:
        return ABSENT
    if stat.S_ISLNK(st.st_mode):
        return sha256_hex(os.readlink(path).encode("utf-8")) + ":symlink"
    if not stat.S_ISREG(st.st_mode):
        return "UNHASHABLE:" + stat.filemode(st.st_mode)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return ABSENT
    except OSError:
        # ELOOP: the entry was swapped to a symlink after lstat. Classify
        # the symlink itself; if it vanished again, fail closed.
        try:
            return sha256_hex(os.readlink(path).encode("utf-8")) + ":symlink"
        except OSError:
            return "UNHASHABLE:unreadable"
    with os.fdopen(fd, "rb") as fh:
        fst = os.fstat(fh.fileno())
        if not stat.S_ISREG(fst.st_mode):
            return "UNHASHABLE:" + stat.filemode(fst.st_mode)
        return sha256_hex(fh.read()) + state_mode_suffix(fst.st_mode)


def hmac_sign(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature)
