#!/usr/bin/env python3
"""One-shot start authority guard for the supported clean-sibling P3C launcher.

The production launcher path accepts only owner-signed capabilities under the
pinned Ed25519 public key below.  Direct tests may call ``consume_authority``
with an explicit synthetic public key; ``consume_from_launcher`` and the CLI do
not expose that override.

Scope boundary: this prevents supported-current-launcher self-minting. It does
not make old commits, file rollback, direct internal script execution, or
arbitrary same-UID commands safe; those need an external monotonic broker,
dedicated UID, container, VM, or root-owned execution boundary.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

SCHEMA = "acgs.start_authority.capability"
SPENT_SCHEMA = "acgs.start_authority.spent"
TERMINAL_SCHEMA = "acgs.start_authority.terminal"
VERSION = 1
SUPPORTED_NODE_ID = "P3-APPROVAL-003C"
OWNER_APPROVAL_ID = "p3c-one-shot-owner-approval-20260730-g047"
ACTION = "start-proof"
PRODUCTION_PUBLIC_KEY_RAW_HEX = "118a55626c6b39a49314c9b93f7578a56f6f6817b96e4b78519e0e25d6a33964"
PRODUCTION_ISSUER_KEY_ID = "2796b27076b10f29adab8b25c5f8846035cd6185c5973365d29570cbaeae68fc"
MAX_CAPABILITY_LIFETIME_SECONDS = 3600
MAX_ISSUED_AT_FUTURE_SKEW_SECONDS = 300
MAX_JSON_BYTES = 64 * 1024
AUTHORITY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,127}\Z")
ATTEMPT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}\Z")
HEX40_RE = re.compile(r"[0-9a-f]{40}\Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
SIG_RE = re.compile(r"[0-9a-f]{128}\Z")
FAULT_ENV = "ACGS_START_AUTHORITY_TEST_FAULT"


class GuardError(RuntimeError):
    pass


class _LibCrypto:
    EVP_PKEY_ED25519 = 1087

    def __init__(self) -> None:
        path = ctypes.util.find_library("crypto") or "libcrypto.so"
        try:
            self.lib = ctypes.CDLL(path)
        except OSError as exc:
            raise GuardError("trusted libcrypto unavailable") from exc
        self.lib.EVP_PKEY_new_raw_public_key.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.lib.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
        self.lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        self.lib.EVP_MD_CTX_new.argtypes = []
        self.lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
        self.lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        self.lib.EVP_DigestVerifyInit.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.lib.EVP_DigestVerifyInit.restype = ctypes.c_int
        self.lib.EVP_DigestVerify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.lib.EVP_DigestVerify.restype = ctypes.c_int

    def verify_ed25519(self, public_key: bytes, signature: bytes, message: bytes) -> bool:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        key_buffer = ctypes.create_string_buffer(public_key)
        sig_buffer = ctypes.create_string_buffer(signature)
        msg_buffer = ctypes.create_string_buffer(message)
        pkey = self.lib.EVP_PKEY_new_raw_public_key(
            self.EVP_PKEY_ED25519,
            None,
            key_buffer,
            len(public_key),
        )
        if not pkey:
            raise GuardError("trusted Ed25519 public key rejected")
        md_ctx = self.lib.EVP_MD_CTX_new()
        if not md_ctx:
            self.lib.EVP_PKEY_free(pkey)
            raise GuardError("trusted Ed25519 verifier unavailable")
        try:
            pctx = ctypes.c_void_p()
            if self.lib.EVP_DigestVerifyInit(md_ctx, ctypes.byref(pctx), None, None, pkey) != 1:
                raise GuardError("trusted Ed25519 verifier init failed")
            verified = self.lib.EVP_DigestVerify(
                md_ctx,
                sig_buffer,
                len(signature),
                msg_buffer,
                len(message),
            )
            return verified == 1
        finally:
            self.lib.EVP_MD_CTX_free(md_ctx)
            self.lib.EVP_PKEY_free(pkey)


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _load_json_no_duplicates(data: bytes) -> Any:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise GuardError(f"duplicate JSON key: {key}")
            seen.add(key)
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_pairs)
    except GuardError:
        raise
    except Exception as exc:
        raise GuardError("malformed authority JSON") from exc


def _file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity_from_stat(path: Path, st: os.stat_result) -> dict[str, Any]:
    return {
        "path": str(path),
        "dev": st.st_dev,
        "ino": st.st_ino,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.S_IMODE(st.st_mode),
        "nlink": st.st_nlink,
    }


def _same_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return left == right


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _canonical_input_path(path_arg: str | Path, label: str) -> Path:
    raw = Path(path_arg)
    if not raw.is_absolute():
        raise GuardError(f"{label} must be a canonical absolute path")
    if any(part in {"", ".", ".."} for part in raw.parts):
        raise GuardError(f"{label} must be a canonical absolute path")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise GuardError(f"{label} unavailable") from exc
    if raw != resolved:
        raise GuardError(f"{label} must be a canonical absolute path")
    return resolved


def _safe_reason(message: str) -> str:
    clean = []
    for character in message[:240]:
        code = ord(character)
        if 0x20 <= code <= 0x7E and character not in "\r\n":
            clean.append(character)
        else:
            clean.append("?")
    return "".join(clean) or "start authority rejected"


def _validate_identifier(value: str, pattern: re.Pattern[str], label: str) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise GuardError(f"{label} is invalid")


def _open_dir_at(parent_fd: int, name: str) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise GuardError("unsafe authority directory name")
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise GuardError(f"authority {name} directory unavailable") from exc
    try:
        _validate_directory_stat(os.fstat(fd), f"authority {name} directory")
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_regular_at(parent_fd: int, name: str, *, max_bytes: int, label: str) -> bytes:
    if "/" in name or name in {"", ".", ".."}:
        raise GuardError(f"unsafe {label} name")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError as exc:
        raise GuardError(f"{label} unavailable") from exc
    try:
        st = os.fstat(fd)
        _validate_regular_stat(st, label)
        if st.st_size <= 0 or st.st_size > max_bytes:
            raise GuardError(f"{label} has invalid size")
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != st.st_size or len(data) > max_bytes:
            raise GuardError(f"{label} changed while reading")
        return data
    finally:
        os.close(fd)


def _validate_directory_stat(st: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(st.st_mode):
        raise GuardError(f"{label} is not a directory")
    if st.st_uid != os.getuid():
        raise GuardError(f"{label} owner mismatch")
    if stat.S_IMODE(st.st_mode) & 0o022:
        raise GuardError(f"{label} is group/world writable")


def _validate_regular_stat(st: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise GuardError(f"{label} is not a regular file")
    if st.st_uid != os.getuid():
        raise GuardError(f"{label} owner mismatch")
    if st.st_nlink != 1:
        raise GuardError(f"{label} must be single-link")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise GuardError(f"{label} mode must be 0600-compatible")


def _open_authority_root(
    root_arg: str | Path,
    repo: Path,
    tmpdir: Path,
) -> tuple[int, Path, dict[str, Any]]:
    root = _canonical_input_path(root_arg, "authority root")
    try:
        root_lstat = os.lstat(root)
    except OSError as exc:
        raise GuardError("authority root unavailable") from exc
    if stat.S_ISLNK(root_lstat.st_mode):
        raise GuardError("authority root must not be a symlink")
    root_path = root
    repo_path = repo.resolve(strict=True)
    tmpdir_path = tmpdir.resolve(strict=True)
    if _is_relative_to(root_path, repo_path) or _is_relative_to(repo_path, root_path):
        raise GuardError("authority root must be outside the repository/worktree")
    if _is_relative_to(root_path, tmpdir_path) or _is_relative_to(tmpdir_path, root_path):
        raise GuardError("authority root must be independent of TMPDIR")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_fstat = os.fstat(fd)
        _validate_directory_stat(root_fstat, "authority root")
        if (
            root_lstat.st_dev != root_fstat.st_dev
            or root_lstat.st_ino != root_fstat.st_ino
            or root_lstat.st_uid != root_fstat.st_uid
            or stat.S_IMODE(root_lstat.st_mode) != stat.S_IMODE(root_fstat.st_mode)
        ):
            raise GuardError("authority root identity changed")
        return fd, root_path, _identity_from_stat(root_path, root_fstat)
    except Exception:
        os.close(fd)
        raise


def _open_captured_authority_root(
    root_arg: str | Path,
    expected_identity: dict[str, Any],
) -> tuple[int, Path, dict[str, Any]]:
    root = _canonical_input_path(root_arg, "authority root")
    try:
        root_lstat = os.lstat(root)
    except OSError as exc:
        raise GuardError("authority root unavailable") from exc
    if stat.S_ISLNK(root_lstat.st_mode):
        raise GuardError("authority root must not be a symlink")
    root_path = root
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_fstat = os.fstat(fd)
        _validate_directory_stat(root_fstat, "authority root")
        actual_identity = _identity_from_stat(root_path, root_fstat)
        if not _same_identity(actual_identity, expected_identity):
            raise GuardError("authority root replacement detected")
        if (
            root_lstat.st_dev != root_fstat.st_dev
            or root_lstat.st_ino != root_fstat.st_ino
            or root_lstat.st_uid != root_fstat.st_uid
            or stat.S_IMODE(root_lstat.st_mode) != stat.S_IMODE(root_fstat.st_mode)
        ):
            raise GuardError("authority root identity changed")
        return fd, root_path, actual_identity
    except Exception:
        os.close(fd)
        raise


def _path_identity(path: str | Path, label: str, *, directory: bool = False) -> dict[str, Any]:
    target = Path(path)
    try:
        st = os.lstat(target)
    except OSError as exc:
        raise GuardError(f"{label} unavailable") from exc
    if stat.S_ISLNK(st.st_mode):
        raise GuardError(f"{label} must not be a symlink")
    resolved = target.resolve(strict=True)
    if directory:
        _validate_directory_stat(st, label)
    elif not stat.S_ISREG(st.st_mode) and label != "worktree git marker":
        raise GuardError(f"{label} is invalid")
    return _identity_from_stat(resolved, st)


def _git_identity(repo: Path) -> dict[str, Any]:
    git_marker = repo / ".git"
    marker_st = os.lstat(git_marker)
    if stat.S_ISLNK(marker_st.st_mode):
        raise GuardError("worktree git identity is a symlink")
    marker = _identity_from_stat(git_marker.resolve(strict=True), marker_st)
    marker_sha = ""
    if stat.S_ISREG(marker_st.st_mode):
        data = git_marker.read_bytes()
        if len(data) > 4096:
            raise GuardError("worktree git identity is oversized")
        marker_sha = hashlib.sha256(data).hexdigest()
        text = data.decode("utf-8", "strict").strip()
        if not text.startswith("gitdir: "):
            raise GuardError("worktree gitdir file is malformed")
        gitdir = Path(text.removeprefix("gitdir: "))
        if not gitdir.is_absolute():
            gitdir = (repo / gitdir).resolve(strict=True)
    elif stat.S_ISDIR(marker_st.st_mode):
        gitdir = git_marker.resolve(strict=True)
    else:
        raise GuardError("worktree git identity is invalid")
    common = gitdir / "commondir"
    if common.exists():
        common_text = common.read_text(encoding="utf-8").strip()
        common_gitdir = Path(common_text)
        if not common_gitdir.is_absolute():
            common_gitdir = (gitdir / common_gitdir).resolve(strict=True)
    else:
        common_gitdir = gitdir
    common_st = os.lstat(common_gitdir)
    if stat.S_ISLNK(common_st.st_mode):
        raise GuardError("worktree common gitdir is a symlink")
    _validate_directory_stat(common_st, "worktree common gitdir")
    return {
        "git_marker": marker,
        "git_marker_sha256": marker_sha,
        "common_gitdir": _identity_from_stat(common_gitdir.resolve(strict=True), common_st),
    }


def _expected_terminal_path(root: Path, authority_id: str) -> Path:
    return root / "outcomes" / f"{authority_id}.terminal.json"


def _read_capability(root_fd: int, authority_id: str) -> dict[str, Any]:
    issued_fd = _open_dir_at(root_fd, "issued")
    try:
        cap_data = _open_regular_at(
            issued_fd,
            f"{authority_id}.json",
            max_bytes=MAX_JSON_BYTES,
            label="issued capability",
        )
    finally:
        os.close(issued_fd)
    document = _load_json_no_duplicates(cap_data)
    if not isinstance(document, dict) or set(document) != {"claims", "signature"}:
        raise GuardError("capability envelope is invalid")
    claims = document["claims"]
    signature = document["signature"]
    if not isinstance(claims, dict):
        raise GuardError("capability claims are invalid")
    if not isinstance(signature, str) or not SIG_RE.fullmatch(signature):
        raise GuardError("capability signature is invalid")
    return {"claims": claims, "signature": signature}


def _verify_signature(
    claims: dict[str, Any],
    signature_hex: str,
    *,
    public_key_raw_hex: str,
) -> None:
    if not HEX64_RE.fullmatch(public_key_raw_hex):
        raise GuardError("issuer public key is invalid")
    public_key = bytes.fromhex(public_key_raw_hex)
    signature = bytes.fromhex(signature_hex)
    message = _canonical_json(claims)
    if not _LibCrypto().verify_ed25519(public_key, signature, message):
        raise GuardError("capability signature mismatch")


def _issuer_key_id(public_key_raw_hex: str) -> str:
    if not HEX64_RE.fullmatch(public_key_raw_hex):
        raise GuardError("issuer public key is invalid")
    return hashlib.sha256(bytes.fromhex(public_key_raw_hex)).hexdigest()


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise GuardError(f"capability {key} is invalid")
    return value


def _require_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise GuardError(f"capability {key} is invalid")
    return value


def _validate_claims(
    claims: dict[str, Any],
    *,
    authority_id: str,
    authority_root_path: Path,
    authority_root_identity: dict[str, Any],
    repo_path: Path,
    tmpdir_path: Path,
    tmpdir_identity: dict[str, Any],
    node_id: str,
    p_commit: str,
    t_commit: str,
    launcher_path: Path,
    helper_path: Path,
    attempt_id: str,
    issuer_key_id: str,
) -> int:
    expected_keys = {
        "schema",
        "version",
        "authority_id",
        "nonce",
        "approval_id",
        "issuer_key_id",
        "action",
        "node_id",
        "p",
        "t",
        "authority_root_path",
        "authority_root_identity",
        "tmpdir_path",
        "tmpdir_identity",
        "repo_path",
        "git_identity",
        "launcher_path",
        "launcher_sha256",
        "helper_path",
        "helper_sha256",
        "issued_at",
        "expires_at",
        "expected_uid",
        "expected_gid",
        "attempt_id",
        "expected_terminal_artifact",
        "scope",
    }
    if set(claims) - {"test_faults_allowed"} != expected_keys:
        raise GuardError("capability claims shape is invalid")
    now = int(time.time())
    if claims["schema"] != SCHEMA or claims["version"] != VERSION:
        raise GuardError("capability schema/version mismatch")
    if _require_string(claims, "authority_id") != authority_id:
        raise GuardError("authority id mismatch")
    _validate_identifier(authority_id, AUTHORITY_ID_RE, "authority id")
    _validate_identifier(_require_string(claims, "attempt_id"), ATTEMPT_ID_RE, "attempt id")
    if claims["attempt_id"] != attempt_id:
        raise GuardError("capability attempt binding mismatch")
    nonce = _require_string(claims, "nonce")
    if len(nonce) < 16 or len(nonce) > 128:
        raise GuardError("capability nonce is invalid")
    if claims["approval_id"] != OWNER_APPROVAL_ID:
        raise GuardError("capability approval binding mismatch")
    if claims["issuer_key_id"] != issuer_key_id:
        raise GuardError("capability issuer binding mismatch")
    if claims["action"] != ACTION:
        raise GuardError("capability action binding mismatch")
    if claims["node_id"] != node_id or node_id != SUPPORTED_NODE_ID:
        raise GuardError("capability node binding mismatch")
    if claims["p"] != p_commit or not HEX40_RE.fullmatch(p_commit):
        raise GuardError("capability P binding mismatch")
    if claims["t"] != t_commit or not HEX40_RE.fullmatch(t_commit):
        raise GuardError("capability T binding mismatch")
    if Path(claims["authority_root_path"]) != authority_root_path:
        raise GuardError("capability authority root path mismatch")
    if not _same_identity(claims["authority_root_identity"], authority_root_identity):
        raise GuardError("capability authority root identity mismatch")
    if Path(claims["tmpdir_path"]) != tmpdir_path:
        raise GuardError("capability TMPDIR path mismatch")
    if not _same_identity(claims["tmpdir_identity"], tmpdir_identity):
        raise GuardError("capability TMPDIR identity mismatch")
    if Path(claims["repo_path"]).resolve(strict=True) != repo_path.resolve(strict=True):
        raise GuardError("capability worktree binding mismatch")
    if claims["git_identity"] != _git_identity(repo_path):
        raise GuardError("capability git/common-git binding mismatch")
    if Path(claims["launcher_path"]).resolve(strict=True) != launcher_path.resolve(strict=True):
        raise GuardError("capability launcher path binding mismatch")
    if claims["launcher_sha256"] != _file_sha256(launcher_path):
        raise GuardError("capability launcher digest mismatch")
    if Path(claims["helper_path"]).resolve(strict=True) != helper_path.resolve(strict=True):
        raise GuardError("capability helper path binding mismatch")
    if claims["helper_sha256"] != _file_sha256(helper_path):
        raise GuardError("capability helper digest mismatch")
    if (
        _require_int(claims, "expected_uid") != os.getuid()
        or _require_int(claims, "expected_gid") != os.getgid()
    ):
        raise GuardError("capability uid/gid binding mismatch")
    issued_at = _require_int(claims, "issued_at")
    expires_at = _require_int(claims, "expires_at")
    if issued_at > now + MAX_ISSUED_AT_FUTURE_SKEW_SECONDS:
        raise GuardError("capability issued-at is in the future")
    if expires_at <= now or expires_at <= issued_at:
        raise GuardError("capability issue/expiry window mismatch")
    if expires_at - issued_at > MAX_CAPABILITY_LIFETIME_SECONDS:
        raise GuardError("capability lifetime exceeds maximum")
    terminal_path = _expected_terminal_path(authority_root_path, authority_id)
    if Path(claims["expected_terminal_artifact"]) != terminal_path:
        raise GuardError("capability terminal path binding mismatch")
    if claims["scope"] != "supported-current-clean-sibling-launcher-only":
        raise GuardError("capability scope mismatch")
    return now


def _spent_path(authority_id: str) -> str:
    _validate_identifier(authority_id, AUTHORITY_ID_RE, "authority id")
    return f"{authority_id}.spent.json"


def _terminal_path(authority_id: str) -> str:
    _validate_identifier(authority_id, AUTHORITY_ID_RE, "authority id")
    return f"{authority_id}.terminal.json"


def _read_spent_record(
    root_fd: int,
    authority_id: str,
    *,
    expected_attempt_id: str,
) -> tuple[dict[str, Any], str]:
    spent_fd = _open_dir_at(root_fd, "spent")
    try:
        data = _open_regular_at(
            spent_fd,
            _spent_path(authority_id),
            max_bytes=MAX_JSON_BYTES,
            label="spent record",
        )
    finally:
        os.close(spent_fd)
    digest = hashlib.sha256(data).hexdigest()
    record = _load_json_no_duplicates(data)
    if not isinstance(record, dict):
        raise GuardError("spent record is invalid")
    if record.get("schema") != SPENT_SCHEMA or record.get("version") != VERSION:
        raise GuardError("spent record schema mismatch")
    if record.get("authority_id") != authority_id:
        raise GuardError("spent record authority mismatch")
    if record.get("attempt_id") != expected_attempt_id:
        raise GuardError("spent record attempt mismatch")
    return record, digest


def consume_authority(
    *,
    authority_id: str,
    authority_root: str | Path,
    repo_path: str | Path,
    tmpdir: str | Path,
    node_id: str,
    p_commit: str,
    t_commit: str,
    launcher_path: str | Path,
    helper_path: str | Path,
    attempt_id: str,
    public_key_raw_hex: str | None = None,
    issuer_key_id: str | None = None,
) -> dict[str, Any]:
    _validate_identifier(authority_id, AUTHORITY_ID_RE, "authority id")
    _validate_identifier(attempt_id, ATTEMPT_ID_RE, "attempt id")
    issuer_public = public_key_raw_hex or PRODUCTION_PUBLIC_KEY_RAW_HEX
    issuer_id = issuer_key_id or PRODUCTION_ISSUER_KEY_ID
    derived_issuer_id = _issuer_key_id(issuer_public)
    if issuer_id != derived_issuer_id:
        raise GuardError("capability issuer key id mismatch")
    if public_key_raw_hex is None and derived_issuer_id != PRODUCTION_ISSUER_KEY_ID:
        raise GuardError("production issuer key id mismatch")
    repo = Path(repo_path).resolve(strict=True)
    tmpdir_resolved = _canonical_input_path(tmpdir, "TMPDIR")
    tmpdir_identity = _path_identity(tmpdir_resolved, "TMPDIR", directory=True)
    root_fd, root_path, root_identity = _open_authority_root(authority_root, repo, tmpdir_resolved)
    try:
        envelope = _read_capability(root_fd, authority_id)
        claims = envelope["claims"]
        _verify_signature(
            claims,
            envelope["signature"],
            public_key_raw_hex=issuer_public,
        )
        now = _validate_claims(
            claims,
            authority_id=authority_id,
            authority_root_path=root_path,
            authority_root_identity=root_identity,
            repo_path=repo,
            tmpdir_path=tmpdir_resolved,
            tmpdir_identity=tmpdir_identity,
            node_id=node_id,
            p_commit=p_commit,
            t_commit=t_commit,
            launcher_path=Path(launcher_path),
            helper_path=Path(helper_path),
            attempt_id=attempt_id,
            issuer_key_id=issuer_id,
        )
        spent_fd = _open_dir_at(root_fd, "spent")
        try:
            record = {
                "schema": SPENT_SCHEMA,
                "version": VERSION,
                "authority_id": authority_id,
                "nonce": claims["nonce"],
                "approval_id": OWNER_APPROVAL_ID,
                "issuer_key_id": issuer_id,
                "action": ACTION,
                "node_id": node_id,
                "p": p_commit,
                "t": t_commit,
                "authority_root_path": str(root_path),
                "authority_root_identity": root_identity,
                "tmpdir_path": str(tmpdir_resolved),
                "tmpdir_identity": tmpdir_identity,
                "repo_path": str(repo),
                "git_identity": claims["git_identity"],
                "launcher_path": str(Path(launcher_path).resolve(strict=True)),
                "launcher_sha256": claims["launcher_sha256"],
                "helper_path": str(Path(helper_path).resolve(strict=True)),
                "helper_sha256": claims["helper_sha256"],
                "issued_at": claims["issued_at"],
                "expires_at": claims["expires_at"],
                "invoking_uid": os.getuid(),
                "invoking_gid": os.getgid(),
                "invoking_pid": os.getpid(),
                "attempt_id": attempt_id,
                "consumed_at": now,
                "expected_terminal_artifact": claims["expected_terminal_artifact"],
                "promise": "at-most-once-authorized-attempt",
            }
            data = _canonical_json(record) + b"\n"
            try:
                fd = os.open(
                    _spent_path(authority_id),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=spent_fd,
                )
            except FileExistsError as exc:
                raise GuardError("authority already spent") from exc
            if (
                os.environ.get(FAULT_ENV) == "after-spent-create"
                and claims.get("test_faults_allowed") is True
            ):
                os.close(fd)
                os.fsync(spent_fd)
                raise GuardError("injected fault after spent create")
            try:
                written = os.write(fd, data)
                if written != len(data):
                    raise GuardError("spent record short write")
                if (
                    os.environ.get(FAULT_ENV) == "after-spent-write"
                    and claims.get("test_faults_allowed") is True
                ):
                    raise GuardError("injected fault after spent write")
                os.fsync(fd)
            finally:
                os.close(fd)
            if (
                os.environ.get(FAULT_ENV) == "after-spent-file-fsync"
                and claims.get("test_faults_allowed") is True
            ):
                os.fsync(spent_fd)
                raise GuardError("injected fault after spent file fsync")
            os.fsync(spent_fd)
            spent_sha256 = hashlib.sha256(data).hexdigest()
            return {
                "authority_id": authority_id,
                "attempt_id": attempt_id,
                "authority_root_path": str(root_path),
                "authority_root_identity": root_identity,
                "spent_record_sha256": spent_sha256,
                "terminal_path": claims["expected_terminal_artifact"],
            }
        finally:
            os.close(spent_fd)
    finally:
        os.close(root_fd)


def _terminal_record(
    *,
    authority_id: str,
    attempt_id: str,
    outcome: str,
    exit_code: int,
    reason: str,
    spent_record_sha256: str,
) -> dict[str, Any]:
    if outcome not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
        raise GuardError("terminal outcome is invalid")
    _validate_identifier(authority_id, AUTHORITY_ID_RE, "authority id")
    _validate_identifier(attempt_id, ATTEMPT_ID_RE, "attempt id")
    if not HEX64_RE.fullmatch(spent_record_sha256):
        raise GuardError("spent digest is invalid")
    return {
        "schema": TERMINAL_SCHEMA,
        "version": VERSION,
        "authority_id": authority_id,
        "attempt_id": attempt_id,
        "outcome": outcome,
        "exit_code": exit_code,
        "reason_sha256": hashlib.sha256(reason.encode("utf-8", "replace")).hexdigest(),
        "spent_record_sha256": spent_record_sha256,
        "recorded_at": int(time.time()),
        "promise": "terminal-result-does-not-rearm-authority",
    }


def record_terminal(
    *,
    authority_id: str,
    authority_root: str | Path,
    authority_root_identity: dict[str, Any],
    attempt_id: str,
    outcome: str,
    exit_code: int,
    reason: str,
    spent_record_sha256: str,
) -> None:
    _validate_identifier(authority_id, AUTHORITY_ID_RE, "authority id")
    _validate_identifier(attempt_id, ATTEMPT_ID_RE, "attempt id")
    root_fd, root_path, root_identity = _open_captured_authority_root(
        authority_root,
        authority_root_identity,
    )
    try:
        if not _same_identity(root_identity, authority_root_identity):
            raise GuardError("authority root replacement detected")
        spent, actual_spent_sha256 = _read_spent_record(
            root_fd,
            authority_id,
            expected_attempt_id=attempt_id,
        )
        if actual_spent_sha256 != spent_record_sha256:
            raise GuardError("spent record digest mismatch")
        if Path(spent["authority_root_path"]) != root_path:
            raise GuardError("spent record root path mismatch")
        record = _terminal_record(
            authority_id=authority_id,
            attempt_id=attempt_id,
            outcome=outcome,
            exit_code=exit_code,
            reason=reason,
            spent_record_sha256=spent_record_sha256,
        )
        data = _canonical_json(record) + b"\n"
        outcomes_fd = _open_dir_at(root_fd, "outcomes")
        try:
            try:
                fd = os.open(
                    _terminal_path(authority_id),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=outcomes_fd,
                )
            except FileExistsError:
                existing = _open_regular_at(
                    outcomes_fd,
                    _terminal_path(authority_id),
                    max_bytes=MAX_JSON_BYTES,
                    label="terminal record",
                )
                existing_record = _load_json_no_duplicates(existing)
                if not isinstance(existing_record, dict):
                    raise GuardError("terminal record is invalid") from None
                comparable = dict(existing_record)
                comparable.pop("recorded_at", None)
                expected = dict(record)
                expected.pop("recorded_at", None)
                if comparable != expected:
                    raise GuardError("preexisting terminal record mismatch") from None
                return
            try:
                written = os.write(fd, data)
                if written != len(data):
                    raise GuardError("terminal record short write")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(outcomes_fd)
        finally:
            os.close(outcomes_fd)
    finally:
        os.close(root_fd)


def consume_from_launcher() -> dict[str, Any] | None:
    if os.environ.get("NODE_ID") != SUPPORTED_NODE_ID:
        return None
    required = [
        "ACGS_START_AUTHORITY_ROOT",
        "ACGS_START_AUTHORITY_ID",
        "ACGS_START_AUTHORITY_ATTEMPT_ID",
        "ACGS_CLEAN_SIBLING_LAUNCHER_PATH",
        "ACGS_START_AUTHORITY_HELPER_PATH",
    ]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise GuardError("P3C start authority environment is incomplete")
    root = Path(os.environ["ACGS_CLEAN_SIBLING_LAUNCHER_PATH"]).resolve(strict=True).parents[2]
    return consume_authority(
        authority_id=os.environ["ACGS_START_AUTHORITY_ID"],
        authority_root=os.environ["ACGS_START_AUTHORITY_ROOT"],
        repo_path=root,
        tmpdir=os.environ.get("TMPDIR", "/tmp"),
        node_id=os.environ["NODE_ID"],
        p_commit=os.environ["P"],
        t_commit=sys.argv[1],
        launcher_path=os.environ["ACGS_CLEAN_SIBLING_LAUNCHER_PATH"],
        helper_path=os.environ["ACGS_START_AUTHORITY_HELPER_PATH"],
        attempt_id=os.environ["ACGS_START_AUTHORITY_ATTEMPT_ID"],
    )


def terminal_from_launcher(
    context: dict[str, Any] | None,
    outcome: str,
    exit_code: int,
    reason: str,
) -> None:
    if context is None:
        return
    record_terminal(
        authority_id=context["authority_id"],
        authority_root=context["authority_root_path"],
        authority_root_identity=context["authority_root_identity"],
        attempt_id=context["attempt_id"],
        outcome=outcome,
        exit_code=exit_code,
        reason=reason,
        spent_record_sha256=context["spent_record_sha256"],
    )


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="consume or finish a start authority")
    subparsers = parser.add_subparsers(dest="command", required=True)
    consume = subparsers.add_parser("consume")
    consume.add_argument("--authority-id", required=True)
    consume.add_argument("--authority-root", required=True)
    consume.add_argument("--repo-path", required=True)
    consume.add_argument("--tmpdir", required=True)
    consume.add_argument("--node-id", required=True)
    consume.add_argument("--p", required=True)
    consume.add_argument("--t", required=True)
    consume.add_argument("--launcher-path", required=True)
    consume.add_argument("--helper-path", required=True)
    consume.add_argument("--attempt-id", required=True)
    args = parser.parse_args(argv)
    try:
        consume_authority(
            authority_id=args.authority_id,
            authority_root=args.authority_root,
            repo_path=args.repo_path,
            tmpdir=args.tmpdir,
            node_id=args.node_id,
            p_commit=args.p,
            t_commit=args.t,
            launcher_path=args.launcher_path,
            helper_path=args.helper_path,
            attempt_id=args.attempt_id,
        )
    except GuardError as exc:
        print(f"CLEAN_SIBLING=FAIL phase=B0 reason={_safe_reason(str(exc))}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
