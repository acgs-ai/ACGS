"""Restricted canary store — fail-closed persistence for secret material.

Everything that must never reach working buckets, evidence packs, logs, or
the repository lives behind this boundary: canary token plaintexts, licensee
derivation salts, HMAC keys, and signing-secret references.

Location policy (all violations refuse startup, no fallback):

- the path comes only from explicit configuration (constructor argument or
  the ACGS_CANARY_STORE environment variable) — never a default;
- the path must exist, be a real directory, and not a symlink;
- the resolved path must NOT be inside any git work tree (a store inside
  the repository will eventually be committed);
- the directory must be owned by the current user, mode 0700 (no group or
  other bits) — world-readable or group-writable stores are refused;
- an existing store is never silently re-initialized or overwritten.

Files are written atomically (tempfile + fsync + os.replace) with 0600
permissions, and every record file carries an integrity digest checked on
read. Secret-bearing values use the Secret wrapper whose repr/str never
prints content.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .errors import StoreConflictError, StoreIntegrityError, StoreLocationError

_STORE_MARKER = "acgs-canary-store.json"
_STORE_SCHEMA = "acgs_canary_store/v1"
ENV_STORE_PATH = "ACGS_CANARY_STORE"


class Secret:
    """Opaque holder for secret bytes. Never prints its content."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        if not isinstance(value, bytes) or not value:
            raise StoreIntegrityError("secret must be non-empty bytes")
        self._value = value

    def reveal(self) -> bytes:
        """Explicit, greppable access point for the secret bytes."""
        return self._value

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        # Constant-time comparison; never leak via timing.
        if not isinstance(other, Secret):
            return NotImplemented
        import hmac as _hmac

        return _hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        raise TypeError("secrets are not hashable")


def _inside_git_worktree(path: Path) -> bool:
    try:
        res = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        # If we cannot determine, fail closed: treat as inside.
        return True
    return res.returncode == 0 and res.stdout.strip() == "true"


def _validate_store_dir(raw: str | os.PathLike[str]) -> Path:
    if not raw:
        raise StoreLocationError("restricted store path is not configured")
    p = Path(raw)
    if not p.is_absolute():
        raise StoreLocationError("restricted store path must be absolute")
    if p.is_symlink():
        raise StoreLocationError("restricted store path must not be a symlink")
    if not p.exists():
        raise StoreLocationError(f"restricted store path does not exist: {p}")
    if not p.is_dir():
        raise StoreLocationError("restricted store path is not a directory")
    resolved = p.resolve()
    if resolved != p:
        raise StoreLocationError("restricted store path is ambiguous (does not resolve to itself)")
    st = p.stat()
    if st.st_uid != os.getuid():
        raise StoreLocationError("restricted store must be owned by the current user")
    mode = stat.S_IMODE(st.st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise StoreLocationError(
            f"restricted store mode {oct(mode)} grants group/other access; require 0700"
        )
    if _inside_git_worktree(p):
        raise StoreLocationError("restricted store must not live inside a git work tree")
    return resolved


def _atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _atomic_create(path: Path, data: bytes) -> None:
    """Atomic create-if-absent: the fully written temp file becomes visible
    only via os.link(), which fails if the path already exists. Unlike an
    exists() check followed by os.replace(), two concurrent creators can
    never silently replace each other's committed record."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            raise StoreConflictError(f"record exists: {path.name}") from None
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _sealed_record(payload: dict[str, Any]) -> bytes:
    body = canonical_bytes(payload)
    digest = hashlib.sha256(body).hexdigest()
    return canonical_bytes({"body": payload, "sha256": digest}) + b"\n"


def _open_sealed_record(raw: bytes) -> dict[str, Any]:
    try:
        outer = json.loads(raw)
        body = outer["body"]
        digest = outer["sha256"]
        if set(outer) != {"body", "sha256"}:
            raise StoreIntegrityError("unknown fields in sealed record envelope")
    except StoreIntegrityError:
        raise
    except Exception as exc:
        raise StoreIntegrityError("malformed sealed record") from exc
    if hashlib.sha256(canonical_bytes(body)).hexdigest() != digest:
        raise StoreIntegrityError("sealed record failed integrity check")
    return body


class CanaryStoreBackend:
    """Interface. Implementations: RestrictedFileStore, InMemoryStore (tests)."""

    production_safe: bool = False

    def read_record(self, name: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def write_record(self, name: str, payload: dict[str, Any], *, overwrite: bool) -> None:
        raise NotImplementedError

    def list_records(self, prefix: str) -> list[str]:
        raise NotImplementedError


_NAME_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def _check_name(name: str) -> str:
    if not name or name.startswith(".") or "/" in name or set(name.lower()) - _NAME_ALLOWED:
        raise StoreIntegrityError(f"illegal record name: {name!r}")
    return name


class RestrictedFileStore(CanaryStoreBackend):
    """The production backend. Refuses unsafe locations at construction."""

    production_safe = True

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        configured = path if path is not None else os.environ.get(ENV_STORE_PATH)
        if configured is None:
            raise StoreLocationError(f"restricted store path not configured (set {ENV_STORE_PATH})")
        self._dir = _validate_store_dir(configured)
        self._marker = self._dir / _STORE_MARKER

    @property
    def path(self) -> Path:
        return self._dir

    def initialize(self, *, operator: str) -> None:
        try:
            _atomic_create(
                self._marker,
                _sealed_record({"schema": _STORE_SCHEMA, "operator": operator}),
            )
        except StoreConflictError:
            raise StoreConflictError(
                "store already initialized; refusing to re-initialize"
            ) from None

    def assert_initialized(self) -> None:
        if not self._marker.exists():
            raise StoreIntegrityError("store is not initialized")
        body = _open_sealed_record(self._marker.read_bytes())
        if body.get("schema") != _STORE_SCHEMA:
            raise StoreIntegrityError(f"store schema mismatch: {body.get('schema')!r}")

    def read_record(self, name: str) -> dict[str, Any] | None:
        self.assert_initialized()
        f = self._dir / _check_name(name)
        if not f.exists():
            return None
        mode = stat.S_IMODE(f.stat().st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise StoreLocationError(f"record {name} has unsafe mode {oct(mode)}")
        return _open_sealed_record(f.read_bytes())

    def write_record(self, name: str, payload: dict[str, Any], *, overwrite: bool) -> None:
        self.assert_initialized()
        f = self._dir / _check_name(name)
        if overwrite:
            _atomic_write(f, _sealed_record(payload))
        else:
            # Atomic create-if-absent: a racing creator must get a conflict,
            # never silently replace a committed record (e.g. the licensee
            # reference key, which would make derived refs irreproducible).
            _atomic_create(f, _sealed_record(payload))

    def list_records(self, prefix: str) -> list[str]:
        self.assert_initialized()
        return sorted(
            p.name
            for p in self._dir.iterdir()
            if p.is_file()
            and p.name.startswith(prefix)
            and p.name != _STORE_MARKER
            and not p.name.startswith(".tmp-")
        )


class InMemoryStore(CanaryStoreBackend):
    """Test-only backend. Cannot be selected by production configuration:

    construction requires the literal acknowledgment string, which no
    configuration file or environment variable pathway supplies.
    """

    production_safe = False
    _ACK = "test-only-not-production"

    def __init__(self, acknowledge: str) -> None:
        if acknowledge != self._ACK:
            raise StoreLocationError("InMemoryStore requires explicit test-only acknowledgment")
        self._records: dict[str, dict[str, Any]] = {}
        self.initialized = False

    def initialize(self, *, operator: str) -> None:
        if self.initialized:
            raise StoreConflictError("store already initialized")
        self.initialized = True
        self._operator = operator

    def assert_initialized(self) -> None:
        if not self.initialized:
            raise StoreIntegrityError("store is not initialized")

    def read_record(self, name: str) -> dict[str, Any] | None:
        self.assert_initialized()
        _check_name(name)
        rec = self._records.get(name)
        # round-trip through the sealed envelope so integrity bugs surface in tests
        return None if rec is None else _open_sealed_record(_sealed_record(rec)[:-1] + b"\n")

    def write_record(self, name: str, payload: dict[str, Any], *, overwrite: bool) -> None:
        self.assert_initialized()
        _check_name(name)
        if name in self._records and not overwrite:
            raise StoreConflictError(f"record exists: {name}")
        self._records[name] = json.loads(canonical_bytes(payload))

    def list_records(self, prefix: str) -> list[str]:
        self.assert_initialized()
        return sorted(n for n in self._records if n.startswith(prefix))
