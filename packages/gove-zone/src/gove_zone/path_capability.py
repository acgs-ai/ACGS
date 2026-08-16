"""Descriptor-retained directory capability for trusted internal path consumers."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from threading import RLock
from typing import Any, Final, SupportsIndex
from weakref import WeakKeyDictionary, WeakSet, finalize

DirectoryIdentity = tuple[int, int]
ErrorType = type[Exception]

_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_PROC_DIRECTORY_FLAGS: Final = _DIRECTORY_FLAGS & ~getattr(os, "O_NOFOLLOW", 0)
_LIVE_INSTANCES: WeakSet[object] = WeakSet()
_OWNED_LOCK = RLock()


@dataclass(slots=True)
class _DescriptorFinalizerState:
    descriptors: tuple[int, ...]
    lock: RLock = field(default_factory=RLock)
    closed: bool = False

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            for descriptor in self.descriptors:
                with suppress(OSError):
                    os.close(descriptor)


def _finalize_descriptors(state: _DescriptorFinalizerState) -> None:
    state.close()


@dataclass(slots=True)
class _OwnedDirectoryRecord:
    identity: DirectoryIdentity
    error_type: ErrorType
    resources: _DescriptorFinalizerState
    finalizer: finalize[[_DescriptorFinalizerState], OwnedAttestedDirectory]
    state: str = "AVAILABLE"


_OWNED_INSTANCES: WeakKeyDictionary[OwnedAttestedDirectory, _OwnedDirectoryRecord]


class OwnedAttestedDirectory:
    """Path-free, non-parented ownership of one retained directory inode."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("OwnedAttestedDirectory can only be detached from AttestedDirectory")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OwnedAttestedDirectory cannot be subclassed")

    def __enter__(self) -> OwnedAttestedDirectory:
        require_owned_attested_directory(self)
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        _close_owned_attested_directory(self)

    def __copy__(self) -> OwnedAttestedDirectory:
        raise TypeError("OwnedAttestedDirectory instances cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> OwnedAttestedDirectory:
        raise TypeError("OwnedAttestedDirectory instances cannot be deep-copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("OwnedAttestedDirectory instances cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("OwnedAttestedDirectory instances cannot be serialized")


_OWNED_INSTANCES = WeakKeyDictionary()


class PathCapabilityError(RuntimeError):
    """A retained directory capability failed closed."""


class PathCapabilityIdentityError(PathCapabilityError):
    """The lexical name no longer identifies the retained directory inode."""

    reason_code: Final = "PATH_CAPABILITY_IDENTITY_CHANGED"


def _identity(info: os.stat_result) -> DirectoryIdentity:
    return info.st_dev, info.st_ino


def _parts(value: str | PurePath, *, error_type: ErrorType) -> tuple[str, ...]:
    raw = os.fspath(value)
    if "\0" in raw:
        raise error_type("attested paths must not contain NUL bytes")
    path = PurePath(raw)
    parts = () if str(path) == "." else path.parts
    if path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise error_type("attested paths must be normalized relative paths")
    return parts


def _duplicate(descriptor: int, *, error_type: ErrorType) -> int:
    try:
        duplicate = os.dup(descriptor)
        os.set_inheritable(duplicate, False)
        return duplicate
    except OSError as exc:
        raise error_type("attested directory descriptor is unavailable") from exc


def _absolute_directory(path: Path, *, error_type: ErrorType) -> tuple[int, DirectoryIdentity]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts[1:]
    if not absolute.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise error_type("attested display path must be absolute and normalized")
    descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        for part in parts:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        return descriptor, _identity(info)
    except BaseException as exc:
        with suppress(OSError):
            os.close(descriptor)
        if isinstance(exc, error_type):
            raise
        raise error_type("attested lexical directory is unsafe or unavailable") from exc


def is_proc_fd_path(value: str | os.PathLike[str]) -> bool:
    """Return whether *value* names a Linux procfs descriptor alias."""

    path = Path(os.path.abspath(os.fspath(value)))
    parts = path.parts
    return (
        len(parts) >= 5
        and parts[0:2] == ("/", "proc")
        and (parts[2] in {"self", "thread-self"} or parts[2].isdecimal())
        and parts[3] == "fd"
        and parts[4].isdecimal()
    )


def is_descriptor_alias_path(value: str | os.PathLike[str]) -> bool:
    """Return whether *value* lexically enters a procfs or ``/dev/fd`` alias."""

    raw = os.fspath(value)
    if "\0" in raw:
        return False
    path = Path(os.path.abspath(raw))
    parts = path.parts
    return is_proc_fd_path(path) or (
        len(parts) >= 4 and parts[:3] == ("/", "dev", "fd") and parts[3].isdecimal()
    )


def validate_direct_file_path(
    value: str | os.PathLike[str],
    *,
    error_type: ErrorType,
    create_parent: bool,
) -> Path:
    """Validate a legacy pathname without following any symlink component."""

    raw = os.fspath(value)
    if not raw or "\0" in raw:
        raise error_type("direct file path is empty or contains NUL bytes")
    absolute = Path(os.path.abspath(raw))
    if not absolute.is_absolute() or not absolute.name:
        raise error_type("direct file path must identify a file")
    if is_descriptor_alias_path(absolute):
        raise error_type("direct descriptor alias paths are not accepted")

    descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        for part in absolute.parent.parts[1:]:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create_parent:
                    raise
                os.mkdir(part, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        try:
            entry = os.stat(absolute.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(entry.st_mode):
                raise error_type("direct file path must not be a symlink or special file")
        return absolute
    except BaseException as exc:
        if isinstance(exc, error_type):
            raise
        raise error_type("direct file path contains an unsafe or unavailable component") from exc
    finally:
        with suppress(OSError):
            os.close(descriptor)


class AttestedDirectory:
    """A registered retained directory inode with relative-only operations.

    Same-process inspection of private Python module state is outside this
    capability's threat model. Public construction, copying, proxying, and
    serialization are nevertheless rejected and every operation checks the
    exact instance against the live registry.
    """

    _parent_fd: int
    _root_fd: int
    _parent_identity: DirectoryIdentity
    _identity: DirectoryIdentity
    _display_path: Path
    _proc_root: Path
    _error_type: ErrorType
    _closed: bool
    _children: WeakSet[AttestedDirectory]
    _finalizer: finalize[[_DescriptorFinalizerState], AttestedDirectory]
    _minting_child: bool
    _minting_owned: bool

    def __init__(
        self,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        raise TypeError("AttestedDirectory can only be minted by PinnedOutputRoot.attest")

    @property
    def identity(self) -> DirectoryIdentity:
        _require_live(self)
        return self._identity

    @property
    def display_path(self) -> Path:
        _require_live(self)
        return self._display_path

    @property
    def root_fd(self) -> int:
        _require_live(self)
        return self._root_fd

    def duplicate_child_fd(self) -> tuple[int, DirectoryIdentity]:
        """Return one non-inheritable duplicate suitable for an exact ``pass_fds`` call."""

        self.checkpoint()
        duplicate = _duplicate(self._root_fd, error_type=self._error_type)
        try:
            info = os.fstat(duplicate)
            if (
                _identity(info) != self._identity
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise self._error_type("attested child directory descriptor is invalid")
            return duplicate, self._identity
        except BaseException:
            with suppress(OSError):
                os.close(duplicate)
            raise

    def __enter__(self) -> AttestedDirectory:
        self.checkpoint()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        _require_live(self)
        _close_registered(self)

    def __copy__(self) -> AttestedDirectory:
        _require_live(self)
        raise TypeError("AttestedDirectory instances cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> AttestedDirectory:
        _require_live(self)
        raise TypeError("AttestedDirectory instances cannot be deep-copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        _require_live(self)
        raise TypeError("AttestedDirectory instances cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _require_live(self)
        raise TypeError("AttestedDirectory instances cannot be serialized")

    def _ensure_open(self) -> None:
        _require_live(self)

    def _verified_proc_root(self) -> Path:
        self._ensure_open()
        path = self._proc_root / str(self._root_fd)
        try:
            descriptor = os.open(path, _PROC_DIRECTORY_FLAGS)
            info = os.fstat(descriptor)
            source = os.fstat(self._root_fd)
        except OSError as exc:
            raise self._error_type("compatible procfs descriptor paths are unavailable") from exc
        try:
            if (
                _identity(info) != self._identity
                or _identity(source) != self._identity
                or not stat.S_ISDIR(info.st_mode)
            ):
                raise self._error_type(
                    "procfs descriptor path does not retain the attested directory"
                )
        finally:
            os.close(descriptor)
        return path

    def checkpoint(self) -> None:
        _require_live(self)
        lexical_parent, lexical_identity = _absolute_directory(
            self._display_path.parent,
            error_type=self._error_type,
        )
        os.close(lexical_parent)
        try:
            parent = os.fstat(self._parent_fd)
            root = os.fstat(self._root_fd)
            entry = os.stat(
                self._display_path.name,
                dir_fd=self._parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PathCapabilityIdentityError("attested directory identity changed") from exc
        if (
            lexical_identity != self._parent_identity
            or _identity(parent) != self._parent_identity
            or _identity(root) != self._identity
            or _identity(entry) != self._identity
            or not stat.S_ISDIR(entry.st_mode)
            or entry.st_uid != os.geteuid()
            or stat.S_IMODE(entry.st_mode) != 0o700
        ):
            raise PathCapabilityIdentityError("attested directory identity changed")
        self._verified_proc_root()

    def _open_directory_parts(
        self,
        parts: tuple[str, ...],
    ) -> tuple[int, DirectoryIdentity]:
        self.checkpoint()
        descriptor = _duplicate(self._root_fd, error_type=self._error_type)
        try:
            for part in parts:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise self._error_type("attested target is not a directory")
            return descriptor, _identity(info)
        except BaseException as exc:
            with suppress(OSError):
                os.close(descriptor)
            if isinstance(exc, self._error_type):
                raise
            raise self._error_type("unsafe attested directory operation") from exc

    def open_directory(
        self,
        relative: str | PurePath = ".",
        *,
        create: bool = False,
    ) -> tuple[int, DirectoryIdentity]:
        parts = _parts(relative, error_type=self._error_type)
        self.checkpoint()
        if not create:
            return self._open_directory_parts(parts)
        descriptor = _duplicate(self._root_fd, error_type=self._error_type)
        try:
            for part in parts:
                try:
                    child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                except FileNotFoundError:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            return descriptor, _identity(info)
        except BaseException as exc:
            with suppress(OSError):
                os.close(descriptor)
            if isinstance(exc, self._error_type):
                raise
            raise self._error_type("unsafe attested directory creation") from exc

    def mkdir(self, relative: str | PurePath) -> DirectoryIdentity:
        parts = _parts(relative, error_type=self._error_type)
        if not parts:
            raise self._error_type("attested mkdir requires a non-root path")
        parent, _ = self._open_directory_parts(parts[:-1])
        try:
            os.mkdir(parts[-1], 0o700, dir_fd=parent)
            os.fsync(parent)
            child = os.open(parts[-1], _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                return _identity(os.fstat(child))
            finally:
                os.close(child)
        except FileExistsError as exc:
            raise self._error_type("attested directory already exists") from exc
        finally:
            os.close(parent)

    def subdirectory(
        self,
        relative: str | PurePath,
        *,
        create: bool = False,
    ) -> AttestedDirectory:
        parts = _parts(relative, error_type=self._error_type)
        if not parts:
            raise self._error_type("attested subdirectory requires a non-root path")
        parent, parent_identity = self._open_directory_parts(parts[:-1])
        try:
            if create:
                try:
                    os.mkdir(parts[-1], 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
            child = os.open(parts[-1], _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                info = os.fstat(child)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise self._error_type("attested subdirectory is not owner-private")
                self._minting_child = True
                try:
                    capability = _mint_attested_directory(
                        owner=self,
                        parent_fd=parent,
                        root_fd=child,
                        parent_identity=parent_identity,
                        identity=_identity(info),
                        display_path=self._display_path.joinpath(*parts),
                        proc_root=self._proc_root,
                        error_type=self._error_type,
                    )
                finally:
                    self._minting_child = False
                self._children.add(capability)
                return capability
            finally:
                os.close(child)
        except BaseException as exc:
            if isinstance(exc, self._error_type):
                raise
            raise self._error_type("unsafe attested subdirectory") from exc
        finally:
            os.close(parent)

    def detach_subdirectory(self, relative: str | PurePath) -> OwnedAttestedDirectory:
        """Detach a path-free independently-owned handle to one child inode."""

        parts = _parts(relative, error_type=self._error_type)
        if not parts:
            raise self._error_type("owned subdirectory requires a non-root path")
        descriptor, identity = self._open_directory_parts(parts)
        try:
            info = os.fstat(descriptor)
            if (
                _identity(info) != identity
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_nlink < 2
            ):
                raise self._error_type("owned subdirectory is not owner-private")
            self._minting_owned = True
            try:
                owned = _mint_owned_attested_directory(
                    owner=self,
                    descriptor=descriptor,
                    identity=identity,
                    error_type=self._error_type,
                )
            finally:
                self._minting_owned = False
            descriptor = -1
            return owned
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def proc_path(self, relative: str | PurePath = ".") -> Path:
        parts = _parts(relative, error_type=self._error_type)
        return self._verified_proc_root().joinpath(*parts)

    def sqlite_path(self, relative: str | PurePath) -> Path:
        parts = _parts(relative, error_type=self._error_type)
        if len(parts) != 1:
            raise self._error_type("attested SQLite path must be one normalized basename")
        return self.proc_path(PurePath(parts[0]))

    def open_file(
        self,
        relative: str | PurePath,
        flags: int,
        mode: int = 0o600,
    ) -> int:
        parts = _parts(relative, error_type=self._error_type)
        if not parts:
            raise self._error_type("attested file path is required")
        parent, _ = self._open_directory_parts(parts[:-1])
        try:
            descriptor = os.open(
                parts[-1],
                flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=parent,
            )
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                os.close(descriptor)
                raise self._error_type("attested file is not an owner-controlled regular file")
            return descriptor
        except BaseException as exc:
            if isinstance(exc, self._error_type):
                raise
            if isinstance(exc, OSError) and exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise self._error_type("unsafe attested file path") from exc
            raise
        finally:
            os.close(parent)

    def write_new(self, relative: str | PurePath, data: bytes, *, mode: int = 0o600) -> None:
        descriptor = self.open_file(relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise self._error_type("short write to attested file")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def read_bytes(self, relative: str | PurePath, *, max_size: int = 2 * 1024 * 1024) -> bytes:
        descriptor = self.open_file(relative, os.O_RDONLY)
        try:
            info = os.fstat(descriptor)
            if info.st_size < 0 or info.st_size > max_size:
                raise self._error_type("attested file exceeds its size limit")
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise self._error_type("attested file ended before its declared size")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise self._error_type("attested file changed while being read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def relative_from_display(self, path: str | os.PathLike[str]) -> PurePath:
        absolute = Path(os.path.abspath(os.fspath(path)))
        try:
            relative = absolute.relative_to(self._display_path)
        except ValueError as exc:
            raise self._error_type("path is outside the attested directory") from exc
        _parts(relative, error_type=self._error_type)
        return PurePath(relative)

    def open_directory_path(self, path: Path) -> tuple[int, DirectoryIdentity]:
        return self.open_directory(self.relative_from_display(path))

    def assert_path_identity(self, path: Path, expected: DirectoryIdentity) -> None:
        descriptor, actual = self.open_directory_path(path)
        try:
            if actual != expected:
                raise self._error_type("attested directory identity changed")
        finally:
            os.close(descriptor)


def require_attested_directory(
    value: object,
    *,
    error_type: ErrorType = PathCapabilityError,
) -> AttestedDirectory:
    """Return an exact registered live capability or fail at the boundary."""

    if type(value) is AttestedDirectory and getattr(value, "_closed", False):
        raise error_type("attested directory is closed")
    if type(value) is not AttestedDirectory or value not in _LIVE_INSTANCES:
        raise error_type("an exact registered live AttestedDirectory is required")
    return value


def _require_live(value: object) -> AttestedDirectory:
    error_type = getattr(value, "_error_type", PathCapabilityError)
    return require_attested_directory(value, error_type=error_type)


def _close_registered(value: AttestedDirectory) -> None:
    if value not in _LIVE_INSTANCES:
        return
    _LIVE_INSTANCES.discard(value)
    value._closed = True
    for child in tuple(value._children):
        _close_registered(child)
    value._children.clear()
    value._finalizer()


def require_owned_attested_directory(
    value: object,
    *,
    error_type: ErrorType = PathCapabilityError,
) -> OwnedAttestedDirectory:
    with _OWNED_LOCK:
        if type(value) is not OwnedAttestedDirectory:
            raise error_type("an exact registered OwnedAttestedDirectory is required")
        record = _OWNED_INSTANCES.get(value)
        if record is None or record.state == "CLOSED" or record.resources.closed:
            raise error_type("owned attested directory is closed or unregistered")
        return value


def _duplicate_owned_attested_directory(
    value: object,
    *,
    error_type: ErrorType = PathCapabilityError,
) -> tuple[int, DirectoryIdentity]:
    with _OWNED_LOCK:
        owned = require_owned_attested_directory(value, error_type=error_type)
        record = _OWNED_INSTANCES[owned]
        descriptor = _duplicate(record.resources.descriptors[0], error_type=error_type)
        try:
            info = os.fstat(descriptor)
            if (
                _identity(info) != record.identity
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_nlink < 2
            ):
                raise error_type("owned directory descriptor identity is invalid")
            return descriptor, record.identity
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise


def _claim_owned_attested_directories(
    values: tuple[OwnedAttestedDirectory, ...],
    *,
    error_type: ErrorType,
) -> None:
    with _OWNED_LOCK:
        if len({id(value) for value in values}) != len(values):
            raise error_type("owned proof resources must be distinct")
        records: list[_OwnedDirectoryRecord] = []
        for value in values:
            owned = require_owned_attested_directory(value, error_type=error_type)
            record = _OWNED_INSTANCES[owned]
            if record.state != "AVAILABLE":
                raise error_type("owned proof resource was already claimed")
            records.append(record)
        for record in records:
            record.state = "CLAIMED"


def _close_owned_attested_directory(value: object) -> None:
    with _OWNED_LOCK:
        if type(value) is not OwnedAttestedDirectory:
            raise PathCapabilityError("an exact registered OwnedAttestedDirectory is required")
        record = _OWNED_INSTANCES.get(value)
        if record is None or record.state == "CLOSED":
            return
        record.state = "CLOSED"
        record.finalizer()


def _mint_owned_attested_directory(
    *,
    owner: AttestedDirectory,
    descriptor: int,
    identity: DirectoryIdentity,
    error_type: ErrorType,
) -> OwnedAttestedDirectory:
    parent = require_attested_directory(owner, error_type=error_type)
    if parent._minting_owned is not True:
        raise TypeError("owned directory minting requires active descriptor detachment")
    info = os.fstat(descriptor)
    if _identity(info) != identity or os.get_inheritable(descriptor):
        raise error_type("owned directory descriptor identity is invalid")
    instance = object.__new__(OwnedAttestedDirectory)
    resources = _DescriptorFinalizerState((descriptor,))
    cleanup = finalize(instance, _finalize_descriptors, resources)
    record = _OwnedDirectoryRecord(identity, error_type, resources, cleanup)
    with _OWNED_LOCK:
        _OWNED_INSTANCES[instance] = record
    return instance


def _mint_attested_directory(
    *,
    owner: object,
    parent_fd: int,
    root_fd: int,
    parent_identity: DirectoryIdentity,
    identity: DirectoryIdentity,
    display_path: Path,
    proc_root: Path,
    error_type: ErrorType,
) -> AttestedDirectory:
    allowed = False
    if type(owner) is AttestedDirectory:
        parent = require_attested_directory(owner)
        allowed = parent._minting_child is True
    else:
        from gove_zone.proof_pack import PinnedOutputRoot

        allowed = (
            type(owner) is PinnedOutputRoot and getattr(owner, "_attest_in_progress", False) is True
        )
    if not allowed:
        raise TypeError("AttestedDirectory minting requires an active attest operation")

    instance = object.__new__(AttestedDirectory)
    instance._parent_fd = _duplicate(parent_fd, error_type=error_type)
    try:
        instance._root_fd = _duplicate(root_fd, error_type=error_type)
    except BaseException:
        os.close(instance._parent_fd)
        raise
    instance._parent_identity = parent_identity
    instance._identity = identity
    instance._display_path = Path(display_path)
    instance._proc_root = Path(proc_root)
    instance._error_type = error_type
    instance._closed = False
    instance._children = WeakSet()
    instance._minting_child = False
    instance._minting_owned = False
    _LIVE_INSTANCES.add(instance)
    resources = _DescriptorFinalizerState((instance._root_fd, instance._parent_fd))
    instance._finalizer = finalize(instance, _finalize_descriptors, resources)
    try:
        instance.checkpoint()
    except BaseException:
        _close_registered(instance)
        raise
    return instance


_ARTIFACT_FILE_FLAGS: Final = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_ARTIFACT_CHUNK_BYTES: Final = 1 << 20
DEFAULT_MAX_ARTIFACT_BYTES: Final = 64 * 1024 * 1024

_SNAPSHOT_LOCK = RLock()
_SNAPSHOT_INSTANCES: WeakSet[ImmutableArtifactSnapshot] = WeakSet()
_SNAPSHOT_MINTING = False
_LEASE_MINTING = False


class ImmutableArtifactSnapshotError(PathCapabilityError):
    """An immutable artifact snapshot could not be captured or proven."""

    reason_code: Final = "IMMUTABLE_ARTIFACT_SNAPSHOT_INVALID"


class ArtifactCaptureLease:
    """A non-forgeable, single-release lease binding one snapshot to its capturer.

    A lease is minted only alongside the snapshot it belongs to, by the same
    kernel-owned capture that reserved the aggregate budget for that snapshot's
    exact size *before* the bytes were materialized. It carries an opaque
    ``owner`` token (identity of the capturing executor) and the reserved
    ``amount``. The snapshot releases the reservation exactly once when it is
    closed; a lease can never be released twice or forged by an unrelated
    caller, so the aggregate budget tracks ACGS-owned snapshot lifetime rather
    than a per-adapter window that ended before the bytes were freed.
    """

    __slots__ = ("__weakref__", "_amount", "_lock", "_owner", "_release", "_released")

    _amount: int
    _lock: RLock
    _owner: object
    _release: Any
    _released: bool

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ArtifactCaptureLease can only be minted alongside a leased capture")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("ArtifactCaptureLease cannot be subclassed")

    @property
    def owner(self) -> object:
        return self._owner

    @property
    def amount(self) -> int:
        return self._amount

    @property
    def released(self) -> bool:
        with self._lock:
            return self._released

    def release(self) -> None:
        """Release the reserved bytes exactly once; a double release is an error."""

        with self._lock:
            if self._released:
                raise ImmutableArtifactSnapshotError("artifact capture lease released twice")
            self._released = True
        self._release(self._amount)

    def __copy__(self) -> ArtifactCaptureLease:
        raise TypeError("ArtifactCaptureLease instances cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> ArtifactCaptureLease:
        raise TypeError("ArtifactCaptureLease instances cannot be deep-copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("ArtifactCaptureLease instances cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("ArtifactCaptureLease instances cannot be serialized")


def _mint_capture_lease(*, owner: object, amount: int, release: Any) -> ArtifactCaptureLease:
    with _SNAPSHOT_LOCK:
        if _LEASE_MINTING is not True:
            raise TypeError("capture lease minting requires an active leased capture")
        instance = object.__new__(ArtifactCaptureLease)
        instance._owner = owner
        instance._amount = amount
        instance._release = release
        instance._released = False
        instance._lock = RLock()
    return instance


class ImmutableArtifactSnapshot:
    """A kernel-minted immutable capture of one regular file's exact bytes.

    The captured chunks are the entire proof. The originating pathname is
    deliberately not retained as a re-openable capability and no descriptor is
    held open, so nothing a later writer does to the source can change what a
    consumer of this snapshot reads. A mutable lexical path is never proof.

    Public construction, subclassing, copying, and serialization are rejected,
    and every accessor re-checks the exact instance against the live registry.
    """

    __slots__ = (
        "__weakref__",
        "_closed",
        "_data",
        "_digest",
        "_finalizer",
        "_identity",
        "_lease",
        "_size",
        "_source_name",
    )

    _closed: bool
    _data: bytes
    _digest: str
    _finalizer: finalize[[], ImmutableArtifactSnapshot] | None
    _identity: DirectoryIdentity
    _lease: ArtifactCaptureLease | None
    _size: int
    _source_name: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "ImmutableArtifactSnapshot can only be minted by capture_immutable_artifact"
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("ImmutableArtifactSnapshot cannot be subclassed")

    @property
    def digest(self) -> str:
        """Return the digest recorded at capture time."""

        require_immutable_artifact_snapshot(self)
        return self._digest

    @property
    def size(self) -> int:
        require_immutable_artifact_snapshot(self)
        return self._size

    @property
    def source_name(self) -> str:
        """Return the source basename only; this can never be re-opened."""

        require_immutable_artifact_snapshot(self)
        return self._source_name

    @property
    def identity(self) -> DirectoryIdentity:
        require_immutable_artifact_snapshot(self)
        return self._identity

    def bytes(self) -> bytes:
        """Return the exact captured bytes as one immutable object.

        The snapshot stores a single immutable ``bytes`` object minted once at
        capture time; this returns that exact object on every call while the
        snapshot is live, so there is no duplicate full-size allocation and no
        per-access join. ``bytes`` is immutable, so sharing the object is safe.

        Limitation: this bounds only the ACGS-owned snapshot's allocation and
        lifetime. Once :meth:`close` runs (deterministically after the adapter,
        a refusal, or an UNKNOWN outcome for kernel-created snapshots), the
        internal reference is dropped and this raises. A copy an adapter already
        made of these bytes is outside this boundary and is not tracked here.
        """

        require_immutable_artifact_snapshot(self)
        return self._data

    def content_digest(self) -> str:
        """Recompute the digest from the captured bytes.

        The recorded :attr:`digest` is never authoritative at a gate: this
        re-derives the digest from the content a consumer would actually read,
        so the compared value and the deployed value cannot diverge.
        """

        require_immutable_artifact_snapshot(self)
        return hashlib.sha256(self._data).hexdigest()

    def close(self) -> None:
        """Drop the captured bytes and release the capture lease exactly once.

        Closing is idempotent at the snapshot surface: it may be called any
        number of times, but the bound :class:`ArtifactCaptureLease` (if any) is
        released on the FIRST close only, so the aggregate capture budget is
        never double-released.

        The lease is also released if the last reference to a leased snapshot is
        collected without an explicit close (a pre-minted snapshot abandoned by a
        caller). A GC finalizer bound to this instance performs that release, so
        an abandoned capture cannot permanently consume the executor's aggregate
        budget. Explicit close releases immediately and detaches the finalizer,
        and the finalizer runs at most once, so GC can never double-release.
        """

        with _SNAPSHOT_LOCK:
            if type(self) is not ImmutableArtifactSnapshot:
                raise ImmutableArtifactSnapshotError(
                    "an exact ImmutableArtifactSnapshot is required"
                )
            already_closed = self._closed
            _SNAPSHOT_INSTANCES.discard(self)
            self._closed = True
            self._data = b""
            lease = self._lease
            finalizer = self._finalizer
        if already_closed:
            return
        # Detach the GC finalizer before releasing so the collected-snapshot path
        # can never fire a second release; the detach is atomic and the snapshot
        # is alive for the duration of this call, so GC cannot race it here.
        if finalizer is not None:
            finalizer.detach()
        if lease is not None:
            lease.release()

    def __enter__(self) -> ImmutableArtifactSnapshot:
        require_immutable_artifact_snapshot(self)
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __copy__(self) -> ImmutableArtifactSnapshot:
        raise TypeError("ImmutableArtifactSnapshot instances cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> ImmutableArtifactSnapshot:
        raise TypeError("ImmutableArtifactSnapshot instances cannot be deep-copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("ImmutableArtifactSnapshot instances cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("ImmutableArtifactSnapshot instances cannot be serialized")


def require_immutable_artifact_snapshot(
    value: object,
    *,
    error_type: ErrorType = ImmutableArtifactSnapshotError,
) -> ImmutableArtifactSnapshot:
    """Return an exact registered live snapshot or fail closed at the boundary.

    The exact-type check runs first and no user code is invoked: a subclass, a
    look-alike, a proxy, and a structurally identical attestation (for example
    :class:`~gove_zone.authorization.PolicyArtifactAttestation`, which also
    carries a ``digest``) are all rejected before any attribute is read.
    """

    if type(value) is not ImmutableArtifactSnapshot:
        raise error_type("an exact registered live ImmutableArtifactSnapshot is required")
    with _SNAPSHOT_LOCK:
        if value._closed or value not in _SNAPSHOT_INSTANCES:
            raise error_type("immutable artifact snapshot is closed or unregistered")
    return value


def require_artifact_capture_lease(
    value: object,
    *,
    error_type: ErrorType = ImmutableArtifactSnapshotError,
) -> ArtifactCaptureLease:
    """Return an exact capture lease or fail closed at the boundary."""

    if type(value) is not ArtifactCaptureLease:
        raise error_type("an exact ArtifactCaptureLease is required")
    return value


def artifact_snapshot_lease(
    snapshot: object,
    *,
    error_type: ErrorType = ImmutableArtifactSnapshotError,
) -> ArtifactCaptureLease | None:
    """Return the capture lease bound to a live snapshot, or ``None`` if unleased.

    A module-level :func:`capture_immutable_artifact` snapshot is unleased
    (``None``); only a snapshot captured through an owning executor's leased
    factory carries a lease whose ``owner`` identifies that executor.
    """

    proven = require_immutable_artifact_snapshot(snapshot, error_type=error_type)
    return proven._lease


def _mint_immutable_artifact_snapshot(
    *,
    data: bytes,
    digest: str,
    size: int,
    source_name: str,
    identity: DirectoryIdentity,
    error_type: ErrorType,
) -> ImmutableArtifactSnapshot:
    with _SNAPSHOT_LOCK:
        if _SNAPSHOT_MINTING is not True:
            raise TypeError("snapshot minting requires an active secure capture")
        instance = object.__new__(ImmutableArtifactSnapshot)
        instance._data = data
        instance._digest = digest
        instance._size = size
        instance._source_name = source_name
        instance._identity = identity
        instance._closed = False
        instance._lease = None
        instance._finalizer = None
        _SNAPSHOT_INSTANCES.add(instance)
    if instance.content_digest() != digest:
        instance.close()
        raise error_type("captured artifact digest is inconsistent with its bytes")
    return instance


def _stable_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def capture_immutable_artifact(
    source: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    error_type: ErrorType = ImmutableArtifactSnapshotError,
    owner: object | None = None,
    acquire: Any | None = None,
    release: Any | None = None,
) -> ImmutableArtifactSnapshot:
    """Capture one regular file's exact bytes into an immutable snapshot.

    This is the only mint path for :class:`ImmutableArtifactSnapshot`. Every
    directory component is opened ``O_NOFOLLOW`` and the file itself is opened
    ``O_RDONLY|O_CLOEXEC|O_NOFOLLOW``, so a symlinked component or a symlinked
    target fails closed rather than being followed. The open file must be a
    regular file with exactly one link (a hardlinked file is refused: a second
    name for the same inode is a second writer), must fit within *max_bytes*,
    and must present an identical ``fstat`` identity before and after the read.

    When ``owner`` is supplied the capture is *leased*: the file's exact size is
    charged to the owning executor's aggregate budget via ``acquire(size)``
    BEFORE any bytes are materialized (a refusal raised by ``acquire`` aborts
    the capture with no allocation), and the returned snapshot carries an
    :class:`ArtifactCaptureLease` whose ``owner`` identifies the capturer and
    which releases the reservation via ``release(size)`` exactly once when the
    snapshot is closed. An unleased (module-level) capture reserves nothing and
    carries no lease.
    """

    if type(max_bytes) is not int or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise error_type("max_bytes must be a positive integer")
    leased = owner is not None
    if leased and (acquire is None or release is None):
        raise error_type("a leased capture requires both acquire and release callbacks")
    raw = os.fspath(source)
    if not raw or "\0" in raw:
        raise error_type("artifact path is empty or contains NUL bytes")
    absolute = Path(os.path.abspath(raw))
    if not absolute.is_absolute() or not absolute.name:
        raise error_type("artifact path must identify a file")
    if is_descriptor_alias_path(absolute):
        raise error_type("descriptor alias paths are not accepted as artifact sources")

    parent = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        for part in absolute.parent.parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(absolute.name, _ARTIFACT_FILE_FLAGS, dir_fd=parent)
    except BaseException as exc:
        with suppress(OSError):
            os.close(parent)
        if isinstance(exc, error_type):
            raise
        raise error_type("artifact source is unsafe, missing, or unavailable") from exc
    else:
        os.close(parent)

    acquired_amount = 0
    try:
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise error_type("artifact source must be a regular file")
            if before.st_nlink != 1:
                raise error_type("artifact source must not be hardlinked")
            size = before.st_size
            if size < 0 or size > max_bytes:
                raise error_type("artifact source exceeds its capture size limit")

            # Aggregate budget is charged for the exact size BEFORE any bytes
            # are read into memory. A refusal here (over budget) propagates
            # without reading a single byte, so an over-budget capture never
            # amplifies memory. A zero-byte artifact reserves nothing.
            if leased and size > 0:
                if acquire is None:  # unreachable: a leased capture always carries acquire
                    raise error_type("a leased capture requires both acquire and release callbacks")
                acquire(size)
                acquired_amount = size

            chunks: list[bytes] = []
            remaining = size
            while remaining:
                chunk = os.read(descriptor, min(remaining, _ARTIFACT_CHUNK_BYTES))
                if not chunk:
                    raise error_type("artifact source ended before its declared size")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise error_type("artifact source grew while being captured")

            after = os.fstat(descriptor)
            if _stable_identity(after) != _stable_identity(before) or after.st_nlink != 1:
                raise error_type("artifact source changed while being captured")
        finally:
            with suppress(OSError):
                os.close(descriptor)

        data = b"".join(chunks)
        digest = hashlib.sha256(data).hexdigest()

        global _SNAPSHOT_MINTING, _LEASE_MINTING
        with _SNAPSHOT_LOCK:
            _SNAPSHOT_MINTING = True
            try:
                snapshot = _mint_immutable_artifact_snapshot(
                    data=data,
                    digest=digest,
                    size=size,
                    source_name=absolute.name,
                    identity=_identity(before),
                    error_type=error_type,
                )
            finally:
                _SNAPSHOT_MINTING = False
        if leased:
            with _SNAPSHOT_LOCK:
                _LEASE_MINTING = True
                try:
                    lease = _mint_capture_lease(
                        owner=owner,
                        amount=acquired_amount,
                        release=release,
                    )
                finally:
                    _LEASE_MINTING = False
                snapshot._lease = lease
                # Bind an exactly-once GC finalizer so an abandoned leased
                # snapshot releases its reservation when its last reference is
                # collected. The callback is the lease's own release bound method:
                # it retains the lease (never the snapshot), so it creates no
                # reference cycle back to the snapshot and cannot keep it alive.
                snapshot._finalizer = finalize(snapshot, lease.release)
        return snapshot
    except BaseException:
        # The reservation is owned by the snapshot's lease only once the snapshot
        # is fully minted and returned. Any failure after acquisition but before
        # that hand-off releases the reserved bytes here, so a capture that
        # reserved budget and then failed never leaks the reservation.
        if acquired_amount and release is not None:
            release(acquired_amount)
        raise


__all__ = [
    "DEFAULT_MAX_ARTIFACT_BYTES",
    "ArtifactCaptureLease",
    "AttestedDirectory",
    "DirectoryIdentity",
    "ImmutableArtifactSnapshot",
    "ImmutableArtifactSnapshotError",
    "PathCapabilityError",
    "PathCapabilityIdentityError",
    "artifact_snapshot_lease",
    "capture_immutable_artifact",
    "is_descriptor_alias_path",
    "is_proc_fd_path",
    "require_artifact_capture_lease",
    "require_attested_directory",
    "require_immutable_artifact_snapshot",
    "validate_direct_file_path",
]
