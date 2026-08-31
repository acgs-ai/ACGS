import hashlib
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from uuid import UUID


class ObjectStorage(Protocol):
    def write(self, key: str, data: bytes) -> "StoredObject": ...
    def write_partial(self, key: str, data: bytes, expected_sha256: str) -> "StoredObject": ...
    def promote(self, key: str, expected_sha256: str, expected_size: int) -> "StoredObject": ...
    def inspect(
        self, key: str, expected_sha256: str, expected_size: int
    ) -> Literal["missing", "partial", "final", "mismatch"]: ...
    def read(self, key: str, expected_sha256: str | None = None) -> bytes: ...
    def delete(self, key: str) -> None: ...
    def delete_source(self, owner_id: UUID, workspace_id: UUID, source_id: UUID) -> None: ...


class S3CompatibleStorage(ObjectStorage, Protocol):
    """Production boundary; an SDK-backed implementation is intentionally deferred."""


class StoredObjectMismatch(ValueError):
    pass


@dataclass(frozen=True)
class StoredObject:
    key: str
    size: int
    sha256: str


def sanitize_filename(value: str | None) -> str | None:
    if value is None:
        return None
    name = Path(value).name.replace("\x00", "")
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return cleaned[:200] or "upload"


def object_key(owner_id: UUID, workspace_id: UUID, source_id: UUID) -> str:
    return f"{owner_id.hex}/{workspace_id.hex}/{source_id.hex}/original"


def job_object_key(owner_id: UUID, workspace_id: UUID, source_id: UUID, job_id: UUID) -> str:
    return f"{owner_id.hex}/{workspace_id.hex}/{source_id.hex}/{job_id.hex}"


class FilesystemStorage:
    _KEY = re.compile(r"[0-9a-f]{32}/[0-9a-f]{32}/[0-9a-f]{32}/(?:original|[0-9a-f]{32})")

    def __init__(self, root: Path, max_bytes: int) -> None:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = root.resolve(strict=True)
        self.max_bytes = max_bytes
        self._root_fd: int | None = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def __del__(self) -> None:
        if self._root_fd is not None:
            with suppress(OSError):
                os.close(self._root_fd)
            self._root_fd = None

    @classmethod
    def _parts(cls, key: str) -> tuple[str, str, str, str]:
        if not cls._KEY.fullmatch(key):
            raise ValueError("invalid object key")
        owner, workspace, source, final = key.split("/")
        return owner, workspace, source, final

    def _directory_fd(self, key: str, *, create: bool) -> tuple[int, str]:
        if self._root_fd is None:
            raise RuntimeError("storage is closed")
        owner, workspace, source, final = self._parts(key)
        current = os.dup(self._root_fd)
        try:
            for component in (owner, workspace, source):
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current)
                        os.fsync(current)
                    except FileExistsError:
                        pass
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                os.close(current)
                current = child
            return current, final
        except Exception:
            os.close(current)
            raise

    def write(self, key: str, data: bytes) -> StoredObject:
        expected = hashlib.sha256(data).hexdigest()
        self._validate_expected(data, expected)
        if self.inspect(key, expected, len(data)) != "missing":
            raise FileExistsError(key)
        self.write_partial(key, data, expected)
        return self.promote(key, expected, len(data))

    def write_partial(self, key: str, data: bytes, expected_sha256: str) -> StoredObject:
        self._validate_expected(data, expected_sha256)
        directory_fd, final = self._directory_fd(key, create=True)
        partial = f".{final}.partial"
        try:
            try:
                existing = self._verified_object(
                    directory_fd, final, key, expected_sha256, len(data)
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                return existing
            for _ in range(3):
                try:
                    fd = os.open(
                        partial,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory_fd,
                    )
                    break
                except FileExistsError:
                    try:
                        return self._verified_object(
                            directory_fd, partial, key, expected_sha256, len(data)
                        )
                    except FileNotFoundError:
                        continue
                    except StoredObjectMismatch:
                        self._unlink_regular_file(directory_fd, partial)
                        os.fsync(directory_fd)
            else:
                raise StoredObjectMismatch("partial object could not be safely replaced")
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory_fd)
            return self._verified_object(directory_fd, partial, key, expected_sha256, len(data))
        finally:
            os.close(directory_fd)

    def promote(self, key: str, expected_sha256: str, expected_size: int) -> StoredObject:
        directory_fd, final = self._directory_fd(key, create=False)
        partial = f".{final}.partial"
        try:
            try:
                existing = self._verified_object(
                    directory_fd, final, key, expected_sha256, expected_size
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                self._unlink_if_exists(directory_fd, partial)
                os.fsync(directory_fd)
                return existing
            self._verified_object(directory_fd, partial, key, expected_sha256, expected_size)
            try:
                os.link(
                    partial,
                    final,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                existing = self._verified_object(
                    directory_fd, final, key, expected_sha256, expected_size
                )
                self._unlink_if_exists(directory_fd, partial)
                os.fsync(directory_fd)
                return existing
            os.fsync(directory_fd)
            os.unlink(partial, dir_fd=directory_fd)
            os.fsync(directory_fd)
            return self._verified_object(directory_fd, final, key, expected_sha256, expected_size)
        finally:
            os.close(directory_fd)

    def inspect(
        self, key: str, expected_sha256: str, expected_size: int
    ) -> Literal["missing", "partial", "final", "mismatch"]:
        try:
            directory_fd, final = self._directory_fd(key, create=False)
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "mismatch"
        try:
            try:
                self._verified_object(directory_fd, final, key, expected_sha256, expected_size)
                return "final"
            except FileNotFoundError:
                pass
            except StoredObjectMismatch:
                return "mismatch"
            try:
                self._verified_object(
                    directory_fd, f".{final}.partial", key, expected_sha256, expected_size
                )
                return "partial"
            except FileNotFoundError:
                return "missing"
            except StoredObjectMismatch:
                return "mismatch"
        finally:
            os.close(directory_fd)

    def read(self, key: str, expected_sha256: str | None = None) -> bytes:
        directory_fd, final = self._directory_fd(key, create=False)
        try:
            data = self._read_file(directory_fd, final)
        finally:
            os.close(directory_fd)
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise StoredObjectMismatch("stored object integrity verification failed")
        return data

    def delete(self, key: str) -> None:
        try:
            directory_fd, final = self._directory_fd(key, create=False)
        except FileNotFoundError:
            return
        try:
            self._unlink_if_exists(directory_fd, final)
            self._unlink_if_exists(directory_fd, f".{final}.partial")
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def delete_source(self, owner_id: UUID, workspace_id: UUID, source_id: UUID) -> None:
        prefix = f"{owner_id.hex}/{workspace_id.hex}/{source_id.hex}"
        if self._root_fd is None:
            raise RuntimeError("storage is closed")
        current = os.dup(self._root_fd)
        parents: list[tuple[int, str]] = []
        try:
            for component in prefix.split("/"):
                parents.append((os.dup(current), component))
                try:
                    child = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=current,
                    )
                except FileNotFoundError:
                    return
                os.close(current)
                current = child
            for name in os.listdir(current):
                self._unlink_regular_file(current, name)
            os.fsync(current)
            for parent_fd, component in reversed(parents):
                with suppress(OSError):
                    os.rmdir(component, dir_fd=parent_fd)
                    os.fsync(parent_fd)
        finally:
            os.close(current)
            for parent_fd, _ in parents:
                os.close(parent_fd)

    def _verified_object(
        self, directory_fd: int, name: str, key: str, expected_sha256: str, expected_size: int
    ) -> StoredObject:
        data = self._read_file(directory_fd, name)
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != expected_size or digest != expected_sha256:
            raise StoredObjectMismatch("stored object integrity verification failed")
        return StoredObject(key, len(data), digest)

    def _read_file(self, directory_fd: int, name: str) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_bytes:
                raise StoredObjectMismatch("stored object is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = self.max_bytes + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > self.max_bytes:
                raise StoredObjectMismatch("stored object exceeds configured byte limit")
            return data
        finally:
            os.close(fd)

    def _validate_expected(self, data: bytes, expected_sha256: str) -> None:
        if len(data) > self.max_bytes:
            raise ValueError("object exceeds configured byte limit")
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise StoredObjectMismatch("object hash does not match its lineage")

    @staticmethod
    def _unlink_if_exists(directory_fd: int, name: str) -> None:
        with suppress(FileNotFoundError):
            os.unlink(name, dir_fd=directory_fd)

    @staticmethod
    def _unlink_regular_file(directory_fd: int, name: str) -> None:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        except FileNotFoundError:
            return
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StoredObjectMismatch("partial object is not a regular file")
        finally:
            os.close(fd)
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            return
