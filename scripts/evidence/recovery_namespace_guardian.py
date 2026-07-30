"""Ephemeral, attempt-bound recovery directory isolated in Linux namespaces.

Protection begins at a dedicated, already-nondumpable broker boundary.  Same-UID
injection before that hardening boundary, host root, ``CAP_SYS_PTRACE``, host
snapshot rollback, and recovery outside the private tmpfs are excluded.  Local
terminal success also does not prove cross-process consumer quiescence; such FD
delegation is prohibited here and requires an integration-level ownership gate.
The unprivileged user namespace is owned by the ambient original UID: observed
same-UID denial is host/LSM-policy evidence, not a portable isolation guarantee,
and ambient namespace-owner authority is explicitly outside this boundary.
The guardian-local export returns an anonymous sealed memfd. A sealed memfd proves
bounded process-lifetime immutability, integrity, and availability while the
descriptor is held. It does not prove confidentiality, crash durability, same-UID secrecy,
restart garbage collection, global FD quiescence, broker/KMS custody, host-root
or ptrace resistance, P3C/P3D readiness, or cross-platform behavior.
"""

from __future__ import annotations

import array
import base64
import binascii
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import resource
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Final, NoReturn

SCHEMA: Final = "acgs.recovery-namespace-guardian.v1"
INTERNAL_MOUNT: Final = "/tmp"
INTERNAL_ROOT: Final = "/tmp/acgs-recovery-root"
MAX_PACKET_BYTES: Final = 64 * 1024
MAX_QUOTA_BYTES: Final = 16 * 1024 * 1024
TMPFS_INODE_LIMIT: Final = 64
EXPORT_SCHEMA: Final = "acgs.recovery-namespace-export.v1"
MFD_CLOEXEC: Final = 0x0001
MFD_ALLOW_SEALING: Final = 0x0002
F_ADD_SEALS: Final = 1033
F_GET_SEALS: Final = 1034
F_SEAL_SEAL: Final = 0x0001
F_SEAL_SHRINK: Final = 0x0002
F_SEAL_GROW: Final = 0x0004
F_SEAL_WRITE: Final = 0x0008
EXPORT_SEALS: Final = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL
SAFE_NAME_BYTES: Final = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)
MAX_EXPORT_PATH_BYTES: Final = 4096
BROKER_SCHEMA: Final = "acgs.recovery-namespace-export-broker.v1"
BROKER_FD: Final = 9
BROKER_MAIN_ARG: Final = "--acgs-recovery-export-broker-main"
COURIER_MAIN_ARG: Final = "--acgs-recovery-export-courier-main"

CLONE_NEWNS: Final = 0x00020000
CLONE_NEWUSER: Final = 0x10000000
MS_NOSUID: Final = 2
MS_NODEV: Final = 4
MS_NOEXEC: Final = 8
MS_REC: Final = 16384
MS_PRIVATE: Final = 1 << 18
PR_SET_DUMPABLE: Final = 4
PR_GET_DUMPABLE: Final = 3
PR_SET_NO_NEW_PRIVS: Final = 38
PR_GET_NO_NEW_PRIVS: Final = 39
PR_SET_PDEATHSIG: Final = 1
PR_GET_PDEATHSIG: Final = 2
PR_SET_SECUREBITS: Final = 28
PR_GET_SECUREBITS: Final = 27
PR_CAPBSET_DROP: Final = 24
PR_CAP_AMBIENT: Final = 47
PR_CAP_AMBIENT_CLEAR_ALL: Final = 4
PTRACE_TRACEME: Final = 0
PTRACE_DETACH: Final = 17
SECUREBITS_LOCKED_ZERO_CAPS: Final = 239
NSFS_MAGIC: Final = 0x6E736673
NS_GET_NSTYPE: Final = 0xB703

_HANDSHAKE_KEYS: Final = frozenset(
    {
        "schema",
        "type",
        "attempt_id",
        "nonce",
        "epoch",
        "child_pid",
        "socket_peercred",
        "message_peercred",
        "namespaces",
        "parent_namespaces",
        "mount",
        "security",
        "fd_inventory",
        "recovery_root",
        "namespace_handle",
    }
)
_BINDING_KEYS: Final = frozenset({"schema", "type", "attempt_id", "nonce", "epoch", "request_id"})
_EXPORT_RESPONSE_KEYS: Final = _BINDING_KEYS | frozenset(
    {
        "export_id",
        "source_root",
        "byte_count",
        "inode_count",
        "entry_count",
        "content_digest",
        "capsule_digest",
        "capsule_size",
        "seals",
        "truth_boundary",
    }
)
_EXPORT_RELEASE_KEYS: Final = _BINDING_KEYS | frozenset({"export_id", "capsule_digest"})
_BROKER_BINDING_KEYS: Final = frozenset({"schema", "type", "attempt_id", "nonce", "request_id"})
_BROKER_ARTIFACT_KEYS: Final = _BROKER_BINDING_KEYS | frozenset(
    {
        "commit",
        "artifact",
        "epoch",
        "capsule_nonce",
        "capsule_digest",
        "capsule_size",
        "content_digest",
        "seals",
        "truth_boundary",
    }
)
_LOWER_HEX: Final = frozenset("0123456789abcdef")
_TRUTH_BOUNDARY: Final = (
    "sealed memfd proves bounded process-lifetime immutability, integrity, and availability "
    "while the file descriptor is held; it does not prove confidentiality, crash durability, "
    "same-UID secrecy, restart garbage collection, global FD quiescence, broker/KMS custody, "
    "host-root or ptrace resistance, P3C/P3D readiness, or cross-platform behavior"
)
_FAULTS: Final = frozenset(
    {
        "handshake_extra_key",
        "handshake_regular_fd",
        "handshake_two_fds",
        "lease_regular_fd",
        "lease_two_fds",
        "export_bad_digest",
        "export_extra_key",
        "export_regular_fd",
        "export_two_fds",
        "export_race_after_snapshot",
        "broker_die_before_receipt",
        "broker_detached_memfd_seal_failure",
        "broker_exit_42_after_artifact",
        "broker_artifact_bad_capsule_digest",
        "broker_artifact_bool_content_digest",
        "broker_artifact_bad_capsule_schema",
        "broker_artifact_escape_path",
        "broker_artifact_string_mode",
        "broker_artifact_bad_file_hash",
        "broker_artifact_bad_base64",
        "courier_exit_42_after_artifact",
        "pidfd_open_failure",
        "die_before_finalize",
        "die_after_release",
        "die_after_export_send",
        "die_after_unmount",
        "mapping_failure",
    }
)
_SYSCALL_NUMBERS: Final = {
    "x86_64": {
        "memfd_create": 319,
        "pidfd_send_signal": 424,
        "pidfd_open": 434,
        "pidfd_getfd": 438,
    },
    "aarch64": {
        "memfd_create": 279,
        "pidfd_send_signal": 424,
        "pidfd_open": 434,
        "pidfd_getfd": 438,
    },
}

_libc = ctypes.CDLL(None, use_errno=True)
_libc.unshare.argtypes = [ctypes.c_int]
_libc.unshare.restype = ctypes.c_int
_libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_char_p,
]
_libc.mount.restype = ctypes.c_int
_libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_libc.umount2.restype = ctypes.c_int
_libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_libc.prctl.restype = ctypes.c_int
_libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
_libc.ptrace.restype = ctypes.c_long
_libc.setfsuid.argtypes = [ctypes.c_uint]
_libc.setfsuid.restype = ctypes.c_int
_libc.setfsgid.argtypes = [ctypes.c_uint]
_libc.setfsgid.restype = ctypes.c_int


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


class _StatFs(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    ]


class GuardianError(RuntimeError):
    """Base class for fail-closed guardian errors."""


class EssentialPrimitiveUnavailable(GuardianError):
    """A required Linux primitive was unavailable; no fallback was used."""


class ProtocolRejected(GuardianError):
    """A peer rejected a request or violated the exact protocol."""


class LiveLeaseError(GuardianError):
    """Finalize was refused because a directory lease remains live."""


class UnknownOutcomeError(GuardianError):
    """The control channel or child ended without terminal success proof."""


class TerminalStateError(GuardianError):
    """A command was attempted after the attempt became terminal."""


def _raise_errno(operation: str) -> NoReturn:
    error_number = ctypes.get_errno()
    raise OSError(error_number, f"{operation}: {os.strerror(error_number)}")


def _syscall_number(name: str) -> int:
    machine_numbers = _SYSCALL_NUMBERS.get(os.uname().machine)
    if machine_numbers is None or name not in machine_numbers:
        raise EssentialPrimitiveUnavailable(f"{name} syscall number is unavailable")
    return machine_numbers[name]


def _pidfd_open(pid: int) -> int:
    result = _libc.syscall(_syscall_number("pidfd_open"), pid, 0)
    if result < 0:
        _raise_errno("pidfd_open")
    return int(result)


def pidfd_send_signal(pidfd: int, signum: int) -> None:
    """Send a signal through the retained pidfd using the Linux syscall."""

    result = _libc.syscall(_syscall_number("pidfd_send_signal"), pidfd, signum, 0, 0)
    if result < 0:
        _raise_errno("pidfd_send_signal")


def _memfd_create(name: str) -> int:
    result = _libc.syscall(
        _syscall_number("memfd_create"),
        name.encode("ascii"),
        MFD_CLOEXEC | MFD_ALLOW_SEALING,
    )
    if result < 0:
        _raise_errno("memfd_create")
    return int(result)


def _caller_precondition() -> None:
    if _libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise EssentialPrimitiveUnavailable("guardian caller must already be nondumpable")
    status = _status_fields()
    if status.get("TracerPid") != "0":
        raise EssentialPrimitiveUnavailable("guardian caller must not be traced")


def _trusted_file(path: str) -> os.stat_result:
    file_stat = os.stat(path, follow_symlinks=False)
    if file_stat.st_uid != 0 or stat.S_IMODE(file_stat.st_mode) & 0o022:
        raise EssentialPrimitiveUnavailable(f"{path} is not root-owned and non-writable")
    return file_stat


def _subordinate_id(path: str, username: str) -> int:
    _trusted_file(path)
    matches: list[tuple[int, int]] = []
    with open(path, encoding="ascii") as ranges:
        for line in ranges:
            fields = line.strip().split(":")
            if len(fields) == 3 and fields[0] == username:
                try:
                    start, count = int(fields[1]), int(fields[2])
                except ValueError as exc:
                    raise EssentialPrimitiveUnavailable(f"malformed {path} entry") from exc
                if start > 0 and count > 0:
                    matches.append((start, count))
    if not matches:
        raise EssentialPrimitiveUnavailable(f"no subordinate id is configured in {path}")
    return matches[0][0]


def _mapping_configuration() -> tuple[int, int]:
    username = pwd.getpwuid(os.getuid()).pw_name
    for helper in ("/usr/bin/newuidmap", "/usr/bin/newgidmap"):
        helper_stat = _trusted_file(helper)
        if not stat.S_ISREG(helper_stat.st_mode) or not os.access(helper, os.X_OK):
            raise EssentialPrimitiveUnavailable(f"mapping helper is unavailable: {helper}")
    return _subordinate_id("/etc/subuid", username), _subordinate_id("/etc/subgid", username)


def _close_all_except(keep: set[int]) -> list[dict[str, Any]]:
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if maximum == resource.RLIM_INFINITY:
        maximum = 1_048_576
    cursor = 0
    for fd in sorted(keep):
        if cursor < fd:
            os.closerange(cursor, fd)
        cursor = fd + 1
    os.closerange(cursor, int(maximum))
    inventory: list[dict[str, Any]] = []
    for fd in sorted(keep):
        descriptor_stat = os.fstat(fd)
        if stat.S_ISSOCK(descriptor_stat.st_mode):
            kind = "socket"
        elif stat.S_ISFIFO(descriptor_stat.st_mode):
            kind = "pipe"
        else:
            raise RuntimeError("bootstrap retained a non-control inherited FD")
        inventory.append({"fd": fd, "kind": kind})
    return inventory


def _persistent_open_fds() -> list[int]:
    result: list[int] = []
    for value in os.listdir("/proc/self/fd"):
        fd = int(value)
        try:
            os.fstat(fd)
        except OSError:
            continue
        result.append(fd)
    return sorted(result)


def _drop_all_capabilities() -> None:
    if _libc.prctl(PR_SET_SECUREBITS, SECUREBITS_LOCKED_ZERO_CAPS, 0, 0, 0) != 0:
        _raise_errno("prctl(PR_SET_SECUREBITS)")
    if _libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
        _raise_errno("prctl(PR_CAP_AMBIENT_CLEAR_ALL)")
    with open("/proc/sys/kernel/cap_last_cap", encoding="ascii") as cap_file:
        last_capability = int(cap_file.read().strip())
    for capability in range(last_capability + 1):
        if _libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0:
            _raise_errno(f"prctl(PR_CAPBSET_DROP,{capability})")
    header = _CapHeader(0x20080522, 0)
    data = (_CapData * 2)()
    if _libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        _raise_errno("capset(zero)")
    if _libc.prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != SECUREBITS_LOCKED_ZERO_CAPS:
        raise RuntimeError("securebits readback mismatch")


def _write_proc(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        data = value.encode("ascii")
        if os.write(fd, data) != len(data):
            raise OSError(errno.EIO, f"short write to {path}")
    finally:
        os.close(fd)


def _namespace_id(kind: str) -> str:
    return os.readlink(f"/proc/self/ns/{kind}")


def _peercred(sock: socket.socket) -> tuple[int, int, int]:
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _canonical_packet(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _close_fds(fds: Sequence[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


def _send_packet(sock: socket.socket, payload: Mapping[str, Any], fds: Sequence[int] = ()) -> None:
    body = _canonical_packet(payload)
    if not body or len(body) > MAX_PACKET_BYTES:
        raise ProtocolRejected("packet length is outside the protocol bound")
    ancillary: list[tuple[int, int, bytes]] = []
    if fds:
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds).tobytes()))
    sent = sock.sendmsg([body], ancillary)
    if sent != len(body):
        raise UnknownOutcomeError("SOCK_SEQPACKET send was incomplete")


def _recv_packet(sock: socket.socket) -> tuple[dict[str, Any], list[int], tuple[int, int, int]]:
    rights_space = socket.CMSG_SPACE(8 * array.array("i").itemsize)
    credentials_space = socket.CMSG_SPACE(struct.calcsize("3i"))
    body, ancillary, flags, _address = sock.recvmsg(
        MAX_PACKET_BYTES, rights_space + credentials_space, socket.MSG_CMSG_CLOEXEC
    )
    if not body:
        raise EOFError("guardian control channel reached EOF")
    received_fds: list[int] = []
    credentials: list[tuple[int, int, int]] = []
    try:
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise ProtocolRejected("truncated packet or ancillary data")
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET:
                raise ProtocolRejected("unexpected ancillary level")
            if kind == socket.SCM_RIGHTS:
                values = array.array("i")
                usable = len(data) - (len(data) % values.itemsize)
                values.frombytes(data[:usable])
                received_fds.extend(values.tolist())
            elif kind == socket.SCM_CREDENTIALS:
                if len(data) < struct.calcsize("3i"):
                    raise ProtocolRejected("short SCM_CREDENTIALS")
                credentials.append(struct.unpack("3i", data[: struct.calcsize("3i")]))
            else:
                raise ProtocolRejected("unexpected ancillary type")
        if len(credentials) != 1:
            raise ProtocolRejected("exactly one SCM_CREDENTIALS record is required")
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolRejected("control packet is not canonical JSON data") from exc
        if not isinstance(decoded, dict) or _canonical_packet(decoded) != body:
            raise ProtocolRejected("control packet is not an exact canonical JSON object")
        return decoded, received_fds, credentials[0]
    except BaseException:
        _close_fds(received_fds)
        raise


def _exact_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProtocolRejected(f"{label} has non-exact keys")
    return value


def _strict_int(value: Any, label: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ProtocolRejected(f"{label} is outside the allowed integer range")
    return value


def _strict_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _LOWER_HEX for character in value)
    ):
        raise ProtocolRejected(f"{label} is not a lowercase sha256 digest")
    return value


def _strict_b64(value: Any, label: str, *, maximum_decoded: int) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum_decoded + 2) // 3):
        raise ProtocolRejected(f"{label} is outside the base64 bound")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProtocolRejected(f"{label} is not valid base64") from exc


def _strict_text(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise ProtocolRejected(f"{label} must be a non-empty string")
    return value


def _strict_bytes(value: Any, label: str) -> bytes:
    if type(value) is not bytes:
        raise ProtocolRejected(f"{label} must be bytes")
    return value


def _validate_export_capsule_body(
    body: bytes, *, attempt_id: str, capsule_nonce: str, expected_digest: str
) -> dict[str, Any]:
    if hashlib.sha256(body).hexdigest() != expected_digest:
        raise ProtocolRejected("detached artifact digest mismatch")
    try:
        capsule = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolRejected("detached export capsule is not JSON") from exc
    expected_capsule_keys = frozenset(
        {
            "schema",
            "type",
            "attempt_id",
            "nonce",
            "epoch",
            "source_root",
            "byte_count",
            "inode_count",
            "entry_count",
            "content_digest",
            "entries",
            "truth_boundary",
        }
    )
    if not isinstance(capsule, dict) or _canonical_packet(capsule) != body:
        raise ProtocolRejected("detached export capsule is not canonical JSON")
    _exact_object(capsule, expected_capsule_keys, "detached export capsule")
    if (
        capsule["schema"] != EXPORT_SCHEMA
        or capsule["type"] != "recovery_export_capsule"
        or capsule["attempt_id"] != attempt_id
        or capsule["nonce"] != capsule_nonce
        or capsule["truth_boundary"] != _TRUTH_BOUNDARY
    ):
        raise ProtocolRejected("detached export capsule binding mismatch")
    _strict_text(capsule["epoch"], "detached capsule epoch")
    _strict_text(capsule["nonce"], "detached capsule nonce")
    content_digest = _strict_sha256(capsule["content_digest"], "detached capsule content digest")
    byte_count = _strict_int(capsule["byte_count"], "detached capsule byte count", minimum=0)
    inode_count = _strict_int(capsule["inode_count"], "detached capsule inode count", minimum=1)
    entry_count = _strict_int(capsule["entry_count"], "detached capsule entry count", minimum=0)
    if inode_count != entry_count + 1:
        raise ProtocolRejected("detached export inode count mismatch")
    source_root = _exact_object(
        capsule["source_root"],
        frozenset({"device", "inode", "mode", "mount_id", "namespace"}),
        "detached source root",
    )
    source_device = _strict_int(source_root["device"], "detached source device", minimum=1)
    _strict_int(source_root["inode"], "detached source inode", minimum=1)
    _strict_int(source_root["mode"], "detached source mode", minimum=0, maximum=0o777)
    _strict_int(source_root["mount_id"], "detached source mount id", minimum=1)
    _strict_text(source_root["namespace"], "detached source namespace")
    entries = capsule["entries"]
    if not isinstance(entries, list) or len(entries) != entry_count:
        raise ProtocolRejected("detached export entries mismatch")
    known_directories = {""}
    seen_paths: set[str] = set()
    total_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict) or "kind" not in entry or "path" not in entry:
            raise ProtocolRejected("detached export entry is malformed")
        path = _validate_export_relative_path(entry["path"], known_directories)
        if path in seen_paths:
            raise ProtocolRejected("detached export duplicate path")
        seen_paths.add(path)
        kind = entry["kind"]
        if kind == "dir":
            _exact_object(
                entry,
                frozenset({"path", "kind", "mode", "device", "inode"}),
                "detached dir entry",
            )
            _strict_int(entry["mode"], "detached directory mode", minimum=0, maximum=0o777)
            if _strict_int(entry["device"], "detached directory device") != source_device:
                raise ProtocolRejected("detached directory device mismatch")
            _strict_int(entry["inode"], "detached directory inode", minimum=1)
            known_directories.add(path)
        elif kind == "file":
            _exact_object(
                entry,
                frozenset(
                    {
                        "path",
                        "kind",
                        "mode",
                        "device",
                        "inode",
                        "size",
                        "nlink",
                        "sha256",
                        "content_b64",
                    }
                ),
                "detached file entry",
            )
            _strict_int(entry["mode"], "detached file mode", minimum=0, maximum=0o777)
            if _strict_int(entry["device"], "detached file device") != source_device:
                raise ProtocolRejected("detached file device mismatch")
            _strict_int(entry["inode"], "detached file inode", minimum=1)
            size = _strict_int(entry["size"], "detached file size", minimum=0, maximum=byte_count)
            if _strict_int(entry["nlink"], "detached file nlink", minimum=1, maximum=1) != 1:
                raise ProtocolRejected("detached file is hardlinked")
            file_digest = _strict_sha256(entry["sha256"], "detached file sha256")
            data = _strict_b64(entry["content_b64"], "detached file content", maximum_decoded=size)
            if len(data) != size or hashlib.sha256(data).hexdigest() != file_digest:
                raise ProtocolRejected("detached file digest mismatch")
            total_bytes += size
        else:
            raise ProtocolRejected("detached export entry kind is unsupported")
    if total_bytes != byte_count or _logical_content_digest(entries) != content_digest:
        raise ProtocolRejected("detached export content digest mismatch")
    return capsule


def _status_fields() -> dict[str, str]:
    fields: dict[str, str] = {}
    with open("/proc/self/status", encoding="ascii") as status_file:
        for line in status_file:
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
    return fields


def _mount_evidence(quota_bytes: int) -> dict[str, Any]:
    mount_line: list[str] | None = None
    root_optional: list[str] | None = None
    with open("/proc/self/mountinfo", encoding="ascii") as mountinfo:
        for line in mountinfo:
            fields = line.rstrip("\n").split(" ")
            separator = fields.index("-")
            if fields[4] == INTERNAL_MOUNT:
                mount_line = fields
            if fields[4] == "/":
                root_optional = fields[6:separator]
    if mount_line is None or root_optional is None:
        raise RuntimeError("required mountinfo records are absent")
    separator = mount_line.index("-")
    mount_options = frozenset(mount_line[5].split(","))
    if mount_line[separator + 1] != "tmpfs":
        raise RuntimeError("private recovery mount is not tmpfs")
    required = {"nosuid", "nodev", "noexec"}
    if not required.issubset(mount_options):
        raise RuntimeError("private recovery mount lacks required flags")
    if any(
        option.startswith(("shared:", "master:", "propagate_from:")) for option in root_optional
    ):
        raise RuntimeError("mount propagation remained non-private")
    filesystem = os.statvfs(INTERNAL_MOUNT)
    actual_bytes = filesystem.f_frsize * filesystem.f_blocks
    if actual_bytes > quota_bytes:
        raise RuntimeError("tmpfs size exceeds requested quota")
    if filesystem.f_files > TMPFS_INODE_LIMIT:
        raise RuntimeError("tmpfs inode count exceeds requested limit")
    return {
        "mountpoint": INTERNAL_MOUNT,
        "filesystem": "tmpfs",
        "requested_bytes": quota_bytes,
        "actual_bytes": actual_bytes,
        "requested_inodes": TMPFS_INODE_LIMIT,
        "actual_inodes": filesystem.f_files,
        "nosuid": True,
        "nodev": True,
        "noexec": True,
        "root_propagation_private": True,
    }


def _bootstrap_child(config: Mapping[str, Any], ready_fd: int, mapped_fd: int) -> dict[str, Any]:
    if _libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise RuntimeError("child did not inherit the nondumpable broker boundary")
    if _libc.ptrace(PTRACE_TRACEME, 0, None, None) != 0:
        _raise_errno("ptrace(PTRACE_TRACEME)")
    if _libc.prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0:
        _raise_errno("temporary prctl(PR_SET_DUMPABLE)")
    if _libc.unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0:
        _raise_errno("unshare(CLONE_NEWUSER|CLONE_NEWNS)")
    if os.write(ready_fd, b"U") != 1:
        raise RuntimeError("mapping ready synchronization failed")
    os.close(ready_fd)
    if os.read(mapped_fd, 1) != b"M":
        raise RuntimeError("parent mapping synchronization failed")
    os.close(mapped_fd)
    os.setgroups([])
    os.setgid(0)
    os.setuid(0)
    if _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        _raise_errno("prctl(PR_SET_DUMPABLE)")
    if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        _raise_errno("prctl(PR_SET_NO_NEW_PRIVS)")
    if _libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        _raise_errno("prctl(PR_SET_PDEATHSIG)")
    pdeathsig = ctypes.c_int()
    if _libc.prctl(PR_GET_PDEATHSIG, ctypes.addressof(pdeathsig), 0, 0, 0) != 0:
        _raise_errno("prctl(PR_GET_PDEATHSIG)")
    if pdeathsig.value != signal.SIGKILL:
        raise RuntimeError("PDEATHSIG readback mismatch")
    if os.getppid() != config["parent_pid"]:
        raise RuntimeError("broker parent changed during bootstrap")
    os.kill(os.getpid(), signal.SIGSTOP)
    fields = _status_fields()
    if fields["TracerPid"] != "0":
        raise RuntimeError("bootstrap tracer remained attached")
    if _persistent_open_fds() != [config["control_fd"]]:
        raise RuntimeError("unexpected inherited FD survived bootstrap")
    return {
        "tracer_pid": 0,
        "inherited_dumpable": 0,
        "groups": fields["Groups"],
        "setgroups": open("/proc/self/setgroups", encoding="ascii").read().strip(),
        "post_bootstrap_open_fds": _persistent_open_fds(),
    }


def _prepare_child(
    config: Mapping[str, Any], bootstrap_evidence: Mapping[str, Any]
) -> tuple[int, dict[str, Any]]:
    if _libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None) != 0:
        _raise_errno("mount propagation private")
    quota_bytes = int(config["quota_bytes"])
    mount_data = f"size={quota_bytes},mode=0700,nr_inodes={TMPFS_INODE_LIMIT}".encode("ascii")
    if (
        _libc.mount(
            b"tmpfs",
            INTERNAL_MOUNT.encode(),
            b"tmpfs",
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            mount_data,
        )
        != 0
    ):
        _raise_errno("mount private tmpfs")
    os.mkdir(INTERNAL_ROOT, mode=0o700)
    os.chown(INTERNAL_ROOT, 1, 1)
    root_fd = os.open(INTERNAL_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    root_stat = os.fstat(root_fd)
    if _libc.setfsgid(1) not in {0, 1} or _libc.setfsgid(1) != 1:
        raise RuntimeError("child fsgid did not bind to the lease owner")
    if _libc.setfsuid(1) not in {0, 1} or _libc.setfsuid(1) != 1:
        raise RuntimeError("child fsuid did not bind to the lease owner")
    if _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        _raise_errno("prctl(PR_SET_DUMPABLE after fsuid)")
    _drop_all_capabilities()
    dumpable = _libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
    no_new_privs = _libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
    if dumpable != 0 or no_new_privs != 1:
        raise RuntimeError("child security state did not become fail-closed")
    status_fields = _status_fields()
    zero = "0000000000000000"
    if any(
        status_fields[name] != zero for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    ):
        raise RuntimeError("capability sets did not read back as zero")
    if status_fields["Groups"] or status_fields["TracerPid"] != "0":
        raise RuntimeError("groups or tracer state changed after bootstrap")
    evidence = {
        "namespaces": {"user": _namespace_id("user"), "mount": _namespace_id("mnt")},
        "mount": _mount_evidence(quota_bytes),
        "security": {
            "dumpable": dumpable,
            "no_new_privs": no_new_privs,
            "cap_inh": status_fields["CapInh"],
            "cap_prm": status_fields["CapPrm"],
            "cap_eff": status_fields["CapEff"],
            "cap_bnd": status_fields["CapBnd"],
            "cap_amb": status_fields["CapAmb"],
            "securebits": _libc.prctl(PR_GET_SECUREBITS, 0, 0, 0, 0),
            "groups": status_fields["Groups"],
            "setgroups": bootstrap_evidence["setgroups"],
            "tracer_pid": int(status_fields["TracerPid"]),
            "pdeathsig": signal.SIGKILL,
            "inherited_dumpable": bootstrap_evidence["inherited_dumpable"],
            "uid_map": open("/proc/self/uid_map", encoding="ascii").read().strip(),
            "gid_map": open("/proc/self/gid_map", encoding="ascii").read().strip(),
        },
        "fd_inventory": {
            "after_inherited_close": config["inherited_fd_inventory"],
            "post_bootstrap_open_fds": bootstrap_evidence["post_bootstrap_open_fds"],
        },
        "recovery_root": {
            "fd_number": root_fd,
            "device": root_stat.st_dev,
            "inode": root_stat.st_ino,
            "mode": stat.S_IMODE(root_stat.st_mode),
            "mount_id": _mount_id_for_fd(root_fd),
        },
    }
    return root_fd, evidence


def _pid_status(pid: int) -> dict[str, str]:
    fields: dict[str, str] = {}
    with open(f"/proc/{pid}/status", encoding="ascii") as status_file:
        for line in status_file:
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
    return fields


def _install_subordinate_maps(
    pid: int, subuid: int, subgid: int, host_uid: int, host_gid: int, fail: bool
) -> None:
    if fail:
        subuid += 2**31
    commands = (
        ("/usr/bin/newuidmap", str(pid), "0", str(subuid), "1", "1", str(host_uid), "1"),
        ("/usr/bin/newgidmap", str(pid), "0", str(subgid), "1", "1", str(host_gid), "1"),
    )
    for command in commands:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            reason = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
            raise EssentialPrimitiveUnavailable(
                f"{command[0]} rejected subordinate mapping: {reason}"
            )


def _verify_stopped_child(pid: int, parent_pid: int, subuid: int, subgid: int) -> None:
    waited_pid, wait_status = os.waitpid(pid, os.WUNTRACED)
    if (
        waited_pid != pid
        or not os.WIFSTOPPED(wait_status)
        or os.WSTOPSIG(wait_status) != signal.SIGSTOP
    ):
        raise EssentialPrimitiveUnavailable("child did not enter the verified ptrace stop")
    fields = _pid_status(pid)
    expected_uid = str(subuid)
    expected_gid = str(subgid)
    if fields["Uid"].split() != [expected_uid] * 4:
        raise EssentialPrimitiveUnavailable("child host subordinate UID attestation failed")
    if fields["Gid"].split() != [expected_gid] * 4:
        raise EssentialPrimitiveUnavailable("child host subordinate GID attestation failed")
    if fields["Groups"] or fields["TracerPid"] != str(parent_pid):
        raise EssentialPrimitiveUnavailable("child groups/tracer attestation failed")
    if _libc.ptrace(PTRACE_DETACH, pid, None, None) != 0:
        _raise_errno("ptrace(PTRACE_DETACH)")


def _binding(config: Mapping[str, Any], packet_type: str, request_id: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "type": packet_type,
        "attempt_id": config["attempt_id"],
        "nonce": config["nonce"],
        "epoch": config["epoch"],
        "request_id": request_id,
    }


def _reject(sock: socket.socket, config: Mapping[str, Any], request_id: str, code: str) -> None:
    _send_packet(sock, {**_binding(config, "rejected", request_id), "code": code})


def _command_binding_valid(packet: Mapping[str, Any], config: Mapping[str, Any]) -> bool:
    return (
        packet.get("schema") == SCHEMA
        and packet.get("attempt_id") == config["attempt_id"]
        and packet.get("nonce") == config["nonce"]
        and packet.get("epoch") == config["epoch"]
        and isinstance(packet.get("request_id"), str)
        and bool(packet["request_id"])
    )


def _cleanup_child(root_fd: int) -> None:
    # Capabilities are intentionally zero, so explicit umount(2) is unavailable.
    # Closing the last root handle and exiting destroys the private mount namespace;
    # the parent closes its namespace attestation FD before accepting child exit.
    os.close(root_fd)


def _mount_id_for_fd(fd: int) -> int:
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1].strip())
    raise RuntimeError("mount identity is absent from fdinfo")


def _safe_child_name(name: str) -> None:
    try:
        raw = name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolRejected("unsafe non-ascii recovery entry name") from exc
    if (
        not raw
        or len(raw) > 255
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or any(byte not in SAFE_NAME_BYTES for byte in raw)
    ):
        raise ProtocolRejected("unsafe recovery entry name")


def _validate_export_relative_path(path: Any, known_directories: set[str]) -> str:
    if not isinstance(path, str) or not path:
        raise ProtocolRejected("export entry path is invalid")
    try:
        raw = path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolRejected("export entry path is not ascii") from exc
    if len(raw) > MAX_EXPORT_PATH_BYTES or path.startswith("/") or "\x00" in path:
        raise ProtocolRejected("export entry path is invalid")
    components = path.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ProtocolRejected("export entry path is invalid")
    for component in components:
        _safe_child_name(component)
    parent = "/".join(components[:-1])
    if parent not in known_directories:
        raise ProtocolRejected("export entry parent was not validated")
    return path


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return _stat_identity(left) == _stat_identity(right)


def _directory_snapshot(
    directory_fd: int, *, source_device: int, source_mount_id: int
) -> list[tuple[str, tuple[int, int, int, int, int, int, int]]]:
    if _mount_id_for_fd(directory_fd) != source_mount_id:
        raise ProtocolRejected("directory mount identity changed during export")
    snapshot: list[tuple[str, tuple[int, int, int, int, int, int, int]]] = []
    for name in sorted(os.listdir(directory_fd)):
        _safe_child_name(name)
        item_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if item_stat.st_dev != source_device:
            raise ProtocolRejected("recovery entry device changed during export")
        snapshot.append((name, _stat_identity(item_stat)))
    return snapshot


def _logical_content_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    logical_entries: list[dict[str, Any]] = []
    for entry in entries:
        kind = entry["kind"]
        if kind == "dir":
            logical_entries.append(
                {
                    "kind": "dir",
                    "path": entry["path"],
                    "mode": entry["mode"],
                }
            )
        elif kind == "file":
            logical_entries.append(
                {
                    "kind": "file",
                    "path": entry["path"],
                    "mode": entry["mode"],
                    "size": entry["size"],
                    "sha256": entry["sha256"],
                }
            )
        else:
            raise ProtocolRejected("export entry type is unsupported")
    return hashlib.sha256(_canonical_packet({"entries": logical_entries})).hexdigest()


def _read_regular_file(fd: int, expected: os.stat_result) -> bytes:
    chunks: list[bytes] = []
    remaining = expected.st_size
    while remaining:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            raise ProtocolRejected("regular file ended before its declared size")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise ProtocolRejected("regular file grew during export")
    after = os.fstat(fd)
    if not _same_identity(expected, after):
        raise ProtocolRejected("regular file changed during export")
    return b"".join(chunks)


def _max_export_capsule_bytes(quota_bytes: int) -> int:
    encoded_payload_bound = 4 * ((quota_bytes + 2) // 3)
    metadata_bound = MAX_PACKET_BYTES + TMPFS_INODE_LIMIT * (MAX_EXPORT_PATH_BYTES + 1024)
    return encoded_payload_bound + metadata_bound


def _export_tree(root_fd: int, config: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    root_stat = os.fstat(root_fd)
    root_mount_id = _mount_id_for_fd(root_fd)
    if root_stat.st_dev != int(config["source_root_device"]):
        raise ProtocolRejected("recovery root device changed during export")
    entries: list[dict[str, Any]] = []
    byte_count = 0
    inode_count = 1

    def visit(directory_fd: int, path: str) -> None:
        nonlocal byte_count, inode_count
        before_snapshot = _directory_snapshot(
            directory_fd, source_device=root_stat.st_dev, source_mount_id=root_mount_id
        )
        if path == "" and config["test_fault"] == "export_race_after_snapshot":
            race_fd = os.open(
                "race-added",
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
            os.close(race_fd)
        for name, before_identity in before_snapshot:
            relative = f"{path}/{name}" if path else name
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _stat_identity(before) != before_identity:
                raise ProtocolRejected("recovery entry changed before export")
            mode = before.st_mode
            if stat.S_ISDIR(mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    after = os.fstat(child_fd)
                    if (
                        after.st_dev != root_stat.st_dev
                        or _mount_id_for_fd(child_fd) != root_mount_id
                    ):
                        raise ProtocolRejected("directory source mount changed during export")
                    if not _same_identity(before, after):
                        raise ProtocolRejected("directory changed during export")
                    inode_count += 1
                    if inode_count > TMPFS_INODE_LIMIT:
                        raise ProtocolRejected("export inode quota exceeded")
                    entries.append(
                        {
                            "path": relative,
                            "kind": "dir",
                            "mode": stat.S_IMODE(after.st_mode),
                            "device": after.st_dev,
                            "inode": after.st_ino,
                        }
                    )
                    visit(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(mode):
                if before.st_nlink != 1:
                    raise ProtocolRejected("regular file has multiple hard links")
                file_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    after = os.fstat(file_fd)
                    if (
                        after.st_dev != root_stat.st_dev
                        or _mount_id_for_fd(file_fd) != root_mount_id
                    ):
                        raise ProtocolRejected("file source mount changed during export")
                    if not stat.S_ISREG(after.st_mode) or not _same_identity(before, after):
                        raise ProtocolRejected("regular file changed during export")
                    if after.st_size > int(config["quota_bytes"]) - byte_count:
                        raise ProtocolRejected("regular file exceeds remaining export quota")
                    data = _read_regular_file(file_fd, after)
                    byte_count += len(data)
                    inode_count += 1
                    if byte_count > int(config["quota_bytes"]) or byte_count > MAX_QUOTA_BYTES:
                        raise ProtocolRejected("export byte quota exceeded")
                    if inode_count > TMPFS_INODE_LIMIT:
                        raise ProtocolRejected("export inode quota exceeded")
                    encoded = base64.b64encode(data).decode("ascii")
                    entries.append(
                        {
                            "path": relative,
                            "kind": "file",
                            "mode": stat.S_IMODE(after.st_mode),
                            "device": after.st_dev,
                            "inode": after.st_ino,
                            "size": len(data),
                            "nlink": after.st_nlink,
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "content_b64": encoded,
                        }
                    )
                finally:
                    os.close(file_fd)
            else:
                raise ProtocolRejected("unsupported recovery entry type")
        after_snapshot = _directory_snapshot(
            directory_fd, source_device=root_stat.st_dev, source_mount_id=root_mount_id
        )
        if after_snapshot != before_snapshot:
            raise ProtocolRejected("directory changed during export")

    visit(root_fd, "")
    content_digest = _logical_content_digest(entries)
    capsule = {
        "schema": EXPORT_SCHEMA,
        "type": "recovery_export_capsule",
        "attempt_id": config["attempt_id"],
        "nonce": config["nonce"],
        "epoch": config["epoch"],
        "source_root": {
            "device": root_stat.st_dev,
            "inode": root_stat.st_ino,
            "mode": stat.S_IMODE(root_stat.st_mode),
            "mount_id": root_mount_id,
            "namespace": config["child_mount_namespace"],
        },
        "byte_count": byte_count,
        "inode_count": inode_count,
        "entry_count": len(entries),
        "content_digest": content_digest,
        "entries": entries,
        "truth_boundary": _TRUTH_BOUNDARY,
    }
    body = _canonical_packet(capsule)
    if len(body) > _max_export_capsule_bytes(int(config["quota_bytes"])):
        raise ProtocolRejected("export capsule size exceeded bound")
    return capsule, body


def _write_all(fd: int, body: bytes, writer: Any = os.write) -> None:
    view = memoryview(body)
    cursor = 0
    while cursor < len(view):
        try:
            written = writer(fd, view[cursor:])
        except InterruptedError:
            continue
        if written is None:
            written = len(view) - cursor
        if written <= 0:
            raise OSError(errno.EIO, "short write made no progress")
        cursor += written


def _sealed_memfd_from_capsule(body: bytes, writer: Any = os.write) -> tuple[int, int]:
    fd = _memfd_create("acgs-recovery-export")
    try:
        _write_all(fd, body, writer)
        if os.fstat(fd).st_size != len(body):
            raise RuntimeError("memfd size did not match capsule before sealing")
        if os.lseek(fd, 0, os.SEEK_SET) != 0:
            raise RuntimeError("memfd seek failed")
        fcntl.fcntl(fd, F_ADD_SEALS, EXPORT_SEALS)
        seals = fcntl.fcntl(fd, F_GET_SEALS)
        if seals != EXPORT_SEALS:
            raise RuntimeError("memfd seals did not read back")
        return fd, seals
    except BaseException:
        os.close(fd)
        raise


def _child_loop(sock: socket.socket, config: Mapping[str, Any], root_fd: int) -> NoReturn:
    lease_issued = False
    live_lease_id: str | None = None
    export_issued = False
    live_export: dict[str, str] | None = None
    parent_credential = tuple(config["child_view_parent_credential"])
    while True:
        try:
            packet, received_fds, credentials = _recv_packet(sock)
        except EOFError:
            _cleanup_child(root_fd)
            os._exit(91)
        except BaseException:
            _cleanup_child(root_fd)
            os._exit(92)
        request_id = packet.get("request_id")
        request_id = request_id if isinstance(request_id, str) and request_id else "invalid"
        try:
            if credentials != parent_credential or _peercred(sock) != parent_credential:
                _reject(sock, config, request_id, "peer_credentials_mismatch")
                continue
            if received_fds:
                _reject(sock, config, request_id, "unexpected_ancillary_fds")
                continue
            if not _command_binding_valid(packet, config):
                _reject(sock, config, request_id, "binding_mismatch")
                continue
            packet_type = packet.get("type")
            if packet_type == "lease_request":
                if set(packet) != _BINDING_KEYS:
                    _reject(sock, config, request_id, "non_exact_lease_request")
                    continue
                if lease_issued:
                    _reject(sock, config, request_id, "lease_already_issued")
                    continue
                lease_issued = True
                live_lease_id = secrets.token_hex(32)
                response = {
                    **_binding(config, "lease_granted", request_id),
                    "lease_id": live_lease_id,
                }
                fault = config["test_fault"]
                if fault == "lease_regular_fd":
                    regular_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        _send_packet(sock, response, [regular_fd])
                    finally:
                        os.close(regular_fd)
                elif fault == "lease_two_fds":
                    duplicate = os.dup(root_fd)
                    try:
                        _send_packet(sock, response, [root_fd, duplicate])
                    finally:
                        os.close(duplicate)
                else:
                    _send_packet(sock, response, [root_fd])
            elif packet_type == "lease_release":
                expected = _BINDING_KEYS | {"lease_id"}
                if set(packet) != expected:
                    _reject(sock, config, request_id, "non_exact_lease_release")
                elif live_lease_id is None or packet.get("lease_id") != live_lease_id:
                    _reject(sock, config, request_id, "lease_binding_mismatch")
                else:
                    live_lease_id = None
                    if config["test_fault"] == "die_after_release":
                        os._exit(95)
                    _send_packet(sock, _binding(config, "lease_released", request_id))
            elif packet_type == "export_request":
                if set(packet) != _BINDING_KEYS:
                    _reject(sock, config, request_id, "non_exact_export_request")
                elif live_lease_id is not None:
                    _reject(sock, config, request_id, "live_lease")
                elif export_issued:
                    _reject(sock, config, request_id, "export_already_issued")
                else:
                    export_issued = True
                    export_id = secrets.token_hex(32)
                    capsule, body = _export_tree(root_fd, config)
                    memfd, seals = _sealed_memfd_from_capsule(body)
                    digest = hashlib.sha256(body).hexdigest()
                    if config["test_fault"] == "export_bad_digest":
                        digest = "0" * 64
                    response = {
                        **_binding(config, "export_granted", request_id),
                        "export_id": export_id,
                        "source_root": capsule["source_root"],
                        "byte_count": capsule["byte_count"],
                        "inode_count": capsule["inode_count"],
                        "entry_count": capsule["entry_count"],
                        "content_digest": capsule["content_digest"],
                        "capsule_digest": digest,
                        "capsule_size": len(body),
                        "seals": seals,
                        "truth_boundary": _TRUTH_BOUNDARY,
                    }
                    if config["test_fault"] == "export_extra_key":
                        response["unexpected"] = True
                    try:
                        if config["test_fault"] == "export_regular_fd":
                            regular_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                            try:
                                _send_packet(sock, response, [regular_fd])
                            finally:
                                os.close(regular_fd)
                        elif config["test_fault"] == "export_two_fds":
                            duplicate = os.dup(memfd)
                            try:
                                _send_packet(sock, response, [memfd, duplicate])
                            finally:
                                os.close(duplicate)
                        else:
                            _send_packet(sock, response, [memfd])
                    finally:
                        os.close(memfd)
                    live_export = {"export_id": export_id, "capsule_digest": digest}
                    if config["test_fault"] == "die_after_export_send":
                        os._exit(97)
            elif packet_type == "export_release":
                if set(packet) != _EXPORT_RELEASE_KEYS:
                    _reject(sock, config, request_id, "non_exact_export_release")
                elif live_export is None:
                    _reject(sock, config, request_id, "export_not_live")
                elif (
                    packet.get("export_id") != live_export["export_id"]
                    or packet.get("capsule_digest") != live_export["capsule_digest"]
                ):
                    _reject(sock, config, request_id, "export_binding_mismatch")
                else:
                    live_export = None
                    _send_packet(sock, _binding(config, "export_released", request_id))
            elif packet_type == "finalize":
                if set(packet) != _BINDING_KEYS:
                    _reject(sock, config, request_id, "non_exact_finalize")
                elif live_lease_id is not None:
                    _reject(sock, config, request_id, "live_lease")
                elif live_export is not None:
                    _reject(sock, config, request_id, "live_export")
                elif config["test_fault"] == "die_before_finalize":
                    os._exit(93)
                else:
                    _cleanup_child(root_fd)
                    if config["test_fault"] == "die_after_unmount":
                        os._exit(96)
                    _send_packet(sock, _binding(config, "finalized", request_id))
                    sock.close()
                    os._exit(0)
            else:
                _reject(sock, config, request_id, "unknown_command")
        finally:
            _close_fds(received_fds)


def _child_main(sock_fd: int, ready_fd: int, mapped_fd: int, config: dict[str, Any]) -> NoReturn:
    sock = socket.socket(fileno=sock_fd)
    root_fd = -1
    namespace_fd = -1
    try:
        if _peercred(sock) != tuple(config["parent_credential"]):
            raise RuntimeError("socketpair creator credentials changed")
        bootstrap_evidence = _bootstrap_child(config, ready_fd, mapped_fd)
        root_fd, evidence = _prepare_child(config, bootstrap_evidence)
        child_view_parent_credential = _peercred(sock)
        config["child_view_parent_credential"] = child_view_parent_credential
        config["child_mount_namespace"] = evidence["namespaces"]["mount"]
        config["source_root_device"] = evidence["recovery_root"]["device"]
        namespace_fd = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        namespace_stat = os.fstat(namespace_fd)
        handshake: dict[str, Any] = {
            "schema": SCHEMA,
            "type": "handshake",
            "attempt_id": config["attempt_id"],
            "nonce": config["nonce"],
            "epoch": config["epoch"],
            "child_pid": os.getpid(),
            "socket_peercred": list(child_view_parent_credential),
            "message_peercred": [os.getpid(), config["subuid"], config["subgid"]],
            "namespaces": evidence["namespaces"],
            "parent_namespaces": config["parent_namespaces"],
            "mount": evidence["mount"],
            "security": evidence["security"],
            "fd_inventory": evidence["fd_inventory"],
            "recovery_root": evidence["recovery_root"],
            "namespace_handle": {
                "device": namespace_stat.st_dev,
                "inode": namespace_stat.st_ino,
            },
        }
        if config["test_fault"] == "handshake_extra_key":
            handshake["unexpected"] = True
        if config["test_fault"] == "handshake_regular_fd":
            handshake_fds = [root_fd]
        elif config["test_fault"] == "handshake_two_fds":
            handshake_fds = [namespace_fd, root_fd]
        else:
            handshake_fds = [namespace_fd]
        _send_packet(sock, handshake, handshake_fds)
        os.close(namespace_fd)
        namespace_fd = -1
        _child_loop(sock, config, root_fd)
    except BaseException as exc:
        if namespace_fd >= 0:
            os.close(namespace_fd)
        if root_fd >= 0:
            try:
                _cleanup_child(root_fd)
            except BaseException:
                pass
        try:
            _send_packet(
                sock,
                {
                    "schema": SCHEMA,
                    "type": "startup_error",
                    "attempt_id": config["attempt_id"],
                    "nonce": config["nonce"],
                    "epoch": config["epoch"],
                    "reason": f"{type(exc).__name__}: {exc}",
                },
            )
        except BaseException:
            pass
        os._exit(94)


@dataclass(frozen=True)
class GuardianEvidence:
    """Validated evidence captured from the private child."""

    payload: dict[str, Any]


class DirectoryLease:
    """One-use attempt-bound directory FD received with ``SCM_RIGHTS``."""

    def __init__(self, guardian: RecoveryNamespaceGuardian, fd: int, lease_id: str) -> None:
        self._guardian = guardian
        self.fd = fd
        self.lease_id = lease_id
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        if self._released:
            raise ProtocolRejected("lease release replay")
        try:
            self._guardian._release_lease(self.lease_id)
        finally:
            os.close(self.fd)
            self._released = True

    def __enter__(self) -> DirectoryLease:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


class SealedRecoveryExport:
    """One-use sealed memfd export that must be relinquished before finalize."""

    def __init__(
        self,
        guardian: RecoveryNamespaceGuardian,
        fd: int,
        export_id: str,
        capsule_digest: str,
        metadata: dict[str, Any],
    ) -> None:
        self._guardian = guardian
        self.fd = fd
        self.export_id = export_id
        self.capsule_digest = capsule_digest
        self.metadata = metadata
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        if self._released:
            raise ProtocolRejected("export release replay")
        self._guardian._assert_no_local_duplicate_export_fds(self.fd)
        try:
            os.close(self.fd)
            self.fd = -1
            self._guardian._release_export(self.export_id, self.capsule_digest)
        except BaseException:
            self._guardian._make_unknown()
            raise
        else:
            self._released = True

    def __enter__(self) -> SealedRecoveryExport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


class RecoveryNamespaceGuardian:
    """Parent-side owner of one isolated recovery attempt."""

    def __init__(
        self,
        attempt_id: str,
        *,
        quota_bytes: int = 64 * 1024,
        test_mode: bool = False,
        test_fault: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not sys.platform.startswith("linux"):
            raise EssentialPrimitiveUnavailable("Linux namespaces are required")
        _caller_precondition()
        if not attempt_id or len(attempt_id) > 256:
            raise ValueError("attempt_id must be a non-empty bounded string")
        if (
            quota_bytes < 16 * 1024
            or quota_bytes > MAX_QUOTA_BYTES
            or quota_bytes % os.sysconf("SC_PAGE_SIZE") != 0
        ):
            raise ValueError("quota_bytes must be page-aligned and within 16 KiB..16 MiB")
        if test_fault is not None and (not test_mode or test_fault not in _FAULTS):
            raise ValueError("test faults require explicit test_mode and a known fault")
        subuid, subgid = _mapping_configuration()
        self.attempt_id = attempt_id
        self.nonce = secrets.token_hex(32)
        self.epoch = secrets.token_hex(16)
        self.quota_bytes = quota_bytes
        self.subuid = subuid
        self.subgid = subgid
        self._timeout_seconds = timeout_seconds
        self._test_mode = test_mode
        self._state = "starting"
        self._lease: DirectoryLease | None = None
        self._export: SealedRecoveryExport | None = None
        self.terminal_pidfd_ready: bool | None = None
        self.pidfd = -1
        self.mount_namespace_fd = -1
        parent, child = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
        )
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        mapped_read, mapped_write = os.pipe2(os.O_CLOEXEC)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        parent.settimeout(timeout_seconds)
        child.settimeout(None)
        parent_credential = (os.getpid(), os.getuid(), os.getgid())
        if _peercred(parent) != parent_credential or _peercred(child) != parent_credential:
            parent.close()
            child.close()
            raise EssentialPrimitiveUnavailable("socketpair SO_PEERCRED did not bind its creator")
        config: dict[str, Any] = {
            "attempt_id": attempt_id,
            "nonce": self.nonce,
            "epoch": self.epoch,
            "quota_bytes": quota_bytes,
            "subuid": subuid,
            "subgid": subgid,
            "host_uid": os.getuid(),
            "host_gid": os.getgid(),
            "parent_pid": os.getpid(),
            "parent_credential": parent_credential,
            "parent_namespaces": {"user": _namespace_id("user"), "mount": _namespace_id("mnt")},
            "test_fault": test_fault,
        }
        pid = os.fork()
        if pid == 0:
            parent.detach()
            child_fd = child.detach()
            config["control_fd"] = child_fd
            config["inherited_fd_inventory"] = _close_all_except(
                {child_fd, ready_write, mapped_read}
            )
            _child_main(child_fd, ready_write, mapped_read, config)
        child.close()
        os.close(ready_write)
        os.close(mapped_read)
        self.pid = pid
        self._sock = parent
        try:
            self.pidfd = _pidfd_open(pid)
        except BaseException:
            self._sock.close()
            os.close(ready_read)
            os.close(mapped_write)
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise
        os.set_inheritable(self.pidfd, False)
        try:
            ready, _, _ = select.select([ready_read, self.pidfd], [], [], timeout_seconds)
            if ready_read not in ready or os.read(ready_read, 1) != b"U":
                raise EssentialPrimitiveUnavailable(
                    "child did not reach subordinate mapping barrier"
                )
            _install_subordinate_maps(
                pid,
                subuid,
                subgid,
                os.getuid(),
                os.getgid(),
                test_fault == "mapping_failure",
            )
            if os.write(mapped_write, b"M") != 1:
                raise EssentialPrimitiveUnavailable("mapping release synchronization failed")
            os.close(mapped_write)
            mapped_write = -1
            _verify_stopped_child(pid, os.getpid(), subuid, subgid)
            payload, fds, credentials = _recv_packet(self._sock)
            try:
                validated, namespace_fd = self._validate_handshake(
                    payload, fds, credentials, config
                )
            except BaseException:
                _close_fds(fds)
                raise
            self.mount_namespace_fd = namespace_fd
            self.evidence = GuardianEvidence(validated)
            self._state = "active"
        except BaseException as exc:
            self._make_unknown()
            if isinstance(exc, GuardianError):
                raise
            raise EssentialPrimitiveUnavailable(f"guardian startup failed: {exc}") from exc
        finally:
            os.close(ready_read)
            if mapped_write >= 0:
                os.close(mapped_write)

    @property
    def state(self) -> str:
        return self._state

    def _validate_handshake(
        self,
        payload: dict[str, Any],
        fds: list[int],
        credentials: tuple[int, int, int],
        config: Mapping[str, Any],
    ) -> tuple[dict[str, Any], int]:
        if payload.get("type") == "startup_error":
            if fds:
                raise ProtocolRejected("startup error carried file descriptors")
            expected = {"schema", "type", "attempt_id", "nonce", "epoch", "reason"}
            _exact_object(payload, frozenset(expected), "startup error")
            raise EssentialPrimitiveUnavailable(str(payload["reason"]))
        _exact_object(payload, _HANDSHAKE_KEYS, "handshake")
        expected_child_credential = (self.pid, config["subuid"], config["subgid"])
        if credentials != expected_child_credential:
            raise ProtocolRejected("handshake SCM_CREDENTIALS did not bind the child")
        if (
            payload["schema"] != SCHEMA
            or payload["type"] != "handshake"
            or payload["attempt_id"] != self.attempt_id
            or payload["nonce"] != self.nonce
            or payload["epoch"] != self.epoch
            or payload["child_pid"] != self.pid
            or payload["socket_peercred"] != [config["parent_credential"][0], 1, 1]
            or payload["message_peercred"] != list(expected_child_credential)
            or payload["parent_namespaces"] != config["parent_namespaces"]
        ):
            raise ProtocolRejected("handshake binding mismatch")
        namespaces = _exact_object(
            payload["namespaces"], frozenset({"user", "mount"}), "namespaces"
        )
        if (
            namespaces["user"] == config["parent_namespaces"]["user"]
            or namespaces["mount"] == config["parent_namespaces"]["mount"]
        ):
            raise ProtocolRejected("child did not enter private user and mount namespaces")
        mount = _exact_object(
            payload["mount"],
            frozenset(
                {
                    "mountpoint",
                    "filesystem",
                    "requested_bytes",
                    "actual_bytes",
                    "requested_inodes",
                    "actual_inodes",
                    "nosuid",
                    "nodev",
                    "noexec",
                    "root_propagation_private",
                }
            ),
            "mount evidence",
        )
        if (
            mount
            != {
                "mountpoint": INTERNAL_MOUNT,
                "filesystem": "tmpfs",
                "requested_bytes": self.quota_bytes,
                "actual_bytes": mount["actual_bytes"],
                "requested_inodes": TMPFS_INODE_LIMIT,
                "actual_inodes": mount["actual_inodes"],
                "nosuid": True,
                "nodev": True,
                "noexec": True,
                "root_propagation_private": True,
            }
            or not isinstance(mount["actual_bytes"], int)
            or not (0 < mount["actual_bytes"] <= self.quota_bytes)
            or not isinstance(mount["actual_inodes"], int)
            or not (0 < mount["actual_inodes"] <= TMPFS_INODE_LIMIT)
        ):
            raise ProtocolRejected("mount evidence mismatch")
        security = _exact_object(
            payload["security"],
            frozenset(
                {
                    "dumpable",
                    "no_new_privs",
                    "cap_inh",
                    "cap_prm",
                    "cap_eff",
                    "cap_bnd",
                    "cap_amb",
                    "securebits",
                    "groups",
                    "setgroups",
                    "tracer_pid",
                    "pdeathsig",
                    "inherited_dumpable",
                    "uid_map",
                    "gid_map",
                }
            ),
            "security evidence",
        )
        if (
            security["dumpable"] != 0
            or security["no_new_privs"] != 1
            or security["securebits"] != SECUREBITS_LOCKED_ZERO_CAPS
            or security["groups"] != ""
            or security["setgroups"] != "allow"
            or security["tracer_pid"] != 0
            or security["pdeathsig"] != signal.SIGKILL
            or security["inherited_dumpable"] != 0
        ):
            raise ProtocolRejected("security evidence mismatch")
        for name in ("cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb"):
            if security[name] != "0000000000000000":
                raise ProtocolRejected(f"security evidence {name} is not zero")
        if security["uid_map"].split() != [
            "0",
            str(config["subuid"]),
            "1",
            "1",
            str(config["host_uid"]),
            "1",
        ]:
            raise ProtocolRejected("uid map evidence mismatch")
        if security["gid_map"].split() != [
            "0",
            str(config["subgid"]),
            "1",
            "1",
            str(config["host_gid"]),
            "1",
        ]:
            raise ProtocolRejected("gid map evidence mismatch")
        for name in ("uid_map", "gid_map"):
            if not isinstance(security[name], str) or not security[name]:
                raise ProtocolRejected(f"security evidence {name} is invalid")
        fd_inventory = _exact_object(
            payload["fd_inventory"],
            frozenset({"after_inherited_close", "post_bootstrap_open_fds"}),
            "FD inventory",
        )
        inherited = fd_inventory["after_inherited_close"]
        if not isinstance(inherited, list) or len(inherited) != 3:
            raise ProtocolRejected("inherited FD inventory mismatch")
        inherited_kinds: list[str] = []
        socket_fds: list[int] = []
        for item in inherited:
            if (
                not isinstance(item, dict)
                or set(item) != {"fd", "kind"}
                or not isinstance(item["fd"], int)
                or item["kind"] not in {"pipe", "socket"}
            ):
                raise ProtocolRejected("inherited FD inventory mismatch")
            inherited_kinds.append(item["kind"])
            if item["kind"] == "socket":
                socket_fds.append(item["fd"])
        if sorted(inherited_kinds) != ["pipe", "pipe", "socket"]:
            raise ProtocolRejected("inherited FD inventory mismatch")
        if fd_inventory["post_bootstrap_open_fds"] != socket_fds:
            raise ProtocolRejected("post-bootstrap FD inventory mismatch")
        recovery_root = _exact_object(
            payload["recovery_root"],
            frozenset({"fd_number", "device", "inode", "mode", "mount_id"}),
            "recovery root evidence",
        )
        if (
            not isinstance(recovery_root["fd_number"], int)
            or recovery_root["fd_number"] < 0
            or recovery_root["mode"] != 0o700
            or not isinstance(recovery_root["mount_id"], int)
            or recovery_root["mount_id"] <= 0
        ):
            raise ProtocolRejected("recovery root evidence mismatch")
        namespace_handle = _exact_object(
            payload["namespace_handle"],
            frozenset({"device", "inode"}),
            "namespace handle evidence",
        )
        if len(fds) != 1:
            raise ProtocolRejected("handshake must transfer exactly one mount namespace FD")
        namespace_stat = os.fstat(fds[0])
        if (
            namespace_stat.st_dev != namespace_handle["device"]
            or namespace_stat.st_ino != namespace_handle["inode"]
        ):
            raise ProtocolRejected("mount namespace FD identity mismatch")
        namespace_filesystem = _StatFs()
        if _libc.fstatfs(fds[0], ctypes.byref(namespace_filesystem)) != 0:
            _raise_errno("fstatfs(namespace FD)")
        if namespace_filesystem.f_type != NSFS_MAGIC:
            raise ProtocolRejected("namespace FD is not nsfs")
        if fcntl.ioctl(fds[0], NS_GET_NSTYPE) != CLONE_NEWNS:
            raise ProtocolRejected("namespace FD is not a mount namespace")
        return payload, fds.pop()

    def _assert_active(self) -> None:
        if self._state != "active":
            raise TerminalStateError(f"guardian is not active: {self._state}")

    def _exchange(
        self, packet: Mapping[str, Any], fds: Sequence[int] = ()
    ) -> tuple[dict[str, Any], list[int]]:
        self._assert_active()
        try:
            _send_packet(self._sock, packet, fds)
            response, response_fds, credentials = _recv_packet(self._sock)
        except (TimeoutError, EOFError, BrokenPipeError, ConnectionError, OSError) as exc:
            self._make_unknown()
            raise UnknownOutcomeError("control EOF/death before terminal success") from exc
        expected_credentials = (self.pid, self.subuid, self.subgid)
        if credentials != expected_credentials:
            _close_fds(response_fds)
            self._make_unknown()
            raise ProtocolRejected("response SCM_CREDENTIALS mismatch")
        return response, response_fds

    def _request(self, packet_type: str, **extra: Any) -> tuple[dict[str, Any], list[int]]:
        request_id = secrets.token_hex(16)
        request = {
            "schema": SCHEMA,
            "type": packet_type,
            "attempt_id": self.attempt_id,
            "nonce": self.nonce,
            "epoch": self.epoch,
            "request_id": request_id,
            **extra,
        }
        response, fds = self._exchange(request)
        response_type = response.get("type")
        if response_type == "rejected":
            _close_fds(fds)
            expected = _BINDING_KEYS | {"code"}
            _exact_object(response, frozenset(expected), "rejection")
            if any(response[key] != request[key] for key in _BINDING_KEYS - {"type"}):
                self._make_unknown()
                raise ProtocolRejected("rejection binding mismatch")
            code = str(response["code"])
            if code in {"live_lease", "live_export"}:
                raise LiveLeaseError(code)
            raise ProtocolRejected(code)
        for key in _BINDING_KEYS - {"type"}:
            if response.get(key) != request[key]:
                _close_fds(fds)
                self._make_unknown()
                raise ProtocolRejected("response binding mismatch")
        return response, fds

    def request_lease(self) -> DirectoryLease:
        self._assert_active()
        response, fds = self._request("lease_request")
        expected = _BINDING_KEYS | {"lease_id"}
        try:
            _exact_object(response, frozenset(expected), "lease response")
            if response["type"] != "lease_granted" or len(fds) != 1:
                raise ProtocolRejected("lease response must transfer exactly one FD")
            descriptor_stat = os.fstat(fds[0])
            root = self.evidence.payload["recovery_root"]
            if (
                not stat.S_ISDIR(descriptor_stat.st_mode)
                or descriptor_stat.st_dev != root["device"]
                or descriptor_stat.st_ino != root["inode"]
            ):
                raise ProtocolRejected("lease FD is not the exact recovery directory")
            lease_id = response["lease_id"]
            if not isinstance(lease_id, str) or len(lease_id) != 64:
                raise ProtocolRejected("lease id is invalid")
            lease = DirectoryLease(self, fds.pop(), lease_id)
            self._lease = lease
            return lease
        except BaseException:
            _close_fds(fds)
            self._make_unknown()
            raise

    def _release_lease(self, lease_id: str) -> None:
        fds: list[int] = []
        try:
            response, fds = self._request("lease_release", lease_id=lease_id)
            _exact_object(response, _BINDING_KEYS, "lease release response")
            if response["type"] != "lease_released" or fds:
                raise ProtocolRejected("lease release response is invalid")
            self._lease = None
        except BaseException:
            self._make_unknown()
            raise
        finally:
            _close_fds(fds)

    def request_export(self) -> SealedRecoveryExport:
        if not getattr(self, "_test_mode", False):
            raise PermissionError("raw guardian export is private/internal/test-only")
        self._assert_active()
        if self._lease is not None and not self._lease.released:
            raise LiveLeaseError("live_lease")
        self._assert_no_local_duplicate_lease_fds()
        response, fds = self._request("export_request")
        try:
            export = self._validate_export_response(response, fds)
            fds.remove(export.fd)
            self._export = export
            return export
        except BaseException:
            _close_fds(fds)
            self._make_unknown()
            raise

    def _validate_export_response(
        self, response: dict[str, Any], fds: list[int]
    ) -> SealedRecoveryExport:
        _exact_object(response, _EXPORT_RESPONSE_KEYS, "export response")
        if response["type"] != "export_granted" or len(fds) != 1:
            raise ProtocolRejected("export response must transfer exactly one FD")
        export_id = response["export_id"]
        if not isinstance(export_id, str) or len(export_id) != 64:
            raise ProtocolRejected("export id is invalid")
        capsule_digest = response["capsule_digest"]
        content_digest = response["content_digest"]
        capsule_digest = _strict_sha256(capsule_digest, "capsule digest")
        content_digest = _strict_sha256(content_digest, "content digest")
        fd = fds[0]
        descriptor_stat = os.fstat(fd)
        if not stat.S_ISREG(descriptor_stat.st_mode) or descriptor_stat.st_nlink != 0:
            raise ProtocolRejected("export FD is not an anonymous memfd regular file")
        capsule_size = _strict_int(
            response["capsule_size"],
            "capsule size",
            minimum=1,
            maximum=_max_export_capsule_bytes(self.quota_bytes),
        )
        if descriptor_stat.st_size != capsule_size:
            raise ProtocolRejected("export capsule size mismatch")
        seals = fcntl.fcntl(fd, F_GET_SEALS)
        if seals != EXPORT_SEALS or _strict_int(response["seals"], "seals") != EXPORT_SEALS:
            raise ProtocolRejected("export memfd seals mismatch")
        if os.lseek(fd, 0, os.SEEK_SET) != 0:
            raise ProtocolRejected("export memfd seek failed")
        body = b""
        while len(body) < capsule_size:
            chunk = os.read(fd, capsule_size - len(body))
            if not chunk:
                break
            body += chunk
        if len(body) != capsule_size or os.read(fd, 1):
            raise ProtocolRejected("export memfd content size mismatch")
        if hashlib.sha256(body).hexdigest() != capsule_digest:
            raise ProtocolRejected("export capsule digest mismatch")
        try:
            capsule = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolRejected("export capsule is not JSON") from exc
        if not isinstance(capsule, dict) or _canonical_packet(capsule) != body:
            raise ProtocolRejected("export capsule is not canonical JSON")
        expected_capsule_keys = frozenset(
            {
                "schema",
                "type",
                "attempt_id",
                "nonce",
                "epoch",
                "source_root",
                "byte_count",
                "inode_count",
                "entry_count",
                "content_digest",
                "entries",
                "truth_boundary",
            }
        )
        _exact_object(capsule, expected_capsule_keys, "export capsule")
        root = self.evidence.payload["recovery_root"]
        expected_source_root = {
            "device": root["device"],
            "inode": root["inode"],
            "mode": root["mode"],
            "mount_id": root["mount_id"],
            "namespace": self.evidence.payload["namespaces"]["mount"],
        }
        if (
            capsule["schema"] != EXPORT_SCHEMA
            or capsule["type"] != "recovery_export_capsule"
            or capsule["attempt_id"] != self.attempt_id
            or capsule["nonce"] != self.nonce
            or capsule["epoch"] != self.epoch
            or capsule["source_root"] != expected_source_root
            or response["source_root"] != expected_source_root
            or capsule["truth_boundary"] != _TRUTH_BOUNDARY
            or response["truth_boundary"] != _TRUTH_BOUNDARY
        ):
            raise ProtocolRejected("export capsule binding mismatch")
        for key in ("byte_count", "inode_count", "entry_count", "content_digest"):
            if response[key] != capsule[key]:
                raise ProtocolRejected("export response metadata mismatch")
        byte_count = _strict_int(
            capsule["byte_count"], "byte count", minimum=0, maximum=self.quota_bytes
        )
        inode_count = _strict_int(
            capsule["inode_count"], "inode count", minimum=1, maximum=TMPFS_INODE_LIMIT
        )
        entry_count = _strict_int(
            capsule["entry_count"],
            "entry count",
            minimum=0,
            maximum=TMPFS_INODE_LIMIT - 1,
        )
        if inode_count != entry_count + 1:
            raise ProtocolRejected("export inode count does not match entries")
        entries = capsule["entries"]
        if not isinstance(entries, list) or len(entries) != entry_count:
            raise ProtocolRejected("export entry count mismatch")
        seen_paths: set[str] = set()
        known_directories = {""}
        total_bytes = 0
        for entry in entries:
            if not isinstance(entry, dict) or "kind" not in entry or "path" not in entry:
                raise ProtocolRejected("export entry is malformed")
            kind = entry["kind"]
            path = _validate_export_relative_path(entry["path"], known_directories)
            if not isinstance(path, str) or path in seen_paths:
                raise ProtocolRejected("export entry path is invalid")
            seen_paths.add(path)
            if kind == "dir":
                _exact_object(
                    entry, frozenset({"path", "kind", "mode", "device", "inode"}), "dir entry"
                )
                _strict_int(entry["mode"], "directory mode", minimum=0, maximum=0o777)
                if (
                    _strict_int(entry["device"], "directory device")
                    != expected_source_root["device"]
                ):
                    raise ProtocolRejected("directory device does not match source root")
                _strict_int(entry["inode"], "directory inode", minimum=1)
                known_directories.add(path)
            elif kind == "file":
                _exact_object(
                    entry,
                    frozenset(
                        {
                            "path",
                            "kind",
                            "mode",
                            "device",
                            "inode",
                            "size",
                            "nlink",
                            "sha256",
                            "content_b64",
                        }
                    ),
                    "file entry",
                )
                _strict_int(entry["mode"], "file mode", minimum=0, maximum=0o777)
                if _strict_int(entry["device"], "file device") != expected_source_root["device"]:
                    raise ProtocolRejected("file device does not match source root")
                _strict_int(entry["inode"], "file inode", minimum=1)
                size = _strict_int(entry["size"], "file size", minimum=0, maximum=byte_count)
                if _strict_int(entry["nlink"], "file nlink", minimum=1, maximum=1) != 1:
                    raise ProtocolRejected("export file entry is hardlinked")
                file_digest = _strict_sha256(entry["sha256"], "file sha256")
                data = _strict_b64(entry["content_b64"], "file content", maximum_decoded=size)
                if len(data) != size or hashlib.sha256(data).hexdigest() != file_digest:
                    raise ProtocolRejected("export file content digest mismatch")
                total_bytes += len(data)
            else:
                raise ProtocolRejected("export entry type is unsupported")
        if total_bytes != byte_count or _logical_content_digest(entries) != content_digest:
            raise ProtocolRejected("export content digest mismatch")
        os.lseek(fd, 0, os.SEEK_SET)
        if (
            self.pidfd >= 0
            and select.select([self.pidfd], [], [], min(0.05, self._timeout_seconds))[0]
        ):
            raise UnknownOutcomeError("child exited before export could remain live")
        metadata = dict(response)
        metadata["capsule"] = capsule
        return SealedRecoveryExport(self, fd, export_id, capsule_digest, metadata)

    def _release_export(self, export_id: str, capsule_digest: str) -> None:
        fds: list[int] = []
        try:
            response, fds = self._request(
                "export_release", export_id=export_id, capsule_digest=capsule_digest
            )
            _exact_object(response, _BINDING_KEYS, "export release response")
            if response["type"] != "export_released" or fds:
                raise ProtocolRejected("export release response is invalid")
            self._export = None
        except BaseException:
            self._make_unknown()
            raise
        finally:
            _close_fds(fds)

    def finalize(self) -> None:
        self._assert_active()
        try:
            self._assert_no_local_duplicate_lease_fds()
            self._assert_no_local_duplicate_export_fds(-1)
            self._assert_no_local_duplicate_namespace_fds()
            response, fds = self._request("finalize")
            _exact_object(response, _BINDING_KEYS, "finalize response")
            if response["type"] != "finalized" or fds:
                raise ProtocolRejected("terminal response is invalid")
            os.close(self.mount_namespace_fd)
            self.mount_namespace_fd = -1
            if not select.select([self.pidfd], [], [], self._timeout_seconds)[0]:
                raise UnknownOutcomeError("child did not exit after terminal response")
            waited_pid, status_code = os.waitpid(self.pid, 0)
            if waited_pid != self.pid or os.waitstatus_to_exitcode(status_code) != 0:
                self._make_unknown(reap=False)
                raise UnknownOutcomeError("child did not exit zero after terminal response")
            self._state = "success"
            self._sock.close()
            self._close_pidfd_terminal()
        except LiveLeaseError:
            raise
        except BaseException:
            self._make_unknown()
            raise
        finally:
            fds = locals().get("fds", [])
            _close_fds(fds)

    def pidfd_ready(self) -> bool:
        if self.pidfd < 0:
            return bool(self.terminal_pidfd_ready)
        return bool(select.select([self.pidfd], [], [], 0)[0])

    def _close_pidfd_terminal(self) -> None:
        if self.pidfd < 0:
            return
        self.terminal_pidfd_ready = bool(select.select([self.pidfd], [], [], 0)[0])
        os.close(self.pidfd)
        self.pidfd = -1

    def _assert_no_local_duplicate_lease_fds(self) -> None:
        root = self.evidence.payload["recovery_root"]
        duplicates: list[int] = []
        intended_lease_fd = (
            self._lease.fd if self._lease is not None and not self._lease.released else -1
        )
        for value in os.listdir("/proc/self/fd"):
            fd = int(value)
            if fd in {
                self.pidfd,
                self.mount_namespace_fd,
                self._sock.fileno(),
                intended_lease_fd,
            }:
                continue
            try:
                descriptor_stat = os.fstat(fd)
            except OSError:
                continue
            if (descriptor_stat.st_dev, descriptor_stat.st_ino) == (
                root["device"],
                root["inode"],
            ):
                duplicates.append(fd)
        if duplicates:
            raise LiveLeaseError(f"duplicate_lease_fd:{duplicates}")

    def _assert_no_local_duplicate_export_fds(self, intended_export_fd: int) -> None:
        export = self._export
        if export is None and intended_export_fd < 0:
            return
        target_fd = intended_export_fd
        if target_fd < 0 and export is not None and not export.released:
            target_fd = export.fd
        if target_fd < 0:
            return
        try:
            target_stat = os.fstat(target_fd)
        except OSError:
            raise LiveLeaseError("export_fd_not_open") from None
        duplicates: list[int] = []
        for value in os.listdir("/proc/self/fd"):
            fd = int(value)
            if fd in {
                target_fd,
                self.pidfd,
                self.mount_namespace_fd,
                self._sock.fileno(),
            }:
                continue
            try:
                descriptor_stat = os.fstat(fd)
            except OSError:
                continue
            if (descriptor_stat.st_dev, descriptor_stat.st_ino) == (
                target_stat.st_dev,
                target_stat.st_ino,
            ):
                duplicates.append(fd)
        if duplicates:
            raise LiveLeaseError(f"duplicate_export_fd:{duplicates}")

    def _assert_no_local_duplicate_namespace_fds(self) -> None:
        namespace = self.evidence.payload["namespace_handle"]
        duplicates: list[int] = []
        for value in os.listdir("/proc/self/fd"):
            fd = int(value)
            if fd == self.mount_namespace_fd:
                continue
            try:
                descriptor_stat = os.fstat(fd)
            except OSError:
                continue
            if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
                namespace["device"],
                namespace["inode"],
            ):
                continue
            namespace_filesystem = _StatFs()
            if _libc.fstatfs(fd, ctypes.byref(namespace_filesystem)) != 0:
                _raise_errno("fstatfs(duplicate namespace FD)")
            if (
                namespace_filesystem.f_type == NSFS_MAGIC
                and fcntl.ioctl(fd, NS_GET_NSTYPE) == CLONE_NEWNS
            ):
                duplicates.append(fd)
        if duplicates:
            raise LiveLeaseError(f"duplicate_mount_namespace_fd:{duplicates}")

    def _make_unknown(self, *, reap: bool = True) -> None:
        if self._state == "success":
            return
        self._state = "unknown"
        try:
            self._sock.close()
        except BaseException:
            pass
        namespace_fd = getattr(self, "mount_namespace_fd", -1)
        if namespace_fd >= 0:
            os.close(namespace_fd)
            self.mount_namespace_fd = -1
        export = getattr(self, "_export", None)
        if export is not None and not export.released and export.fd >= 0:
            try:
                os.close(export.fd)
            except OSError:
                pass
            export.fd = -1
        if self.pidfd >= 0:
            try:
                pidfd_send_signal(self.pidfd, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        if reap:
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
        self._close_pidfd_terminal()

    def abort(self) -> None:
        if self._state in {"active", "starting"}:
            self._make_unknown()

    def test_exchange(
        self, packet: Mapping[str, Any], send_fds: Sequence[int] = ()
    ) -> tuple[dict[str, Any], list[int]]:
        """Send a deliberately malformed packet; available only in explicit test mode."""

        # The attribute is inferred from the presence of the test-only configuration marker.
        if not getattr(self, "_test_mode", False):
            raise PermissionError("test_exchange requires explicit test_mode")
        return self._exchange(packet, send_fds)

    def close_control_for_test(self) -> None:
        """Cause control EOF; available only in explicit test mode."""

        if not getattr(self, "_test_mode", False):
            raise PermissionError("close_control_for_test requires explicit test_mode")
        self._sock.close()
        self._make_unknown()

    def __enter__(self) -> RecoveryNamespaceGuardian:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._state == "active":
            self.abort()

    def __del__(self) -> None:
        try:
            if getattr(self, "_state", "") == "active":
                self.abort()
            pidfd = getattr(self, "pidfd", -1)
            if pidfd >= 0:
                os.close(pidfd)
                self.pidfd = -1
            namespace_fd = getattr(self, "mount_namespace_fd", -1)
            if namespace_fd >= 0:
                os.close(namespace_fd)
                self.mount_namespace_fd = -1
            export = getattr(self, "_export", None)
            if export is not None and not export.released and export.fd >= 0:
                os.close(export.fd)
                export.fd = -1
        except BaseException:
            pass


@dataclass(frozen=True)
class BrokeredRecoveryArtifact:
    """Detached post-terminal sealed artifact received from the exec broker."""

    fd: int
    metadata: dict[str, Any]


def _broker_binding(
    attempt_id: str, nonce: str, packet_type: str, request_id: str
) -> dict[str, Any]:
    return {
        "schema": BROKER_SCHEMA,
        "type": packet_type,
        "attempt_id": attempt_id,
        "nonce": nonce,
        "request_id": request_id,
    }


def _broker_reject(
    sock: socket.socket, attempt_id: str, nonce: str, request_id: str, code: str
) -> None:
    _send_packet(sock, {**_broker_binding(attempt_id, nonce, "rejected", request_id), "code": code})


def _broker_validate_binding(packet: Mapping[str, Any], attempt_id: str, nonce: str) -> str:
    if not (
        packet.get("schema") == BROKER_SCHEMA
        and packet.get("attempt_id") == attempt_id
        and packet.get("nonce") == nonce
        and isinstance(packet.get("request_id"), str)
        and packet["request_id"]
    ):
        raise ProtocolRejected("broker binding mismatch")
    return str(packet["request_id"])


def _parent_path(path: str) -> tuple[str, str]:
    normalized = _validate_export_relative_path(path, {""} | set(path.rsplit("/", 1)[:1]))
    if "/" not in normalized:
        return "", normalized
    parent, leaf = normalized.rsplit("/", 1)
    return parent, leaf


def _open_broker_dir(root_fd: int, path: str, known_directories: set[str]) -> int:
    if path not in known_directories:
        raise ProtocolRejected("broker parent directory was not created")
    fd = os.dup(root_fd)
    try:
        if path:
            for component in path.split("/"):
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_fd_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            raise ProtocolRejected("artifact FD ended before expected size")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise ProtocolRejected("artifact FD exceeded expected size")
    return b"".join(chunks)


def _validate_detached_memfd(fd: int, metadata: Mapping[str, Any]) -> bytes:
    size = _strict_int(metadata.get("capsule_size"), "detached capsule size", minimum=1)
    expected_digest = _strict_sha256(metadata.get("capsule_digest"), "detached capsule digest")
    if "seals" in metadata and _strict_int(metadata["seals"], "detached seals") != EXPORT_SEALS:
        raise ProtocolRejected("detached artifact metadata seals mismatch")
    descriptor_stat = os.fstat(fd)
    if not stat.S_ISREG(descriptor_stat.st_mode) or descriptor_stat.st_nlink != 0:
        raise ProtocolRejected("detached artifact is not an anonymous memfd")
    if descriptor_stat.st_size != size:
        raise ProtocolRejected("detached artifact size mismatch")
    if not (fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
        raise ProtocolRejected("detached artifact lacks FD_CLOEXEC")
    if fcntl.fcntl(fd, F_GET_SEALS) != EXPORT_SEALS:
        raise ProtocolRejected("detached artifact seals mismatch")
    os.lseek(fd, 0, os.SEEK_SET)
    body = _read_fd_exact(fd, size)
    if hashlib.sha256(body).hexdigest() != expected_digest:
        raise ProtocolRejected("detached artifact digest mismatch")
    os.lseek(fd, 0, os.SEEK_SET)
    return body


def _validate_broker_artifact(
    response: Mapping[str, Any], fd: int, *, attempt_id: str, nonce: str, request_id: str
) -> bytes:
    _exact_object(response, _BROKER_ARTIFACT_KEYS, "broker artifact response")
    if (
        response["schema"] != BROKER_SCHEMA
        or response["type"] != "artifact"
        or response["attempt_id"] != attempt_id
        or response["nonce"] != nonce
        or response["request_id"] != request_id
        or response["commit"] != "post_terminal"
        or response["artifact"] != "received"
        or response["truth_boundary"] != _TRUTH_BOUNDARY
    ):
        raise ProtocolRejected("broker artifact binding mismatch")
    _strict_text(response["epoch"], "broker artifact epoch")
    capsule_nonce = _strict_text(response["capsule_nonce"], "broker capsule nonce")
    _strict_sha256(response["content_digest"], "broker content digest")
    body = _validate_detached_memfd(fd, response)
    capsule = _validate_export_capsule_body(
        body,
        attempt_id=attempt_id,
        capsule_nonce=capsule_nonce,
        expected_digest=_strict_sha256(response["capsule_digest"], "broker capsule digest"),
    )
    if (
        capsule["epoch"] != response["epoch"]
        or capsule["content_digest"] != response["content_digest"]
    ):
        raise ProtocolRejected("broker artifact capsule metadata mismatch")
    return body


def _broker_send_error(sock: socket.socket, attempt_id: str, nonce: str, code: str) -> NoReturn:
    try:
        _send_packet(
            sock,
            {
                **_broker_binding(attempt_id, nonce, "fatal", secrets.token_hex(16)),
                "code": code,
                "commit": "unknown",
                "artifact": "not_received",
            },
        )
    except BaseException:
        pass
    os._exit(98)


def _broker_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _broker_script_path() -> str:
    path = os.path.abspath(__file__)
    if not os.path.isfile(path):
        raise EssentialPrimitiveUnavailable("broker script path is unavailable")
    return path


def _broker_script_entry(argv: Sequence[str]) -> NoReturn:
    if len(argv) != 3 or argv[1] != BROKER_MAIN_ARG:
        if len(argv) == 3 and argv[1] == COURIER_MAIN_ARG:
            if _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
                os._exit(99)
            try:
                fd = _strict_int(int(argv[2]), "courier fd", minimum=3)
            except BaseException:
                os._exit(99)
            _courier_main(fd)
        os._exit(99)
    if _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        os._exit(99)
    try:
        fd = _strict_int(int(argv[2]), "broker fd", minimum=3)
    except BaseException:
        os._exit(99)
    _broker_main(fd)


class _OwnedProcess:
    def __init__(self, process: subprocess.Popen[Any], sock: socket.socket) -> None:
        self.process = process
        self.sock = sock
        self.pid = process.pid
        self.pidfd = -1
        self.reaped = False
        self.status: int | None = None
        try:
            self.pidfd = _pidfd_open(self.pid)
            os.set_inheritable(self.pidfd, False)
        except BaseException:
            self.close(kill=True, timeout=1.0)
            raise

    def wait(self, timeout: float, *, require_zero: bool) -> int:
        if self.reaped:
            if self.status is None:
                raise UnknownOutcomeError("process wait status is unavailable")
            return self.status
        if self.pidfd < 0:
            raise UnknownOutcomeError("process pidfd is unavailable")
        if not select.select([self.pidfd], [], [], timeout)[0]:
            raise UnknownOutcomeError("artifact_not_received:commit_unknown")
        waited_pid, status = os.waitpid(self.pid, 0)
        if waited_pid != self.pid:
            raise UnknownOutcomeError("artifact_not_received:commit_unknown")
        self.status = status
        self.reaped = True
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1
        if require_zero and (not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0):
            raise UnknownOutcomeError("artifact_not_received:commit_unknown")
        return status

    def close(self, *, kill: bool, timeout: float) -> None:
        try:
            self.sock.close()
        except BaseException:
            pass
        if kill and not self.reaped:
            if self.pidfd >= 0:
                try:
                    pidfd_send_signal(self.pidfd, signal.SIGKILL)
                except OSError as exc:
                    if exc.errno not in (errno.ESRCH, errno.EINVAL):
                        raise
            else:
                try:
                    self.process.kill()
                except OSError:
                    pass
        if not self.reaped:
            try:
                self.process.wait(timeout=timeout)
                self.reaped = True
            except subprocess.TimeoutExpired:
                if not kill:
                    raise
                self.process.kill()
                self.process.wait(timeout=timeout)
                self.reaped = True
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1


def _launch_isolated_process(mode: str, timeout_seconds: float) -> _OwnedProcess:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    parent.settimeout(timeout_seconds)
    child.settimeout(None)
    try:
        process = subprocess.Popen(
            [
                os.path.abspath(sys.executable),
                "-I",
                "-S",
                _broker_script_path(),
                mode,
                str(child.fileno()),
            ],
            env=_broker_env(),
            close_fds=True,
            pass_fds=(child.fileno(),),
            shell=False,
        )
        child.close()
        return _OwnedProcess(process, parent)
    except BaseException:
        parent.close()
        child.close()
        raise


def _send_fatal_then_exit(sock: socket.socket, attempt_id: str, nonce: str, code: str) -> NoReturn:
    _broker_send_error(sock, attempt_id, nonce, code)


def _courier_recv_response(
    worker: _OwnedProcess, request: Mapping[str, Any]
) -> tuple[dict[str, Any], list[int]]:
    response, fds, credentials = _recv_packet(worker.sock)
    if credentials != (worker.pid, os.getuid(), os.getgid()):
        _close_fds(fds)
        raise ProtocolRejected("worker response credentials mismatch")
    for key in _BROKER_BINDING_KEYS - {"type"}:
        if response.get(key) != request[key]:
            _close_fds(fds)
            raise ProtocolRejected("worker response binding mismatch")
    return response, fds


def _courier_forward_nonterminal(
    parent_sock: socket.socket,
    worker: _OwnedProcess,
    packet: Mapping[str, Any],
    *,
    timeout_seconds: float,
) -> None:
    _send_packet(worker.sock, packet)
    response, fds = _courier_recv_response(worker, packet)
    try:
        if fds:
            raise ProtocolRejected("worker sent unexpected nonterminal fd")
        if response.get("type") == "fatal":
            _send_packet(parent_sock, response)
            worker.wait(timeout_seconds, require_zero=False)
            os._exit(98)
        _send_packet(parent_sock, response)
    finally:
        _close_fds(fds)


def _courier_main(sock_fd: int) -> NoReturn:
    parent_sock = socket.socket(fileno=sock_fd)
    parent_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    attempt_id = "unknown"
    nonce = "unknown"
    worker: _OwnedProcess | None = None
    try:
        hello, fds, credentials = _recv_packet(parent_sock)
        _close_fds(fds)
        if set(hello) != {
            "schema",
            "type",
            "attempt_id",
            "nonce",
            "request_id",
            "quota_bytes",
            "test_mode",
            "test_fault",
        }:
            os._exit(99)
        attempt_id = _strict_text(hello["attempt_id"], "courier attempt_id")
        nonce = _strict_text(hello["nonce"], "courier nonce")
        request_id = _broker_validate_binding(hello, attempt_id, nonce)
        if hello["type"] != "start" or credentials[1:] != (os.getuid(), os.getgid()):
            os._exit(99)
        parent_credentials = credentials
        if _peercred(parent_sock) != parent_credentials:
            os._exit(99)
        timeout_seconds = 5.0
        worker = _launch_isolated_process(BROKER_MAIN_ARG, timeout_seconds)
        _send_packet(worker.sock, hello)
        response, response_fds = _courier_recv_response(worker, hello)
        try:
            if response_fds:
                raise ProtocolRejected("worker start sent fds")
            _exact_object(response, _BROKER_BINDING_KEYS, "worker start response")
            if response["type"] != "started":
                raise ProtocolRejected("worker did not start")
            _send_packet(parent_sock, _broker_binding(attempt_id, nonce, "started", request_id))
        finally:
            _close_fds(response_fds)

        while True:
            packet, packet_fds, credentials = _recv_packet(parent_sock)
            packet_request_id = packet.get("request_id")
            request_id = (
                packet_request_id
                if isinstance(packet_request_id, str) and packet_request_id
                else "invalid"
            )
            try:
                if packet_fds:
                    _broker_reject(
                        parent_sock, attempt_id, nonce, request_id, "unexpected_ancillary_fds"
                    )
                    continue
                if (
                    credentials != parent_credentials
                    or _peercred(parent_sock) != parent_credentials
                ):
                    _broker_reject(
                        parent_sock, attempt_id, nonce, request_id, "peer_credentials_mismatch"
                    )
                    continue
                _broker_validate_binding(packet, attempt_id, nonce)
                if packet.get("type") != "export":
                    _courier_forward_nonterminal(
                        parent_sock, worker, packet, timeout_seconds=timeout_seconds
                    )
                    continue
                if set(packet) != _BROKER_BINDING_KEYS:
                    _broker_reject(parent_sock, attempt_id, nonce, request_id, "non_exact_export")
                    continue
                _send_packet(worker.sock, packet)
                worker.wait(timeout_seconds, require_zero=True)
                response, response_fds = _courier_recv_response(worker, packet)
                try:
                    if len(response_fds) != 1:
                        raise ProtocolRejected("worker artifact must send one fd")
                    _validate_broker_artifact(
                        response,
                        response_fds[0],
                        attempt_id=attempt_id,
                        nonce=nonce,
                        request_id=request_id,
                    )
                    if hello["test_fault"] == "courier_exit_42_after_artifact":
                        _send_packet(parent_sock, response, [response_fds[0]])
                        os._exit(42)
                    _send_packet(parent_sock, response, [response_fds[0]])
                    os._exit(0)
                finally:
                    _close_fds(response_fds)
            finally:
                _close_fds(packet_fds)
    except BaseException as exc:
        if worker is not None:
            try:
                worker.close(kill=True, timeout=1.0)
            except BaseException:
                pass
        _send_fatal_then_exit(parent_sock, attempt_id, nonce, f"{type(exc).__name__}:{exc}")


def _broker_main(sock_fd: int) -> NoReturn:
    sock = socket.socket(fileno=sock_fd)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    attempt_id = "unknown"
    nonce = "unknown"
    guardian: RecoveryNamespaceGuardian | None = None
    lease: DirectoryLease | None = None
    internal_export: SealedRecoveryExport | None = None
    detached_fd = -1
    try:
        if _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            _raise_errno("broker prctl(PR_SET_DUMPABLE)")
        hello, fds, credentials = _recv_packet(sock)
        _close_fds(fds)
        if set(hello) != {
            "schema",
            "type",
            "attempt_id",
            "nonce",
            "request_id",
            "quota_bytes",
            "test_mode",
            "test_fault",
        }:
            os._exit(99)
        attempt_id = _strict_text(hello["attempt_id"], "broker attempt_id")
        nonce = _strict_text(hello["nonce"], "broker nonce")
        request_id = _broker_validate_binding(hello, attempt_id, nonce)
        if hello["type"] != "start" or credentials[1:] != (os.getuid(), os.getgid()):
            os._exit(99)
        parent_credentials = credentials
        if _peercred(sock) != parent_credentials:
            os._exit(99)
        quota_bytes = _strict_int(
            hello["quota_bytes"], "broker quota", minimum=16 * 1024, maximum=MAX_QUOTA_BYTES
        )
        if type(hello["test_mode"]) is not bool:
            raise ProtocolRejected("broker test_mode must be bool")
        test_mode = hello["test_mode"]
        test_fault = hello["test_fault"]
        if test_fault is not None and (
            type(test_fault) is not str or not test_mode or test_fault not in _FAULTS
        ):
            raise ProtocolRejected("broker test fault is invalid")
        guardian = RecoveryNamespaceGuardian(
            attempt_id,
            quota_bytes=quota_bytes,
            test_mode=True,
            test_fault=test_fault if test_mode else None,
        )
        lease = guardian.request_lease()
        known_directories = {""}
        written_bytes = 0
        export_started = False
        _send_packet(sock, _broker_binding(attempt_id, nonce, "started", request_id))
        while True:
            packet, fds, credentials = _recv_packet(sock)
            packet_request_id = packet.get("request_id")
            request_id = (
                packet_request_id
                if isinstance(packet_request_id, str) and packet_request_id
                else "invalid"
            )
            try:
                if fds:
                    _broker_reject(sock, attempt_id, nonce, request_id, "unexpected_ancillary_fds")
                    continue
                if credentials != parent_credentials or _peercred(sock) != parent_credentials:
                    _broker_reject(sock, attempt_id, nonce, request_id, "peer_credentials_mismatch")
                    continue
                _broker_validate_binding(packet, attempt_id, nonce)
                packet_type = packet.get("type")
                if packet_type == "mkdir":
                    if set(packet) != _BROKER_BINDING_KEYS | {"path", "mode"}:
                        _broker_reject(sock, attempt_id, nonce, request_id, "non_exact_mkdir")
                        continue
                    if export_started:
                        _broker_reject(sock, attempt_id, nonce, request_id, "writes_closed")
                        continue
                    path = _strict_text(packet["path"], "directory path")
                    parent, leaf = _parent_path(path)
                    if parent not in known_directories or path in known_directories:
                        _broker_reject(sock, attempt_id, nonce, request_id, "directory_order")
                        continue
                    mode = _strict_int(packet["mode"], "directory mode", minimum=0, maximum=0o777)
                    parent_fd = _open_broker_dir(lease.fd, parent, known_directories)
                    try:
                        os.mkdir(leaf, mode, dir_fd=parent_fd)
                    finally:
                        os.close(parent_fd)
                    known_directories.add(path)
                    _send_packet(sock, _broker_binding(attempt_id, nonce, "mkdir_ok", request_id))
                elif packet_type == "put_file":
                    if set(packet) != _BROKER_BINDING_KEYS | {
                        "path",
                        "mode",
                        "content_b64",
                        "sha256",
                    }:
                        _broker_reject(sock, attempt_id, nonce, request_id, "non_exact_put_file")
                        continue
                    if export_started:
                        _broker_reject(sock, attempt_id, nonce, request_id, "writes_closed")
                        continue
                    path = _strict_text(packet["path"], "file path")
                    parent, leaf = _parent_path(path)
                    if parent not in known_directories:
                        _broker_reject(sock, attempt_id, nonce, request_id, "missing_parent")
                        continue
                    mode = _strict_int(packet["mode"], "file mode", minimum=0, maximum=0o777)
                    remaining = quota_bytes - written_bytes
                    data = _strict_b64(
                        packet["content_b64"], "file content", maximum_decoded=remaining
                    )
                    if hashlib.sha256(data).hexdigest() != _strict_sha256(
                        packet["sha256"], "file sha256"
                    ):
                        _broker_reject(
                            sock, attempt_id, nonce, request_id, "content_digest_mismatch"
                        )
                        continue
                    parent_fd = _open_broker_dir(lease.fd, parent, known_directories)
                    try:
                        file_fd = os.open(
                            leaf,
                            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            mode,
                            dir_fd=parent_fd,
                        )
                        try:
                            _write_all(file_fd, data)
                            if os.fstat(file_fd).st_size != len(data):
                                raise ProtocolRejected("broker writer size mismatch")
                        finally:
                            os.close(file_fd)
                    finally:
                        os.close(parent_fd)
                    written_bytes += len(data)
                    _send_packet(
                        sock, _broker_binding(attempt_id, nonce, "put_file_ok", request_id)
                    )
                elif packet_type == "test_sparse":
                    if not test_mode or set(packet) != _BROKER_BINDING_KEYS | {"path", "size"}:
                        _broker_reject(sock, attempt_id, nonce, request_id, "non_exact_test_sparse")
                        continue
                    _strict_text(packet["path"], "sparse path")
                    size = _strict_int(packet["size"], "sparse size", minimum=0)
                    if size > quota_bytes - written_bytes:
                        _broker_reject(sock, attempt_id, nonce, request_id, "sparse_quota")
                        continue
                    _broker_reject(sock, attempt_id, nonce, request_id, "test_sparse_disabled")
                elif packet_type == "export":
                    if set(packet) != _BROKER_BINDING_KEYS:
                        _broker_reject(sock, attempt_id, nonce, request_id, "non_exact_export")
                        continue
                    if export_started:
                        _broker_reject(sock, attempt_id, nonce, request_id, "export_replay")
                        continue
                    export_started = True
                    lease.release()
                    lease = None
                    internal_export = guardian.request_export()
                    internal_body = _read_fd_exact(
                        internal_export.fd, internal_export.metadata["capsule_size"]
                    )
                    if test_fault == "broker_artifact_bad_capsule_schema":
                        tampered = json.loads(internal_body)
                        tampered["schema"] = "acgs.invalid"
                        internal_body = _canonical_packet(tampered)
                    if test_fault == "broker_artifact_escape_path":
                        tampered = json.loads(internal_body)
                        if tampered["entries"]:
                            tampered["entries"][0]["path"] = "/escape"
                        internal_body = _canonical_packet(tampered)
                    if test_fault == "broker_artifact_string_mode":
                        tampered = json.loads(internal_body)
                        if tampered["entries"]:
                            tampered["entries"][0]["mode"] = "700"
                        internal_body = _canonical_packet(tampered)
                    if test_fault == "broker_artifact_bad_file_hash":
                        tampered = json.loads(internal_body)
                        for entry in tampered["entries"]:
                            if entry["kind"] == "file":
                                entry["sha256"] = "0" * 64
                                break
                        internal_body = _canonical_packet(tampered)
                    if test_fault == "broker_artifact_bad_base64":
                        tampered = json.loads(internal_body)
                        for entry in tampered["entries"]:
                            if entry["kind"] == "file":
                                entry["content_b64"] = "?"
                                break
                        internal_body = _canonical_packet(tampered)
                    internal_digest = hashlib.sha256(internal_body).hexdigest()
                    if (
                        test_fault
                        not in {
                            "broker_artifact_bad_capsule_schema",
                            "broker_artifact_escape_path",
                            "broker_artifact_string_mode",
                            "broker_artifact_bad_file_hash",
                            "broker_artifact_bad_base64",
                        }
                        and internal_digest != internal_export.capsule_digest
                    ):
                        raise ProtocolRejected("internal export digest mismatch")
                    if test_fault == "broker_detached_memfd_seal_failure":
                        raise ProtocolRejected("detached memfd seal failure")
                    detached_fd, _seals = _sealed_memfd_from_capsule(internal_body)
                    internal_capsule = json.loads(internal_body)
                    content_digest = _strict_sha256(
                        internal_capsule["content_digest"], "broker content digest"
                    )
                    epoch = _strict_text(internal_capsule["epoch"], "broker epoch")
                    capsule_nonce = _strict_text(internal_capsule["nonce"], "broker capsule nonce")
                    response = {
                        **_broker_binding(attempt_id, nonce, "artifact", request_id),
                        "commit": "post_terminal",
                        "artifact": "received",
                        "epoch": epoch,
                        "capsule_nonce": capsule_nonce,
                        "capsule_digest": internal_digest,
                        "capsule_size": len(internal_body),
                        "content_digest": content_digest,
                        "seals": EXPORT_SEALS,
                        "truth_boundary": _TRUTH_BOUNDARY,
                    }
                    if test_fault == "broker_artifact_bad_capsule_digest":
                        response["capsule_digest"] = "0" * 64
                    if test_fault == "broker_artifact_bool_content_digest":
                        response["content_digest"] = True
                    internal_export.release()
                    internal_export = None
                    guardian.finalize()
                    if test_fault == "broker_die_before_receipt":
                        os._exit(97)
                    _send_packet(sock, response, [detached_fd])
                    os.close(detached_fd)
                    detached_fd = -1
                    sock.close()
                    if test_fault == "broker_exit_42_after_artifact":
                        os._exit(42)
                    os._exit(0)
                else:
                    _broker_reject(sock, attempt_id, nonce, request_id, "unknown_command")
            finally:
                _close_fds(fds)
    except BaseException as exc:
        if detached_fd >= 0:
            os.close(detached_fd)
        if internal_export is not None and not internal_export.released:
            try:
                internal_export.release()
            except BaseException:
                pass
        if lease is not None and not lease.released:
            try:
                lease.release()
            except BaseException:
                pass
        if guardian is not None and guardian.state == "active":
            guardian.abort()
        _broker_send_error(sock, attempt_id, nonce, f"{type(exc).__name__}:{exc}")


class RecoveryExportBroker:
    """Public fresh-exec broker API for post-terminal sealed recovery export."""

    def __init__(
        self,
        attempt_id: str,
        *,
        quota_bytes: int = 64 * 1024,
        test_mode: bool = False,
        test_fault: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if type(attempt_id) is not str or not attempt_id or len(attempt_id) > 256:
            raise ValueError("attempt_id must be a non-empty bounded string")
        _strict_int(quota_bytes, "broker quota", minimum=16 * 1024, maximum=MAX_QUOTA_BYTES)
        if type(test_mode) is not bool:
            raise ValueError("test_mode must be a bool")
        if test_fault is not None and (
            type(test_fault) is not str or not test_mode or test_fault not in _FAULTS
        ):
            raise ValueError("test faults require explicit test_mode and a known fault")
        self.attempt_id = attempt_id
        self.nonce = secrets.token_hex(32)
        self._timeout_seconds = timeout_seconds
        self._state = "starting"
        self.pid = -1
        self.pidfd = -1
        self._wait_status: int | None = None
        self._reaped = False
        self._courier = _launch_isolated_process(COURIER_MAIN_ARG, timeout_seconds)
        self.pid = self._courier.pid
        self.pidfd = self._courier.pidfd
        self._sock = self._courier.sock
        try:
            response, fds = self._request(
                "start",
                quota_bytes=quota_bytes,
                test_mode=test_mode,
                test_fault=test_fault,
            )
            _close_fds(fds)
            _exact_object(response, _BROKER_BINDING_KEYS, "broker start response")
            if response["type"] != "started":
                raise ProtocolRejected("broker did not start")
            self._state = "open"
        except BaseException:
            self.abort()
            raise

    @property
    def state(self) -> str:
        return self._state

    def _send_request(self, packet_type: str, **extra: Any) -> dict[str, Any]:
        if self._state not in {"starting", "open"}:
            raise TerminalStateError(f"broker is not open: {self._state}")
        request = {
            **_broker_binding(self.attempt_id, self.nonce, packet_type, secrets.token_hex(16)),
            **extra,
        }
        try:
            _send_packet(self._sock, request)
        except (TimeoutError, EOFError, BrokenPipeError, ConnectionError, OSError) as exc:
            self._close_and_reap_unknown()
            raise UnknownOutcomeError("artifact_not_received:commit_unknown") from exc
        return request

    def _recv_response(self, request: Mapping[str, Any]) -> tuple[dict[str, Any], list[int]]:
        try:
            response, fds, credentials = _recv_packet(self._sock)
        except (TimeoutError, EOFError, BrokenPipeError, ConnectionError, OSError) as exc:
            self._close_and_reap_unknown()
            raise UnknownOutcomeError("artifact_not_received:commit_unknown") from exc
        expected = (self.pid, os.getuid(), os.getgid())
        if credentials != expected:
            _close_fds(fds)
            self._close_and_reap_unknown()
            raise ProtocolRejected("broker response credentials mismatch")
        if response.get("type") == "fatal":
            _close_fds(fds)
            self._close_and_reap_unknown()
            raise UnknownOutcomeError("artifact_not_received:commit_unknown")
        if response.get("type") == "rejected":
            _close_fds(fds)
            _exact_object(response, _BROKER_BINDING_KEYS | {"code"}, "broker rejection")
            raise ProtocolRejected(str(response["code"]))
        for key in _BROKER_BINDING_KEYS - {"type"}:
            if response.get(key) != request[key]:
                _close_fds(fds)
                self._close_and_reap_unknown()
                raise ProtocolRejected("broker response binding mismatch")
        return response, fds

    def _request(self, packet_type: str, **extra: Any) -> tuple[dict[str, Any], list[int]]:
        request = self._send_request(packet_type, **extra)
        return self._recv_response(request)

    def _wait_for_child(self, *, require_zero: bool) -> int:
        try:
            status = self._courier.wait(self._timeout_seconds, require_zero=require_zero)
        except UnknownOutcomeError:
            self._close_and_reap_unknown()
            raise
        self._wait_status = self._courier.status
        self._reaped = self._courier.reaped
        self.pidfd = self._courier.pidfd
        return status

    def _close_socket(self) -> None:
        try:
            self._sock.close()
        except BaseException:
            pass

    def _close_and_reap_unknown(self) -> None:
        self._state = "commit_unknown"
        self._close_socket()
        try:
            if self.pidfd >= 0 and not self._reaped:
                self._courier.close(kill=True, timeout=1.0)
            elif not self._reaped:
                self._courier.close(kill=True, timeout=1.0)
        except BaseException:
            pass
        self._wait_status = self._courier.status
        self._reaped = self._courier.reaped
        self.pidfd = self._courier.pidfd

    def mkdir(self, path: str, *, mode: int = 0o700) -> None:
        _strict_text(path, "directory path")
        _strict_int(mode, "directory mode", minimum=0, maximum=0o777)
        response, fds = self._request("mkdir", path=path, mode=mode)
        _close_fds(fds)
        _exact_object(response, _BROKER_BINDING_KEYS, "mkdir response")
        if response["type"] != "mkdir_ok":
            raise ProtocolRejected("mkdir failed")

    def put_file(self, path: str, content: bytes, *, mode: int = 0o600) -> None:
        _strict_text(path, "file path")
        content = _strict_bytes(content, "file content")
        _strict_int(mode, "file mode", minimum=0, maximum=0o777)
        if len(content) > MAX_QUOTA_BYTES:
            raise ValueError("content exceeds max quota")
        response, fds = self._request(
            "put_file",
            path=path,
            mode=mode,
            content_b64=base64.b64encode(content).decode("ascii"),
            sha256=hashlib.sha256(content).hexdigest(),
        )
        _close_fds(fds)
        _exact_object(response, _BROKER_BINDING_KEYS, "put_file response")
        if response["type"] != "put_file_ok":
            raise ProtocolRejected("put_file failed")

    def export(self) -> BrokeredRecoveryArtifact:
        request = self._send_request("export")
        try:
            self._wait_for_child(require_zero=True)
            response, fds = self._recv_response(request)
            if len(fds) != 1:
                raise ProtocolRejected("artifact response must transfer exactly one FD")
            _validate_broker_artifact(
                response,
                fds[0],
                attempt_id=self.attempt_id,
                nonce=self.nonce,
                request_id=str(request["request_id"]),
            )
            fd = fds.pop()
            self._state = "success"
            self._close_socket()
            return BrokeredRecoveryArtifact(fd=fd, metadata=dict(response))
        except BaseException:
            _close_fds(locals().get("fds", []))
            self._close_and_reap_unknown()
            raise

    def test_sparse_file(self, path: str, size: int) -> None:
        _strict_text(path, "sparse path")
        _strict_int(size, "sparse size", minimum=0)
        response, fds = self._request("test_sparse", path=path, size=size)
        _close_fds(fds)
        if response.get("type") != "sparse_ok":
            raise ProtocolRejected("sparse file rejected")

    def close(self) -> None:
        self.abort()

    def abort(self) -> None:
        if getattr(self, "_state", "") in {"starting", "open", "commit_unknown"}:
            self._close_and_reap_unknown()

    def __enter__(self) -> RecoveryExportBroker:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._state in {"starting", "open", "commit_unknown"}:
            self.abort()

    def __del__(self) -> None:
        try:
            if getattr(self, "_state", "") in {"starting", "open", "commit_unknown"}:
                self.abort()
        except BaseException:
            pass


def pidfd_getfd(pidfd: int, target_fd: int) -> int:
    """Invoke Linux ``pidfd_getfd`` directly; never falls back to ``/proc/PID/fd``."""

    result = _libc.syscall(_syscall_number("pidfd_getfd"), pidfd, target_fd, 0)
    if result < 0:
        _raise_errno("pidfd_getfd")
    return int(result)


if __name__ == "__main__":
    _broker_script_entry(sys.argv)
