"""Ephemeral, attempt-bound recovery directory isolated in Linux namespaces.

Protection begins at a dedicated, already-nondumpable broker boundary.  Same-UID
injection before that hardening boundary, host root, ``CAP_SYS_PTRACE``, host
snapshot rollback, and recovery outside the private tmpfs are excluded.  Local
terminal success also does not prove cross-process consumer quiescence; such FD
delegation is prohibited here and requires an integration-level ownership gate.
The unprivileged user namespace is owned by the ambient original UID: observed
same-UID denial is host/LSM-policy evidence, not a portable isolation guarantee,
and ambient namespace-owner authority is explicitly outside this boundary.
"""

from __future__ import annotations

import array
import ctypes
import errno
import fcntl
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
_FAULTS: Final = frozenset(
    {
        "handshake_extra_key",
        "handshake_regular_fd",
        "handshake_two_fds",
        "lease_regular_fd",
        "lease_two_fds",
        "die_before_finalize",
        "die_after_release",
        "die_after_unmount",
        "mapping_failure",
    }
)
_SYSCALL_NUMBERS: Final = {
    "x86_64": {"pidfd_send_signal": 424, "pidfd_open": 434, "pidfd_getfd": 438},
    "aarch64": {"pidfd_send_signal": 424, "pidfd_open": 434, "pidfd_getfd": 438},
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


def _child_loop(sock: socket.socket, config: Mapping[str, Any], root_fd: int) -> NoReturn:
    lease_issued = False
    live_lease_id: str | None = None
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
            elif packet_type == "finalize":
                if set(packet) != _BINDING_KEYS:
                    _reject(sock, config, request_id, "non_exact_finalize")
                elif live_lease_id is not None:
                    _reject(sock, config, request_id, "live_lease")
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
            frozenset({"fd_number", "device", "inode", "mode"}),
            "recovery root evidence",
        )
        if (
            not isinstance(recovery_root["fd_number"], int)
            or recovery_root["fd_number"] < 0
            or recovery_root["mode"] != 0o700
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
            if code == "live_lease":
                raise LiveLeaseError(code)
            raise ProtocolRejected(code)
        expected_binding = {**request, "type": response_type}
        for key in _BINDING_KEYS - {"type"}:
            if response.get(key) != expected_binding[key]:
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

    def finalize(self) -> None:
        self._assert_active()
        try:
            self._assert_no_local_duplicate_lease_fds()
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
        except BaseException:
            pass


def pidfd_getfd(pidfd: int, target_fd: int) -> int:
    """Invoke Linux ``pidfd_getfd`` directly; never falls back to ``/proc/PID/fd``."""

    result = _libc.syscall(_syscall_number("pidfd_getfd"), pidfd, target_fd, 0)
    if result < 0:
        _raise_errno("pidfd_getfd")
    return int(result)
