"""Real-host tests for the hardened recovery namespace guardian."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = ROOT / "scripts/evidence"
sys.path.insert(0, str(MODULE_DIR))

import recovery_namespace_guardian as guardian_module  # noqa: E402

SCENARIO_PROGRAM = textwrap.dedent(
    r"""
    import ctypes
    import errno
    import fcntl
    import json
    import os
    import signal
    import stat
    import subprocess
    import sys
    import textwrap
    import uuid
    from pathlib import Path

    sys.path.insert(0, sys.argv[1])
    import recovery_namespace_guardian as m

    scenario = sys.argv[2]
    if m._libc.prctl(m.PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot harden dedicated broker")

    def emit(**values):
        print(json.dumps(values, sort_keys=True), flush=True)

    def packet(g, kind, **changes):
        value = {
            "schema": m.SCHEMA,
            "type": kind,
            "attempt_id": g.attempt_id,
            "nonce": g.nonce,
            "epoch": g.epoch,
            "request_id": uuid.uuid4().hex,
        }
        value.update(changes)
        return value

    if scenario == "basic":
        g = m.RecoveryNamespaceGuardian("hardened-basic", test_mode=True)
        evidence = g.evidence.payload
        lease = g.request_lease()
        fd = os.open("round-trip", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600, dir_fd=lease.fd)
        os.write(fd, b"private-data")
        os.lseek(fd, 0, os.SEEK_SET)
        assert os.read(fd, 32) == b"private-data"
        os.close(fd)
        try:
            g.request_export()
        except m.LiveLeaseError as exc:
            live_export_refusal = str(exc)
        else:
            raise AssertionError("live lease export unexpectedly succeeded")
        try:
            g.finalize()
        except m.LiveLeaseError as exc:
            live_refusal = str(exc)
        else:
            raise AssertionError("live lease finalize unexpectedly succeeded")
        duplicate = os.dup(lease.fd)
        lease.release()
        try:
            g.finalize()
        except m.LiveLeaseError as exc:
            duplicate_refusal = str(exc)
        else:
            raise AssertionError("duplicate lease FD was not detected")
        os.close(duplicate)
        namespace_duplicate = os.dup(g.mount_namespace_fd)
        try:
            g.finalize()
        except m.LiveLeaseError as exc:
            namespace_refusal = str(exc)
        else:
            raise AssertionError("duplicate mount namespace FD was not detected")
        os.close(namespace_duplicate)
        export = g.request_export()
        export_body = os.read(export.fd, export.metadata["capsule_size"])
        export_stat = os.fstat(export.fd)
        export_seals = fcntl.fcntl(export.fd, m.F_GET_SEALS)
        try:
            os.write(export.fd, b"x")
        except OSError as exc:
            write_seal_errno = exc.errno
        else:
            raise AssertionError("sealed export memfd accepted a write")
        try:
            g.finalize()
        except m.LiveLeaseError as exc:
            live_export_finalize_refusal = str(exc)
        else:
            raise AssertionError("finalize accepted a live export")
        duplicate_export = os.dup(export.fd)
        try:
            export.release()
        except m.LiveLeaseError as exc:
            duplicate_export_release_refusal = str(exc)
        else:
            raise AssertionError("duplicate export FD did not block release")
        try:
            g.finalize()
        except m.LiveLeaseError as exc:
            duplicate_export_finalize_refusal = str(exc)
        else:
            raise AssertionError("duplicate export FD did not block finalize")
        os.close(duplicate_export)
        export.release()
        try:
            os.fstat(export.fd)
        except OSError as exc:
            released_export_errno = exc.errno
        else:
            raise AssertionError("released export FD remained open")
        g.finalize()
        try:
            g.request_lease()
        except m.TerminalStateError:
            terminal_rejected = True
        else:
            terminal_rejected = False
        emit(
            evidence=evidence,
            live_refusal=live_refusal,
            live_export_refusal=live_export_refusal,
            duplicate_refusal=duplicate_refusal,
            namespace_refusal=namespace_refusal,
            export_metadata=export.metadata,
            export_body=json.loads(export_body),
            export_stat_nlink=export_stat.st_nlink,
            export_stat_size=export_stat.st_size,
            export_seals=export_seals,
            write_seal_errno=write_seal_errno,
            live_export_finalize_refusal=live_export_finalize_refusal,
            duplicate_export_release_refusal=duplicate_export_release_refusal,
            duplicate_export_finalize_refusal=duplicate_export_finalize_refusal,
            released_export_errno=released_export_errno,
            terminal_rejected=terminal_rejected,
            state=g.state,
            pidfd=g.pidfd,
            namespace_fd=g.mount_namespace_fd,
            terminal_pidfd_ready=g.terminal_pidfd_ready,
        )
    elif scenario == "bindings":
        g = m.RecoveryNamespaceGuardian("hardened-bindings", test_mode=True)
        codes = []
        for change in ({"attempt_id": "wrong"}, {"nonce": "wrong"}):
            response, fds = g.test_exchange(packet(g, "lease_request", **change))
            assert not fds
            codes.append(response["code"])
        regular = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        response, fds = g.test_exchange(packet(g, "lease_request"), [regular])
        os.close(regular)
        assert not fds
        codes.append(response["code"])
        lease = g.request_lease()
        try:
            g.request_lease()
        except m.ProtocolRejected as exc:
            replay = str(exc)
        lease.release()
        for change in ({"attempt_id": "wrong"}, {"nonce": "wrong"}):
            response, fds = g.test_exchange(packet(g, "export_request", **change))
            assert not fds
            codes.append(response["code"])
        regular = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        response, fds = g.test_exchange(packet(g, "export_request"), [regular])
        os.close(regular)
        assert not fds
        codes.append(response["code"])
        export = g.request_export()
        try:
            g.request_export()
        except m.ProtocolRejected as exc:
            export_replay = str(exc)
        export.release()
        g.finalize()
        emit(codes=codes, replay=replay, export_replay=export_replay, state=g.state)
    elif scenario == "duplicate_lease_export":
        g = m.RecoveryNamespaceGuardian("hardened-duplicate-lease-export", test_mode=True)
        lease = g.request_lease()
        fd = os.open("payload", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=lease.fd)
        os.write(fd, b"payload")
        os.close(fd)
        duplicate = os.dup(lease.fd)
        lease.release()
        try:
            g.request_export()
        except m.LiveLeaseError as exc:
            blocked = str(exc)
        else:
            raise AssertionError("duplicate lease FD did not block export")
        os.close(duplicate)
        export = g.request_export()
        digest = export.metadata["content_digest"]
        export.release()
        g.finalize()
        emit(blocked=blocked, digest=digest, state=g.state)
    elif scenario == "digest_shapes":
        def export_digest(build):
            local = m.RecoveryNamespaceGuardian("hardened-digest", test_mode=True)
            local_lease = local.request_lease()
            build(local_lease.fd)
            local_lease.release()
            local_export = local.request_export()
            value = local_export.metadata["content_digest"]
            entries = local_export.metadata["capsule"]["entries"]
            local_export.release()
            local.finalize()
            return value, entries

        def no_entries(_root):
            return None

        def empty_dir(root):
            os.mkdir("dir", 0o700, dir_fd=root)

        def file_mode(root, mode):
            item = os.open("file", os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode, dir_fd=root)
            os.write(item, b"same")
            os.close(item)

        empty_digest, empty_entries = export_digest(no_entries)
        empty_dir_digest, empty_dir_entries = export_digest(empty_dir)
        mode_600_digest, mode_600_entries = export_digest(lambda root: file_mode(root, 0o600))
        mode_640_digest, mode_640_entries = export_digest(lambda root: file_mode(root, 0o640))
        repeat_digest, repeat_entries = export_digest(lambda root: file_mode(root, 0o600))
        emit(
            empty_digest=empty_digest,
            empty_entries=empty_entries,
            empty_dir_digest=empty_dir_digest,
            empty_dir_entries=empty_dir_entries,
            mode_600_digest=mode_600_digest,
            mode_600_entries=mode_600_entries,
            mode_640_digest=mode_640_digest,
            mode_640_entries=mode_640_entries,
            repeat_digest=repeat_digest,
            repeat_entries=repeat_entries,
        )
    elif scenario == "tamper_paths":
        g = m.RecoveryNamespaceGuardian("hardened-tamper-paths", test_mode=True)
        lease = g.request_lease()
        os.mkdir("dir", 0o700, dir_fd=lease.fd)
        dir_fd = os.open("dir", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=lease.fd)
        try:
            child = os.open("child", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=dir_fd)
            os.write(child, b"payload")
            os.close(child)
        finally:
            os.close(dir_fd)
        lease.release()
        export = g.request_export()
        base_response = {
            key: value for key, value in export.metadata.items() if key != "capsule"
        }
        base_capsule = export.metadata["capsule"]
        rejected = []

        def probe(label, mutate):
            capsule = json.loads(json.dumps(base_capsule))
            mutate(capsule)
            body = m._canonical_packet(capsule)
            fd, seals = m._sealed_memfd_from_capsule(body)
            response = dict(base_response)
            response["capsule_digest"] = __import__("hashlib").sha256(body).hexdigest()
            response["capsule_size"] = len(body)
            response["seals"] = seals
            response["content_digest"] = capsule["content_digest"]
            try:
                g._validate_export_response(response, [fd])
            except m.ProtocolRejected:
                rejected.append(label)
            else:
                raise AssertionError(f"malformed path accepted: {label}")
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

        probe("/absolute", lambda capsule: capsule["entries"][1].update(path="/absolute"))
        probe("../escape", lambda capsule: capsule["entries"][1].update(path="../escape"))
        probe("dir/../escape", lambda capsule: capsule["entries"][1].update(path="dir/../escape"))
        probe("dir//child", lambda capsule: capsule["entries"][1].update(path="dir//child"))
        probe("missing-parent", lambda capsule: capsule["entries"][1].update(path="missing/child"))
        export.release()
        g.finalize()
        emit(rejected=rejected, state=g.state)
    elif scenario == "tamper_metadata":
        g = m.RecoveryNamespaceGuardian("hardened-tamper-metadata", test_mode=True)
        lease = g.request_lease()
        fd = os.open("file", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=lease.fd)
        os.write(fd, b"payload")
        os.close(fd)
        lease.release()
        export = g.request_export()
        base_response = {
            key: value for key, value in export.metadata.items() if key != "capsule"
        }
        base_capsule = export.metadata["capsule"]
        rejected = []

        def probe(label, mutate):
            capsule = json.loads(json.dumps(base_capsule))
            mutate(capsule)
            body = m._canonical_packet(capsule)
            fd, seals = m._sealed_memfd_from_capsule(body)
            response = dict(base_response)
            response["capsule_digest"] = __import__("hashlib").sha256(body).hexdigest()
            response["capsule_size"] = len(body)
            response["seals"] = seals
            response["content_digest"] = capsule["content_digest"]
            try:
                g._validate_export_response(response, [fd])
            except m.ProtocolRejected:
                rejected.append(label)
            else:
                raise AssertionError(f"malformed metadata accepted: {label}")
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

        probe("bool-size", lambda capsule: capsule["entries"][0].update(size=True))
        probe("string-mode", lambda capsule: capsule["entries"][0].update(mode="384"))
        probe("range-nlink", lambda capsule: capsule["entries"][0].update(nlink=2))
        probe("uppercase-hash", lambda capsule: capsule["entries"][0].update(sha256="A" * 64))
        probe("bad-base64", lambda capsule: capsule["entries"][0].update(content_b64="***"))
        probe("device", lambda capsule: capsule["entries"][0].update(device=999999999))
        probe("inode-count", lambda capsule: capsule.update(inode_count=99))
        export.release()
        g.finalize()
        emit(rejected=rejected, state=g.state)
    elif scenario.startswith("unsupported:"):
        kind = scenario.split(":", 1)[1]
        g = m.RecoveryNamespaceGuardian("hardened-unsupported", test_mode=True)
        lease = g.request_lease()
        if kind == "symlink":
            os.symlink("/etc/passwd", "bad-link", dir_fd=lease.fd)
        elif kind == "fifo":
            os.mkfifo("bad-fifo", 0o600, dir_fd=lease.fd)
        elif kind == "hardlink":
            fd = os.open("original", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=lease.fd)
            os.write(fd, b"x")
            os.close(fd)
            os.link("original", "linked", src_dir_fd=lease.fd, dst_dir_fd=lease.fd)
        elif kind == "unsafe_name":
            fd = os.open("bad name", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=lease.fd)
            os.write(fd, b"x")
            os.close(fd)
        else:
            raise AssertionError("unknown unsupported kind")
        lease.release()
        try:
            g.request_export()
        except m.GuardianError as exc:
            emit(error_type=type(exc).__name__, error=str(exc), state=g.state)
        else:
            raise AssertionError("unsupported recovery tree exported")
    elif scenario.startswith("fault:"):
        fault = scenario.split(":", 1)[1]
        g = None
        before_fds = set(os.listdir("/proc/self/fd"))
        try:
            g = m.RecoveryNamespaceGuardian("hardened-fault", test_mode=True, test_fault=fault)
            if fault.startswith("lease_"):
                g.request_lease()
            elif fault.startswith("export_") or fault == "die_after_export_send":
                lease = g.request_lease()
                fd = os.open(
                    "payload",
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                    dir_fd=lease.fd,
                )
                os.write(fd, b"payload")
                os.close(fd)
                lease.release()
                g.request_export()
            elif fault == "die_after_release":
                g.request_lease().release()
            elif fault in {"die_before_finalize", "die_after_unmount"}:
                g.finalize()
            else:
                raise AssertionError("startup fault unexpectedly constructed")
        except BaseException as exc:
            emit(
                error_type=type(exc).__name__,
                error=str(exc),
                state=None if g is None else g.state,
                pidfd=None if g is None else g.pidfd,
                terminal_ready=None if g is None else g.terminal_pidfd_ready,
                fd_delta=len(set(os.listdir("/proc/self/fd"))) - len(before_fds),
            )
        else:
            raise AssertionError("fault did not fail closed")
    elif scenario == "eof":
        g = m.RecoveryNamespaceGuardian("hardened-eof", test_mode=True)
        g.close_control_for_test()
        emit(state=g.state, pidfd=g.pidfd, ready=g.terminal_pidfd_ready)
    elif scenario == "death":
        g = m.RecoveryNamespaceGuardian("hardened-death", test_mode=True)
        m.pidfd_send_signal(g.pidfd, signal.SIGKILL)
        try:
            g.finalize()
        except m.UnknownOutcomeError as exc:
            emit(
                error_type=type(exc).__name__,
                state=g.state,
                pidfd=g.pidfd,
                ready=g.terminal_pidfd_ready,
            )
        else:
            raise AssertionError("child death was accepted")
    elif scenario == "quota":
        g = m.RecoveryNamespaceGuardian("hardened-quota", quota_bytes=32768, test_mode=True)
        lease = g.request_lease()
        fd = os.open("fill", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=lease.fd)
        total = 0
        observed = None
        for _ in range(64):
            try:
                total += os.write(fd, b"x" * 4096)
            except OSError as exc:
                observed = exc.errno
                break
        os.close(fd)
        lease.release()
        g.finalize()
        emit(total=total, observed=observed, state=g.state)
    elif scenario == "sentinel":
        assert not Path(m.INTERNAL_ROOT).exists()
        name = "acgs-sentinel-" + uuid.uuid4().hex
        external = Path(m.INTERNAL_MOUNT) / name
        external.write_bytes(b"host-original")
        g = m.RecoveryNamespaceGuardian("hardened-sentinel", test_mode=True)
        lease = g.request_lease()
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=lease.fd)
        os.write(fd, b"internal-private")
        os.close(fd)
        unchanged_live = (
            external.read_bytes() == b"host-original"
            and not Path(m.INTERNAL_ROOT).exists()
        )
        lease.release()
        g.finalize()
        unchanged_terminal = (
            external.read_bytes() == b"host-original"
            and not Path(m.INTERNAL_ROOT).exists()
        )
        external.unlink()
        emit(unchanged_live=unchanged_live, unchanged_terminal=unchanged_terminal)
    elif scenario == "permissions":
        g = m.RecoveryNamespaceGuardian("hardened-permissions", test_mode=True)
        lease = g.request_lease()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.setns.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.setns.restype = ctypes.c_int
        ctypes.set_errno(0)
        setns_result = libc.setns(g.mount_namespace_fd, 0)
        setns_errno = ctypes.get_errno()
        try:
            m.pidfd_getfd(g.pidfd, g.evidence.payload["recovery_root"]["fd_number"])
        except OSError as exc:
            getfd_errno = exc.errno
        attacker = textwrap.dedent(r'''
        import ctypes, errno, json, os, sys
        sys.path.insert(0, sys.argv[1])
        import recovery_namespace_guardian as m
        broker, child, target = map(int, sys.argv[2:])
        results = {}
        for pid in (broker, child):
            for leaf in ("fd", "root", "cwd"):
                path = f"/proc/{pid}/{leaf}"
                try:
                    if leaf == "fd":
                        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                        os.close(fd)
                    else:
                        os.readlink(path)
                except OSError as exc:
                    results[f"{pid}:{leaf}"] = exc.errno
                else:
                    results[f"{pid}:{leaf}"] = 0
        libc = ctypes.CDLL(None, use_errno=True)
        for pid in (broker, child):
            ctypes.set_errno(0)
            result = libc.ptrace(16, pid, 0, 0)
            results[f"{pid}:ptrace"] = ctypes.get_errno() if result == -1 else 0
            if result == 0:
                libc.ptrace(17, pid, 0, 0)
        pidfd = m._pidfd_open(child)
        try:
            m.pidfd_getfd(pidfd, target)
        except OSError as exc:
            results["pidfd_getfd"] = exc.errno
        else:
            results["pidfd_getfd"] = 0
        os.close(pidfd)
        print(json.dumps(results, sort_keys=True))
        ''')
        attack = subprocess.run(
            [
                sys.executable,
                "-c",
                attacker,
                sys.argv[1],
                str(os.getpid()),
                str(g.pid),
                str(g.evidence.payload["recovery_root"]["fd_number"]),
            ],
            text=True, capture_output=True, check=True,
        )
        lease.release()
        g.finalize()
        emit(
            setns_result=setns_result,
            setns_errno=setns_errno,
            getfd_errno=getfd_errno,
            attacks=json.loads(attack.stdout),
        )
    elif scenario == "max_quota":
        g = m.RecoveryNamespaceGuardian("exact-max", quota_bytes=m.MAX_QUOTA_BYTES)
        accepted = g.evidence.payload["mount"]
        g.finalize()
        try:
            m.RecoveryNamespaceGuardian("too-large", quota_bytes=m.MAX_QUOTA_BYTES + 4096)
        except ValueError as exc:
            emit(error_type=type(exc).__name__, error=str(exc), accepted=accepted)
        else:
            raise AssertionError("oversized quota accepted")
    else:
        raise AssertionError("unknown scenario")
    """
)
PARENT_DEATH_PROGRAM = textwrap.dedent(
    r"""
    import ctypes, json, sys
    sys.path.insert(0, sys.argv[1])
    import recovery_namespace_guardian as m
    assert m._libc.prctl(m.PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    g = m.RecoveryNamespaceGuardian("parent-death", test_mode=True)
    lease = g.request_lease()
    print(json.dumps({"broker": __import__("os").getpid(), "child": g.pid}), flush=True)
    sys.stdin.buffer.read(1)
    """
)


def _run_scenario(name: str) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-c", SCENARIO_PROGRAM, str(MODULE_DIR), name],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_general_caller_is_rejected_before_guardian_descriptors() -> None:
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(
        guardian_module.EssentialPrimitiveUnavailable, match="already be nondumpable"
    ):
        guardian_module.RecoveryNamespaceGuardian("general-caller")
    after = set(os.listdir("/proc/self/fd"))
    assert after == before


def test_hardened_bootstrap_handshake_lease_duplicate_and_terminal_lifecycle() -> None:
    result = _run_scenario("basic")
    evidence = result["evidence"]
    assert evidence["schema"] == guardian_module.SCHEMA
    assert evidence["namespaces"]["user"] != evidence["parent_namespaces"]["user"]
    assert evidence["namespaces"]["mount"] != evidence["parent_namespaces"]["mount"]
    assert evidence["mount"] == {
        "mountpoint": "/tmp",
        "filesystem": "tmpfs",
        "requested_bytes": 65536,
        "actual_bytes": 65536,
        "requested_inodes": 64,
        "actual_inodes": 64,
        "nosuid": True,
        "nodev": True,
        "noexec": True,
        "root_propagation_private": True,
    }
    security = evidence["security"]
    for field in ("cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb"):
        assert security[field] == "0000000000000000"
    assert security["groups"] == ""
    assert security["setgroups"] == "allow"
    assert security["tracer_pid"] == 0
    assert security["securebits"] == guardian_module.SECUREBITS_LOCKED_ZERO_CAPS
    inventory = evidence["fd_inventory"]
    assert sorted(item["kind"] for item in inventory["after_inherited_close"]) == [
        "pipe",
        "pipe",
        "socket",
    ]
    socket_fd = next(
        item["fd"] for item in inventory["after_inherited_close"] if item["kind"] == "socket"
    )
    assert inventory["post_bootstrap_open_fds"] == [socket_fd]
    assert "live_lease" in result["live_refusal"]
    assert "live_lease" in result["live_export_refusal"]
    assert "duplicate_lease_fd" in result["duplicate_refusal"]
    assert "duplicate_mount_namespace_fd" in result["namespace_refusal"]
    export_metadata = result["export_metadata"]
    export_body = result["export_body"]
    assert export_metadata["source_root"] == export_body["source_root"]
    assert export_metadata["byte_count"] == export_body["byte_count"] == len(b"private-data")
    assert export_metadata["inode_count"] == export_body["inode_count"] == 2
    assert export_metadata["entry_count"] == export_body["entry_count"] == 1
    assert export_metadata["capsule"]["entries"] == export_body["entries"]
    assert export_body["entries"] == [
        {
            "content_b64": "cHJpdmF0ZS1kYXRh",
            "device": export_body["entries"][0]["device"],
            "inode": export_body["entries"][0]["inode"],
            "kind": "file",
            "mode": 384,
            "nlink": 1,
            "path": "round-trip",
            "sha256": "ee73c1168865f5f8daa6f7aead30c7ca0c34373324284c1ff9bae667eeadcb89",
            "size": 12,
        }
    ]
    assert result["export_stat_nlink"] == 0
    assert result["export_stat_size"] == export_metadata["capsule_size"]
    assert result["export_seals"] == guardian_module.EXPORT_SEALS
    assert result["write_seal_errno"] == errno.EPERM
    assert "live_export" in result["live_export_finalize_refusal"]
    assert "duplicate_export_fd" in result["duplicate_export_release_refusal"]
    assert "duplicate_export_fd" in result["duplicate_export_finalize_refusal"]
    assert result["released_export_errno"] == errno.EBADF
    assert result["terminal_rejected"] is True
    assert result["state"] == "success"
    assert result["pidfd"] == result["namespace_fd"] == -1
    assert result["terminal_pidfd_ready"] is True


def test_binding_replay_and_ancillary_substitution_are_rejected() -> None:
    result = _run_scenario("bindings")
    assert result == {
        "codes": [
            "binding_mismatch",
            "binding_mismatch",
            "unexpected_ancillary_fds",
            "binding_mismatch",
            "binding_mismatch",
            "unexpected_ancillary_fds",
        ],
        "replay": "lease_already_issued",
        "export_replay": "export_already_issued",
        "state": "success",
    }


@pytest.mark.parametrize(
    ("fault", "error_type"),
    [
        ("mapping_failure", "EssentialPrimitiveUnavailable"),
        ("handshake_extra_key", "ProtocolRejected"),
        ("handshake_regular_fd", "ProtocolRejected"),
        ("handshake_two_fds", "ProtocolRejected"),
        ("lease_regular_fd", "ProtocolRejected"),
        ("lease_two_fds", "ProtocolRejected"),
        ("export_bad_digest", "ProtocolRejected"),
        ("export_extra_key", "ProtocolRejected"),
        ("export_regular_fd", "ProtocolRejected"),
        ("export_two_fds", "ProtocolRejected"),
        ("export_race_after_snapshot", "ProtocolRejected"),
        ("die_after_export_send", "UnknownOutcomeError"),
        ("die_after_release", "UnknownOutcomeError"),
        ("die_after_unmount", "UnknownOutcomeError"),
    ],
)
def test_faults_fail_closed_with_explicit_terminal_cleanup(fault: str, error_type: str) -> None:
    result = _run_scenario(f"fault:{fault}")
    assert result["error_type"] == error_type
    assert result["fd_delta"] == 0
    if result["state"] is not None:
        assert result["state"] == "unknown"
        assert result["pidfd"] == -1
        assert result["terminal_ready"] is True


def test_control_eof_and_child_death_are_unknown() -> None:
    for scenario in ("eof", "death"):
        result = _run_scenario(scenario)
        assert result["state"] == "unknown"
        assert result["pidfd"] == -1
        assert result["ready"] is True


def test_quota_sentinel_and_maximum_are_real_and_fail_closed() -> None:
    quota = _run_scenario("quota")
    assert quota["observed"] == errno.ENOSPC
    assert 0 < quota["total"] <= 32768
    assert quota["state"] == "success"
    sentinel = _run_scenario("sentinel")
    assert sentinel == {"unchanged_live": True, "unchanged_terminal": True}
    maximum = _run_scenario("max_quota")
    assert maximum["error_type"] == "ValueError"
    assert maximum["accepted"]["requested_bytes"] == guardian_module.MAX_QUOTA_BYTES
    assert maximum["accepted"]["actual_bytes"] == guardian_module.MAX_QUOTA_BYTES
    assert maximum["accepted"]["actual_inodes"] == guardian_module.TMPFS_INODE_LIMIT


def test_host_lsm_observation_denies_unrelated_helper_while_lease_is_live() -> None:
    result = _run_scenario("permissions")
    assert result["setns_result"] == -1
    assert result["setns_errno"] == errno.EPERM
    assert result["getfd_errno"] == errno.EPERM
    assert result["attacks"]
    assert set(result["attacks"].values()) <= {errno.EACCES, errno.EPERM}
    assert all(value in {errno.EACCES, errno.EPERM} for value in result["attacks"].values())


def test_broker_parent_death_kills_child_via_pdeathsig_and_pidfd() -> None:
    broker = subprocess.Popen(
        [sys.executable, "-c", PARENT_DEATH_PROGRAM, str(MODULE_DIR)],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert broker.stdout is not None
    identity = json.loads(broker.stdout.readline())
    child_pidfd = guardian_module._pidfd_open(identity["child"])
    try:
        os.kill(identity["broker"], signal.SIGKILL)
        broker.wait(timeout=5)
        deadline = time.monotonic() + 5
        while not select.select([child_pidfd], [], [], 0)[0] and time.monotonic() < deadline:
            time.sleep(0.01)
        assert select.select([child_pidfd], [], [], 0)[0]
    finally:
        os.close(child_pidfd)
        if broker.poll() is None:
            broker.kill()


def test_truth_boundary_and_runtime_protocol_do_not_claim_external_quiescence() -> None:
    doc = " ".join((guardian_module.__doc__ or "").split())
    for boundary in (
        "nondumpable broker boundary",
        "Same-UID injection before",
        "host root",
        "CAP_SYS_PTRACE",
        "host snapshot rollback",
        "does not prove cross-process consumer quiescence",
        "owned by the ambient original UID",
        "not a portable isolation guarantee",
        "ambient namespace-owner authority is explicitly outside",
        "sealed memfd proves bounded process-lifetime immutability",
        "does not prove confidentiality",
        "crash durability",
        "same-UID secrecy",
        "restart garbage collection",
        "global FD quiescence",
        "broker/KMS custody",
        "P3C/P3D readiness",
        "cross-platform behavior",
    ):
        assert boundary in doc


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink", "unsafe_name"])
def test_export_rejects_unsupported_entries_without_valid_artifact(kind: str) -> None:
    result = _run_scenario(f"unsupported:{kind}")
    assert result["error_type"] in {"ProtocolRejected", "UnknownOutcomeError"}
    assert result["state"] == "unknown"


def test_export_content_address_is_deterministic() -> None:
    first = _run_scenario("basic")["export_metadata"]
    second = _run_scenario("basic")["export_metadata"]
    assert first["content_digest"] == second["content_digest"]


def test_duplicate_recovery_root_fd_blocks_export_until_closed() -> None:
    result = _run_scenario("duplicate_lease_export")
    assert "duplicate_lease_fd" in result["blocked"]
    assert result["digest"]
    assert result["state"] == "success"


def test_malformed_sealed_capsule_paths_are_rejected_without_artifact() -> None:
    result = _run_scenario("tamper_paths")
    assert result == {
        "rejected": [
            "/absolute",
            "../escape",
            "dir/../escape",
            "dir//child",
            "missing-parent",
        ],
        "state": "success",
    }


def test_logical_content_digest_covers_empty_dirs_modes_and_repeated_trees() -> None:
    result = _run_scenario("digest_shapes")
    assert result["empty_entries"] == []
    assert result["empty_dir_entries"] == [
        {
            "device": result["empty_dir_entries"][0]["device"],
            "inode": result["empty_dir_entries"][0]["inode"],
            "kind": "dir",
            "mode": 448,
            "path": "dir",
        }
    ]
    assert result["empty_digest"] != result["empty_dir_digest"]
    assert result["mode_600_digest"] != result["mode_640_digest"]
    assert result["mode_600_digest"] == result["repeat_digest"]
    assert result["mode_600_entries"][0]["mode"] == 384
    assert result["mode_640_entries"][0]["mode"] == 416
    assert result["repeat_entries"][0]["mode"] == 384


def test_write_all_handles_eintr_and_short_writes_without_partial_success() -> None:
    calls = {"count": 0}
    captured = bytearray()

    def partial_writer(_fd: int, data: memoryview) -> int:
        calls["count"] += 1
        if calls["count"] == 1:
            raise InterruptedError
        chunk = bytes(data[:2])
        captured.extend(chunk)
        return len(chunk)

    guardian_module._write_all(-1, b"abcdef", partial_writer)
    assert bytes(captured) == b"abcdef"

    def stalled_writer(_fd: int, _data: memoryview) -> int:
        return 0

    with pytest.raises(OSError, match="short write"):
        guardian_module._write_all(-1, b"x", stalled_writer)


def test_export_capsule_bound_allows_base64_expansion_without_unbounded_payload() -> None:
    bound = guardian_module._max_export_capsule_bytes(guardian_module.MAX_QUOTA_BYTES)
    encoded_payload_bound = 4 * ((guardian_module.MAX_QUOTA_BYTES + 2) // 3)
    assert bound > encoded_payload_bound
    assert bound == encoded_payload_bound + guardian_module.MAX_PACKET_BYTES + (
        guardian_module.TMPFS_INODE_LIMIT * (guardian_module.MAX_EXPORT_PATH_BYTES + 1024)
    )


def test_malformed_metadata_recomputed_digest_is_rejected() -> None:
    result = _run_scenario("tamper_metadata")
    assert result == {
        "rejected": [
            "bool-size",
            "string-mode",
            "range-nlink",
            "uppercase-hash",
            "bad-base64",
            "device",
            "inode-count",
        ],
        "state": "success",
    }


def _memfd_links() -> set[str]:
    links: set[str] = set()
    for value in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{value}")
        except OSError:
            continue
        if "memfd:acgs-recovery-export" in target:
            links.add(target)
    return links


def _is_zombie(pid: int) -> bool:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except FileNotFoundError:
        return False
    for line in status.splitlines():
        if line.startswith("State:"):
            return "\tZ" in line or "zombie" in line
    return False


def _capture_memfds_during(callable_under_test: Any) -> list[set[str]]:
    captured: list[set[str]] = []
    stop = threading.Event()

    def scanner() -> None:
        while not stop.is_set():
            captured.append(_memfd_links())

    thread = threading.Thread(target=scanner)
    thread.start()
    try:
        callable_under_test()
    finally:
        stop.set()
        thread.join(timeout=2)
    return captured


def _kill_courier_before_next_send(broker: guardian_module.RecoveryExportBroker) -> None:
    guardian_module.pidfd_send_signal(broker.pidfd, signal.SIGKILL)
    ready, _, _ = select.select([broker.pidfd], [], [], 2.0)
    assert ready == [broker.pidfd]


def _assert_broker_reaped_after_transport_death(
    broker: guardian_module.RecoveryExportBroker, pid: int
) -> None:
    assert broker.state == "commit_unknown"
    assert broker._reaped is True
    assert broker.pidfd == -1
    assert not _is_zombie(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError("courier process survived transport failure cleanup")
    broker.abort()
    broker.close()
    assert broker.state == "commit_unknown"


def test_broker_happy_path_artifact_is_post_terminal_sealed_and_correct() -> None:
    broker = guardian_module.RecoveryExportBroker("broker-happy")
    broker.mkdir("dir")
    broker.put_file("dir/file", b"broker-data")
    artifact = broker.export()
    try:
        assert broker.state == "success"
        assert artifact.metadata["commit"] == "post_terminal"
        assert artifact.metadata["artifact"] == "received"
        assert fcntl.fcntl(artifact.fd, guardian_module.F_GET_SEALS) == guardian_module.EXPORT_SEALS
        with pytest.raises(OSError):
            os.write(artifact.fd, b"x")
        body = guardian_module._validate_detached_memfd(artifact.fd, artifact.metadata)
        capsule = json.loads(body)
        assert capsule["entries"][0]["path"] == "dir"
        assert capsule["entries"][1]["path"] == "dir/file"
        assert capsule["entries"][1]["sha256"] == hashlib.sha256(b"broker-data").hexdigest()
        assert artifact.metadata["content_digest"] == capsule["content_digest"]
    finally:
        os.close(artifact.fd)


def test_public_artifact_alias_does_not_affect_terminal_guardian_state() -> None:
    broker = guardian_module.RecoveryExportBroker("broker-alias")
    broker.put_file("file", b"payload")
    artifact = broker.export()
    duplicate = os.dup(artifact.fd)
    try:
        os.close(artifact.fd)
        artifact_body = guardian_module._validate_detached_memfd(duplicate, artifact.metadata)
        assert hashlib.sha256(artifact_body).hexdigest() == artifact.metadata["capsule_digest"]
        assert broker.state == "success"
    finally:
        os.close(duplicate)


def test_parent_fd_scanner_cannot_capture_artifact_on_broker_validation_failure() -> None:
    broker = guardian_module.RecoveryExportBroker(
        "broker-failure-scan", test_mode=True, test_fault="export_bad_digest"
    )
    broker.put_file("file", b"payload")
    captured: list[set[str]] = []
    stop = threading.Event()

    def scanner() -> None:
        while not stop.is_set():
            captured.append(_memfd_links())

    thread = threading.Thread(target=scanner)
    thread.start()
    try:
        with pytest.raises(guardian_module.UnknownOutcomeError, match="artifact_not_received"):
            broker.export()
    finally:
        stop.set()
        thread.join(timeout=2)
    assert broker.state == "commit_unknown"
    assert all(not links for links in captured)
    assert not _memfd_links()


def test_broker_death_before_receipt_is_commit_unknown_without_artifact() -> None:
    broker = guardian_module.RecoveryExportBroker(
        "broker-death", test_mode=True, test_fault="broker_die_before_receipt"
    )
    broker.put_file("file", b"payload")
    with pytest.raises(guardian_module.UnknownOutcomeError, match="artifact_not_received"):
        broker.export()
    assert broker.state == "commit_unknown"
    assert not _memfd_links()
    assert not _is_zombie(broker.pid)
    broker.abort()
    broker.abort()
    assert not _is_zombie(broker.pid)


def test_broker_detached_memfd_failure_precedes_finalization_and_returns_no_artifact() -> None:
    broker = guardian_module.RecoveryExportBroker(
        "broker-seal-failure", test_mode=True, test_fault="broker_detached_memfd_seal_failure"
    )
    broker.put_file("file", b"payload")
    with pytest.raises(guardian_module.UnknownOutcomeError, match="artifact_not_received"):
        broker.export()
    assert broker.state == "commit_unknown"
    assert not _memfd_links()


def test_broker_parent_never_receives_recovery_writer_and_writes_close_after_export() -> None:
    before = set(os.listdir("/proc/self/fd"))
    broker = guardian_module.RecoveryExportBroker("broker-no-writer")
    broker.put_file("file", b"payload")
    after_write = set(os.listdir("/proc/self/fd"))
    assert len(after_write - before) <= 2  # broker control socket plus pidfd
    artifact = broker.export()
    try:
        with pytest.raises(guardian_module.TerminalStateError):
            broker.put_file("late", b"nope")
        assert broker.state == "success"
    finally:
        os.close(artifact.fd)


@pytest.mark.parametrize(
    ("operation", "setup"),
    [
        ("export", lambda broker: broker.put_file("file", b"payload")),
        ("mkdir", lambda broker: None),
        ("put_file", lambda broker: None),
    ],
)
def test_public_send_paths_reap_killed_courier_without_manual_abort(
    operation: str, setup: Any
) -> None:
    broker = guardian_module.RecoveryExportBroker(f"broker-killed-before-{operation}")
    setup(broker)
    pid = broker.pid
    _kill_courier_before_next_send(broker)
    with pytest.raises(guardian_module.UnknownOutcomeError, match="artifact_not_received"):
        if operation == "export":
            broker.export()
        elif operation == "mkdir":
            broker.mkdir("late-dir")
        else:
            broker.put_file("late-file", b"payload")
    _assert_broker_reaped_after_transport_death(broker, pid)
    assert not _memfd_links()


def test_broker_sparse_file_quota_precheck_and_exact_rpc_rejections() -> None:
    broker = guardian_module.RecoveryExportBroker("broker-rpc", test_mode=True, quota_bytes=16384)
    with pytest.raises(guardian_module.ProtocolRejected, match="sparse_quota"):
        broker.test_sparse_file("sparse", 16385)
    with pytest.raises(guardian_module.ProtocolRejected, match="missing_parent"):
        broker.put_file("missing/file", b"x")
    with pytest.raises(guardian_module.ProtocolRejected, match="non_exact_mkdir"):
        broker._request("mkdir", path="dir", mode=0o700, extra=True)
    broker.abort()


def test_broker_rejects_ambient_python_and_loader_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "sitecustomize-ran"
    malicious = tmp_path / "sitecustomize.py"
    malicious.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran', encoding='ascii')\n",
        encoding="ascii",
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "fake-home"))
    monkeypatch.setenv("PYTHONSTARTUP", str(tmp_path / "startup.py"))
    monkeypatch.setenv("PYTHONINSPECT", "1")
    monkeypatch.setenv("LD_PRELOAD", str(tmp_path / "fake-preload.so"))
    monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path))

    broker = guardian_module.RecoveryExportBroker("broker-ambient")
    broker.put_file("file", b"payload")
    artifact = broker.export()
    try:
        assert broker.state == "success"
        assert not marker.exists()
    finally:
        os.close(artifact.fd)


def test_broker_launch_does_not_inherit_unrelated_explicit_fd() -> None:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    os.set_inheritable(write_fd, True)
    try:
        broker = guardian_module.RecoveryExportBroker("broker-no-fd-leak")
        os.close(write_fd)
        write_fd = -1
        ready, _, _ = select.select([read_fd], [], [], 1.0)
        assert ready == [read_fd]
        assert os.read(read_fd, 1) == b""
        artifact = broker.export()
        os.close(artifact.fd)
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


def test_broker_pidfd_open_failure_reaps_spawned_courier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[int] = []

    def fail_pidfd_open(pid: int) -> int:
        captured.append(pid)
        raise OSError(errno.EBADF, "forced pidfd failure")

    monkeypatch.setattr(guardian_module, "_pidfd_open", fail_pidfd_open)
    with pytest.raises(OSError, match="forced pidfd failure"):
        guardian_module.RecoveryExportBroker("broker-pidfd-failure")
    assert captured
    assert not _is_zombie(captured[0])
    try:
        os.kill(captured[0], 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError("courier process survived pidfd setup failure")


def test_broker_default_rejects_test_fault_without_test_mode() -> None:
    with pytest.raises(ValueError, match="test faults require explicit test_mode"):
        guardian_module.RecoveryExportBroker(
            "broker-no-implicit-fault", test_fault="export_bad_digest"
        )


def test_broker_public_api_rejects_non_exact_input_types() -> None:
    broker = guardian_module.RecoveryExportBroker("broker-type-api")
    try:
        with pytest.raises(guardian_module.ProtocolRejected, match="directory path"):
            broker.mkdir(123)  # type: ignore[arg-type]
        with pytest.raises(guardian_module.ProtocolRejected, match="file content"):
            broker.put_file("file", bytearray(b"x"))  # type: ignore[arg-type]
        with pytest.raises(guardian_module.ProtocolRejected, match="sparse path"):
            broker.test_sparse_file(123, 1)  # type: ignore[arg-type]
    finally:
        broker.abort()


@pytest.mark.parametrize(
    "fault",
    [
        "broker_artifact_bad_capsule_digest",
        "broker_artifact_bool_content_digest",
        "broker_artifact_bad_capsule_schema",
        "broker_artifact_escape_path",
        "broker_artifact_string_mode",
        "broker_artifact_bad_file_hash",
        "broker_artifact_bad_base64",
    ],
)
def test_courier_rejects_corrupt_worker_final_artifact_before_parent_fd_install(
    fault: str,
) -> None:
    broker = guardian_module.RecoveryExportBroker(
        f"broker-corrupt-{fault}", test_mode=True, test_fault=fault
    )
    broker.put_file("file", b"payload")

    def run_export() -> None:
        with pytest.raises(guardian_module.UnknownOutcomeError, match="artifact_not_received"):
            broker.export()

    captured = _capture_memfds_during(run_export)
    assert broker.state == "commit_unknown"
    assert all(not links for links in captured)
    assert not _memfd_links()


@pytest.mark.parametrize(
    "fault",
    ["broker_exit_42_after_artifact", "courier_exit_42_after_artifact"],
)
def test_worker_or_courier_nonzero_after_queued_artifact_drops_parent_capability(
    fault: str,
) -> None:
    broker = guardian_module.RecoveryExportBroker(
        f"broker-nonzero-{fault}", test_mode=True, test_fault=fault
    )
    broker.put_file("file", b"payload")

    def run_export() -> None:
        with pytest.raises(guardian_module.UnknownOutcomeError, match="artifact_not_received"):
            broker.export()

    captured = _capture_memfds_during(run_export)
    assert broker.state == "commit_unknown"
    assert all(not links for links in captured)
    assert not _memfd_links()
    assert not _is_zombie(broker.pid)


def test_broker_rejects_ancillary_fd_rpc_without_state_transition() -> None:
    broker = guardian_module.RecoveryExportBroker("broker-ancillary", test_mode=True)
    request = {
        "schema": guardian_module.BROKER_SCHEMA,
        "type": "mkdir",
        "attempt_id": broker.attempt_id,
        "nonce": broker.nonce,
        "request_id": "ancillary",
        "path": "dir",
        "mode": 0o700,
    }
    fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    try:
        guardian_module._send_packet(broker._sock, request, [fd])
        response, fds, _credentials = guardian_module._recv_packet(broker._sock)
    finally:
        os.close(fd)
    guardian_module._close_fds(fds)
    assert response["type"] == "rejected"
    assert response["code"] == "unexpected_ancillary_fds"
    broker.mkdir("dir")
    artifact = broker.export()
    os.close(artifact.fd)
