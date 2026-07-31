"""Real-host tests for the hardened recovery namespace guardian."""

from __future__ import annotations

import errno
import json
import os
import select
import signal
import subprocess
import sys
import textwrap
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
            duplicate_refusal=duplicate_refusal,
            namespace_refusal=namespace_refusal,
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
        g.finalize()
        emit(codes=codes, replay=replay, state=g.state)
    elif scenario.startswith("fault:"):
        fault = scenario.split(":", 1)[1]
        g = None
        before_fds = set(os.listdir("/proc/self/fd"))
        try:
            g = m.RecoveryNamespaceGuardian("hardened-fault", test_mode=True, test_fault=fault)
            if fault.startswith("lease_"):
                g.request_lease()
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
    assert "duplicate_lease_fd" in result["duplicate_refusal"]
    assert "duplicate_mount_namespace_fd" in result["namespace_refusal"]
    assert result["terminal_rejected"] is True
    assert result["state"] == "success"
    assert result["pidfd"] == result["namespace_fd"] == -1
    assert result["terminal_pidfd_ready"] is True


def test_binding_replay_and_ancillary_substitution_are_rejected() -> None:
    result = _run_scenario("bindings")
    assert result == {
        "codes": ["binding_mismatch", "binding_mismatch", "unexpected_ancillary_fds"],
        "replay": "lease_already_issued",
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
    ):
        assert boundary in doc
