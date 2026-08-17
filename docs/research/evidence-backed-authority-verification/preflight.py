"""Sections 1 and 2: prior evidence is frozen, and the runtime is established.

V2 proved that the answer changes depending on where the measurement runs --
its own predecessor recorded "subordinate uid creation unavailable" because it
measured inside a harness sandbox with `NoNewPrivs=1`, where `newuidmap`'s file
capability is ignored. A verifier that does not know which environment it is in
cannot be trusted to report a privilege result.

So V3 fails closed. If the observed environment masks a privilege the real agent
principal holds, the verdict is `ENVIRONMENT_NOT_EQUIVALENT` and no closure is
claimed. The specific tell is cheap to check and is checked every run.

This module also freezes V1 and V2. Their contents are hashed at the start of
every V3 run and re-hashed at the end; any difference is a verifier failure, not
a note in a report.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
PRIOR_PACKAGES = (
    "CANONICAL_STATE_PROMOTION_AUTHORITY_V1",
    "CANONICAL_STATE_PROMOTION_AUTHORITY_V2",
)
#: Only the package's own artefacts are frozen. Harness bookkeeping directories
#: are written by tooling outside this task and are excluded by name rather than
#: silently tolerated when they change.
EXCLUDED_DIRS = {".omc", ".claude", "__pycache__", ".ruff_cache"}

ENVIRONMENT_NOT_EQUIVALENT = "ENVIRONMENT_NOT_EQUIVALENT"


def _run(cmd, **kwargs):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=False, **kwargs
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


# ------------------------------------------------------------ section 1
def hash_package(root: str) -> dict:
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                files[rel] = {"sha256": digest, "mtime": os.stat(full).st_mtime}
            except OSError as exc:
                files[rel] = {"error": exc.strerror}
    aggregate = hashlib.sha256(
        json.dumps(
            {name: entry.get("sha256") for name, entry in sorted(files.items())},
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return {
        "root": root,
        "file_count": len(files),
        "files": files,
        "aggregate_sha256": aggregate,
    }


def freeze_prior() -> dict:
    packages = {}
    for name in PRIOR_PACKAGES:
        path = os.path.join(PARENT, name)
        packages[name] = hash_package(path) if os.path.isdir(path) else {"missing": True}
    return packages


def prior_evidence_pointers() -> dict:
    """Where V2's machine-readable evidence lives. Never restated from memory."""
    v2 = os.path.join(PARENT, "CANONICAL_STATE_PROMOTION_AUTHORITY_V2")
    pointers = {
        "carrier_classification_37": ("attack_suite/results.json :: os_boundary + reachability"),
        "subuid_escalation": (
            "attack_suite/results.json :: independent_attacker.subuid_reacquisition"
        ),
        "setns_escalation": (
            "attack_suite/results.json :: independent_attacker.launcher_setns_reentry"
        ),
        "ptrace_escalation": (
            "attack_suite/results.json :: independent_attacker.independent_process_ptrace_authority"
        ),
        "docker_escalation": "host_capability.json :: mechanisms.rootful_helper_docker_socket",
        "uid_524288_experiment": "attack_suite/results.json :: environment",
        "uid_999_experiment": "minimum_primitive.json",
        "verdict": "verification_report.json :: verdict",
    }
    loaded = {}
    for key, spec in pointers.items():
        filename = spec.split(" :: ")[0]
        loaded[key] = {
            "source": os.path.join(v2, filename),
            "selector": spec.split(" :: ")[1] if " :: " in spec else None,
            "present": os.path.exists(os.path.join(v2, filename)),
        }
    return loaded


def read_v2_evidence() -> dict:
    """Load V2's own numbers from disk rather than restating them."""
    v2 = os.path.join(PARENT, "CANONICAL_STATE_PROMOTION_AUTHORITY_V2")
    out: dict = {}
    try:
        with open(os.path.join(v2, "attack_suite", "results.json"), encoding="utf-8") as h:
            results = json.load(h)
        counts: dict[str, int] = {}
        for entry in results["os_boundary"] + results["reachability"]:
            counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        out["carrier_counts"] = counts
        out["carriers_total"] = sum(counts.values())
        out["independent_attacker"] = {
            name: entry.get("verdict") for name, entry in results["independent_attacker"].items()
        }
        out["agent_uid"] = results["environment"]["agent_uid"]
        out["broker_uid"] = results["environment"]["broker_uid"]
        out["protocol_cases"] = results["protocol"]["count"]
        out["protocol_failures"] = results["protocol"]["failures"]
    except (OSError, ValueError, KeyError) as exc:
        out["attack_results_error"] = str(exc)
    try:
        with open(os.path.join(v2, "verification_report.json"), encoding="utf-8") as h:
            report = json.load(h)
        out["v2_verdict"] = report["verdict"]
        out["v2_section18_failed"] = sorted(
            k for k, v in report["section_18_conditions"].items() if not v["met"]
        )
    except (OSError, ValueError, KeyError) as exc:
        out["verification_report_error"] = str(exc)
    try:
        with open(os.path.join(v2, "minimum_primitive.json"), encoding="utf-8") as h:
            out["minimum_primitive"] = json.load(h)
    except (OSError, ValueError) as exc:
        out["minimum_primitive_error"] = str(exc)
    return out


# ------------------------------------------------------------ section 2
def _status_fields() -> dict:
    fields = {}
    with open("/proc/self/status", encoding="utf-8") as handle:
        for line in handle:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


def _namespaces() -> dict:
    namespaces = {}
    for name in ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup", "time"):
        path = f"/proc/self/ns/{name}"
        try:
            namespaces[name] = os.readlink(path)
        except OSError as exc:
            namespaces[name] = f"unreadable ({exc.strerror})"
    return namespaces


def _setuid_and_file_caps() -> dict:
    """Identity-transition binaries. Bounded scan; the directories that matter."""
    setuid_binaries = []
    directories = ("/usr/bin", "/usr/sbin", "/usr/libexec", "/bin", "/sbin")
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for name in entries:
            full = os.path.join(directory, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if not os.path.isfile(full):
                continue
            if st.st_mode & 0o4000:
                setuid_binaries.append(
                    {
                        "path": full,
                        "owner_uid": st.st_uid,
                        "mode": oct(st.st_mode & 0o7777),
                    }
                )
    caps = _run(["getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/libexec"])
    return {
        "setuid_binaries": sorted(setuid_binaries, key=lambda e: e["path"]),
        "setuid_count": len(setuid_binaries),
        "file_capabilities": [line for line in caps.stdout.splitlines() if line.strip()],
    }


def _container_sockets() -> dict:
    candidates = {
        "docker": ["/var/run/docker.sock", "/run/docker.sock"],
        "podman_user": [f"/run/user/{os.getuid()}/podman/podman.sock"],
        "podman_system": ["/run/podman/podman.sock"],
        "containerd": ["/run/containerd/containerd.sock"],
        "cri": ["/var/run/crio/crio.sock", "/run/crio/crio.sock"],
        "lxd": ["/var/lib/lxd/unix.socket", "/var/snap/lxd/common/lxd/unix.socket"],
        "buildkit": ["/run/buildkit/buildkitd.sock"],
    }
    found = {}
    for label, paths in candidates.items():
        for path in paths:
            if not os.path.exists(path):
                continue
            st = os.stat(path)
            acl = _run(["getfacl", "-c", path])
            found[label] = {
                "path": path,
                "owner_uid": st.st_uid,
                "owner_gid": st.st_gid,
                "group_name": _gid_name(st.st_gid),
                "mode": oct(st.st_mode & 0o7777),
                "writable_by_agent": os.access(path, os.W_OK),
                "acl": [line for line in acl.stdout.splitlines() if line.strip()],
            }
            break
    return found


def _gid_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _privileged_helpers() -> dict:
    """Presence and authority shape. Never exercised -- see the note."""
    helpers = {}
    for name in ("sudo", "pkexec", "doas", "machinectl", "systemd-run", "run0"):
        helpers[name] = shutil.which(name)
    groups = [_gid_name(gid) for gid in os.getgroups()]
    return {
        "binaries": helpers,
        "agent_groups": groups,
        "in_wheel_or_sudo": any(name in groups for name in ("wheel", "sudo", "admin")),
        "in_docker_group": "docker" in groups,
        "sudoers_readable": os.access("/etc/sudoers", os.R_OK),
        "note": "sudo and pkexec are password- or polkit-gated interactive paths. "
        "They are recorded as present and NOT exercised: escalating "
        "through them is a human action, and doing so would neither "
        "change the verdict nor be reversible from inside this task.",
    }


def _subid_delegation() -> dict:
    user = pwd.getpwuid(os.getuid()).pw_name
    delegation = {}
    for path in ("/etc/subuid", "/etc/subgid"):
        entries = []
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    parts = line.strip().split(":")
                    if len(parts) == 3:
                        entries.append(
                            {
                                "owner": parts[0],
                                "start": int(parts[1]),
                                "count": int(parts[2]),
                                "belongs_to_agent": parts[0] == user,
                            }
                        )
        except OSError as exc:
            entries = [{"error": exc.strerror}]
        delegation[os.path.basename(path)] = {
            "entries": entries,
            "writable_by_agent": os.access(path, os.W_OK),
        }
    return delegation


def environment() -> dict:
    status = _status_fields()
    uid_real, uid_eff, uid_saved, uid_fs = (
        int(part) for part in status.get("Uid", "0 0 0 0").split()
    )
    gid_real, gid_eff, gid_saved, gid_fs = (
        int(part) for part in status.get("Gid", "0 0 0 0").split()
    )
    lsm = ""
    try:
        with open("/sys/kernel/security/lsm", encoding="utf-8") as handle:
            lsm = handle.read().strip()
    except OSError:
        lsm = "unreadable"
    return {
        "uid": {
            "real": uid_real,
            "effective": uid_eff,
            "saved": uid_saved,
            "fs": uid_fs,
        },
        "gid": {
            "real": gid_real,
            "effective": gid_eff,
            "saved": gid_saved,
            "fs": gid_fs,
        },
        "supplementary_groups": [{"gid": gid, "name": _gid_name(gid)} for gid in os.getgroups()],
        "no_new_privs": int(status.get("NoNewPrivs", "-1")),
        "seccomp_mode": int(status.get("Seccomp", "-1")),
        "seccomp_filters": int(status.get("Seccomp_filters", "-1")),
        "capabilities": {
            name: status.get(f"Cap{suffix}")
            for name, suffix in (
                ("effective", "Eff"),
                ("permitted", "Prm"),
                ("inheritable", "Inh"),
                ("ambient", "Amb"),
                ("bounding", "Bnd"),
            )
        },
        "namespaces": _namespaces(),
        "cgroup": _read_first_line("/proc/self/cgroup"),
        "lsm": lsm,
        "selinux_mode": _run(["getenforce"]).stdout.strip() or "unavailable",
        "yama_ptrace_scope": _run(["sysctl", "-n", "kernel.yama.ptrace_scope"]).stdout.strip(),
        "max_user_namespaces": _run(["sysctl", "-n", "user.max_user_namespaces"]).stdout.strip(),
        "kernel": os.uname().release,
        "subid_delegation": _subid_delegation(),
        "identity_transition_binaries": _setuid_and_file_caps(),
        "container_sockets": _container_sockets(),
        "privileged_helpers": _privileged_helpers(),
        "in_container": os.path.exists("/.dockerenv")
        or "docker" in _read_first_line("/proc/1/cgroup"),
    }


def _read_first_line(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.readline().strip()
    except OSError:
        return ""


def equivalence(env: dict) -> dict:
    """Is this the real agent principal's environment, or a masked one?

    A masked environment silently *removes* privilege, which makes a privilege
    result look better than the truth. That is the one direction of error this
    whole exercise cannot tolerate, so any sign of masking fails closed.
    """
    problems = []
    if env["no_new_privs"] != 0:
        problems.append(
            "NoNewPrivs=1: file capabilities are ignored on execve, so identity "
            "transitions available to the real agent are masked (this is exactly "
            "what invalidated V1's premise 3)"
        )
    if env["seccomp_mode"] != 0:
        problems.append(
            f"a seccomp filter is installed (mode {env['seccomp_mode']}, "
            f"{env['seccomp_filters']} filter(s)): syscalls available to the real "
            f"agent may be masked"
        )
    if env["in_container"]:
        problems.append("running inside a container; host privilege topology differs")
    if env["uid"]["real"] != env["uid"]["effective"]:
        problems.append("real and effective uid differ; this is not a plain agent")
    return {
        "equivalent": not problems,
        "problems": problems,
        "verdict_if_not_equivalent": ENVIRONMENT_NOT_EQUIVALENT,
    }


def run() -> dict:
    env = environment()
    return {
        "prior_packages": freeze_prior(),
        "prior_evidence_pointers": prior_evidence_pointers(),
        "v2_evidence_as_read_from_disk": read_v2_evidence(),
        "environment": env,
        "environment_equivalence": equivalence(env),
    }


if __name__ == "__main__":
    outcome = run()
    print(json.dumps(outcome["environment_equivalence"], indent=2))
    print(json.dumps(outcome["v2_evidence_as_read_from_disk"], indent=2)[:1200])
