"""Section 3: every path by which the agent principal can reach root-equivalent
or authority-equivalent capability, enumerated before any fix is proposed.

V2 found rootful Docker. That is not evidence Docker is the only such path, so
this module enumerates the whole class and classifies each member. The
classification vocabulary is deliberately blunt:

    NOT_PRESENT              the mechanism does not exist here
    PRESENT_NON_ESCALATING   it exists and does not yield A-J for the agent
    ROOT_EQUIVALENT          it yields arbitrary host write / chown / uid 0
    AUTHORITY_EQUIVALENT     it yields the authority principal's capability
    UNKNOWN                  not established -- and never counted as a pass

Capability targets tested, per the specification:

    A arbitrary host file write        F mount/bind to defeat DAC
    B arbitrary host chmod/chown       G control the authority process
    C transition to uid 0              H replace its executable/config
    D transition to the authority uid  I write its IPC endpoint
    E obtain CAP_DAC_OVERRIDE etc.     J alter the agent's own delegation

Two mechanisms are recorded present and deliberately **not exercised**: `sudo`
and `pkexec`. Both are interactive human-authentication gates. Exercising them
would be a privilege escalation this task has no authority to perform, it would
not be reversible from inside the task, and it cannot change the verdict --
Docker already settles root-equivalence. Their presence and shape are recorded;
their capability is marked UNKNOWN rather than assumed either way.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

import identity_pseudonym

NOT_PRESENT = "NOT_PRESENT"
PRESENT_NON_ESCALATING = "PRESENT_NON_ESCALATING"
ROOT_EQUIVALENT = "ROOT_EQUIVALENT"
AUTHORITY_EQUIVALENT = "AUTHORITY_EQUIVALENT"
UNKNOWN = "UNKNOWN"

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(HERE, "ROOT_EQUIVALENCE_REGISTRY.json")


def _run(cmd, timeout=180, **kwargs):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False, **kwargs
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


def _probe_dir() -> str:
    base = tempfile.mkdtemp(prefix="cspa3-rootprobe-", dir="/tmp")
    with open(os.path.join(base, "f"), "w", encoding="utf-8") as handle:
        handle.write("original\n")
    return base


# ------------------------------------------------------------ docker
def _docker_rootful_active() -> dict:
    socket = None
    for candidate in ("/var/run/docker.sock", "/run/docker.sock"):
        if os.path.exists(candidate):
            socket = candidate
            break
    if socket is None:
        return {"classification": NOT_PRESENT, "targets": {}}
    writable = os.access(socket, os.W_OK)
    info = _run(["docker", "info", "--format", "{{.DockerRootDir}}|{{json .SecurityOptions}}"])
    if not writable or info.returncode != 0:
        classification = UNKNOWN if writable and info.returncode != 0 else PRESENT_NON_ESCALATING
        return {
            "classification": classification,
            "evidence": {
                "socket": socket,
                "writable": writable,
                "docker_info_rc": info.returncode,
                "stderr": info.stderr.strip()[:160],
            },
            "targets": {},
        }
    rootless = "rootless" in info.stdout
    images = _run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    image = next(
        (line for line in images.stdout.splitlines() if line.strip() and "<none>" not in line),
        None,
    )
    evidence = {
        "socket": socket,
        "writable": True,
        "rootless_daemon": rootless,
        "docker_root_dir": info.stdout.strip()[:80],
        "image": image,
    }
    targets = {}
    if image:
        base = _probe_dir()
        target = os.path.join(base, "f")
        mutation_command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--security-opt",
            "label=disable",
            "--entrypoint",
            "sh",
            "-v",
            f"{base}:/mnt",
            image,
            "-c",
            "set -e; id -u; cat /proc/self/uid_map; echo root-write > /mnt/f; "
            "chown 4242:4242 /mnt/f; chmod 0600 /mnt/f; echo done",
        ]
        evidence["active_probe"] = {
            "probe_class": "ACTIVE_MUTATION",
            "disposable_host_warning": (
                "Run only on a disposable host: this probe bind-mounts a host "
                "directory and changes file bytes, ownership, and mode."
            ),
            "setup": {
                "path": target,
                "operation": "create temporary host file with original bytes",
                "returncode": 0,
                "outcome": "CREATED",
            },
            "mutation_command": {
                "argv": mutation_command,
                "returncode": None,
                "outcome": "PENDING",
            },
            "mutations": [],
            "cleanup": [],
        }
        result = _run(mutation_command)
        evidence["active_probe"]["mutation_command"].update(
            {
                "returncode": result.returncode,
                "outcome": ("COMMAND_SUCCEEDED" if result.returncode == 0 else "COMMAND_FAILED"),
            }
        )
        # stat and read are separate questions. The container chmods the file
        # 0600 under a foreign uid, so the agent can stat it but not read it --
        # folding both into one try discarded the stat and scored a successful
        # escalation as UNKNOWN.
        try:
            st = os.stat(target)
        except OSError as exc:
            st = None
            evidence["stat_error"] = exc.strerror
        try:
            with open(target, encoding="utf-8") as handle:
                content = handle.read().strip()
        except OSError as exc:
            content = f"unreadable by agent: {exc.strerror}"
        evidence["container_uid_map"] = [
            line
            for line in result.stdout.splitlines()
            if "4294967295" in line or line.strip().startswith("0 ")
        ][:2]
        # The write is evidenced by the size and the foreign ownership; the
        # agent being unable to read the result is itself part of the finding.
        targets["A_arbitrary_host_write"] = bool(st) and st.st_size > 0
        targets["B_arbitrary_host_chown"] = bool(st) and st.st_uid == 4242
        targets["C_uid_0"] = "0" in result.stdout.splitlines()[:1]
        targets["E_capabilities"] = targets["B_arbitrary_host_chown"]
        targets["F_mount_defeats_dac"] = targets["A_arbitrary_host_write"]
        evidence["host_file_uid_after"] = st.st_uid if st else None
        evidence["host_file_content_after"] = content
        evidence["active_probe"]["mutations"] = [
            {
                "path": target,
                "operation": "write root-write",
                "command_returncode": result.returncode,
                "outcome": ("OBSERVED" if targets["A_arbitrary_host_write"] else "NOT_OBSERVED"),
            },
            {
                "path": target,
                "operation": "chown 4242:4242",
                "command_returncode": result.returncode,
                "outcome": ("OBSERVED" if targets["B_arbitrary_host_chown"] else "NOT_OBSERVED"),
            },
            {
                "path": target,
                "operation": "chmod 0600",
                "command_returncode": result.returncode,
                "outcome": ("COMMAND_SUCCEEDED" if result.returncode == 0 else "COMMAND_FAILED"),
            },
        ]
        # A file now owned by 4242 cannot be removed by the agent; the same
        # instrument has to hand it back.
        cleanup_command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--security-opt",
            "label=disable",
            "--entrypoint",
            "sh",
            "-v",
            f"{base}:/mnt",
            image,
            "-c",
            f"set -e; rm -f /mnt/f; chown {os.getuid()}:{os.getgid()} /mnt",
        ]
        cleanup = _run(cleanup_command)
        shutil.rmtree(base, ignore_errors=True)
        removed = not os.path.exists(base)
        cleanup_status = "REMOVED" if cleanup.returncode == 0 and removed else "FAILED"
        evidence["active_probe"]["cleanup_command"] = {
            "argv": cleanup_command,
            "returncode": cleanup.returncode,
            "outcome": ("COMMAND_SUCCEEDED" if cleanup.returncode == 0 else "COMMAND_FAILED"),
        }
        evidence["active_probe"]["cleanup"] = [
            {
                "path": target,
                "operation": "rm -f",
                "command_returncode": cleanup.returncode,
                "outcome": ("COMMAND_SUCCEEDED" if cleanup.returncode == 0 else "COMMAND_FAILED"),
            },
            {
                "path": base,
                "operation": f"chown {os.getuid()}:{os.getgid()}",
                "command_returncode": cleanup.returncode,
                "outcome": ("COMMAND_SUCCEEDED" if cleanup.returncode == 0 else "COMMAND_FAILED"),
            },
            {
                "path": base,
                "operation": "rmtree",
                "action_returncode": 0 if removed else 1,
                "outcome": cleanup_status,
                "removed": removed,
            },
        ]
        evidence["active_probe"]["cleanup_status"] = cleanup_status
    classification = ROOT_EQUIVALENT if targets.get("B_arbitrary_host_chown") else UNKNOWN
    return {
        "classification": classification,
        "evidence": evidence,
        "targets": targets,
        "note": "SELinux denies the bind-mount write by default; "
        "--security-opt label=disable removes it. A flag is not a "
        "boundary when the attacker chooses the flags.",
    }


def docker_rootful(*, active: bool = False, acknowledge_disposable: bool = False) -> dict:
    """Run the mutation probe only after two explicit operator choices."""
    warning = (
        "Docker root-equivalence is an ACTIVE_MUTATION probe. Run it only on "
        "a disposable host; it changes host file bytes, ownership, and mode."
    )
    if not active:
        return {
            "classification": UNKNOWN,
            "targets": {},
            "probe": {
                "probe_class": "ACTIVE_MUTATION",
                "status": "UNAVAILABLE",
                "reason": "active probe not opted in",
                "disposable_host_warning": warning,
            },
        }
    if not acknowledge_disposable:
        raise ValueError("--active-docker-probe requires --ack-disposable-host")
    result = _docker_rootful_active()
    classification = result.get("classification")
    active_evidence = result.get("evidence", {}).get("active_probe")
    cleanup_complete = (
        isinstance(active_evidence, dict) and active_evidence.get("cleanup_status") == "REMOVED"
    )
    if classification == NOT_PRESENT:
        status = "NOT_PRESENT"
    elif classification == PRESENT_NON_ESCALATING:
        status = "SUCCESS"
    elif classification == ROOT_EQUIVALENT and cleanup_complete:
        status = "SUCCESS"
    else:
        status = "ERROR"
    result.setdefault("probe", {})
    result["probe"].update(
        {
            "probe_class": "ACTIVE_MUTATION",
            "status": status,
            "classification_observed": classification,
            "cleanup_complete": cleanup_complete,
            "disposable_host_warning": warning,
        }
    )
    return result


def docker_access_route(env: dict) -> dict:
    """Section 7: exactly how uid 1000 obtains Docker authority."""
    socket = None
    for candidate in ("/var/run/docker.sock", "/run/docker.sock"):
        if os.path.exists(candidate):
            socket = candidate
            break
    if socket is None:
        return {"route": "none", "socket": None}
    st = os.stat(socket)
    acl = _run(["getfacl", "-c", socket])
    groups = {entry["name"] for entry in env["supplementary_groups"]}
    group_name = env["container_sockets"].get("docker", {}).get("group_name")
    routes = []
    if group_name in groups:
        routes.append(f"group membership: agent is in group {group_name!r}")
    if st.st_mode & 0o002:
        routes.append("socket is world-writable")
    if any("user:" in line and str(os.getuid()) in line for line in acl.stdout.splitlines()):
        routes.append("POSIX ACL grants the agent uid directly")
    if st.st_uid == os.getuid():
        routes.append("socket is owned by the agent uid")
    return {
        "socket": socket,
        "socket_owner_uid": st.st_uid,
        "socket_group": group_name,
        "socket_mode": oct(st.st_mode & 0o7777),
        "acl": [line for line in acl.stdout.splitlines() if line.strip()],
        "routes": routes or ["undetermined"],
        "minimal_removal": (
            f"remove the agent from group {group_name!r} (or drop the ACL entry); "
            "the daemon itself needs no change"
        ),
    }


# ------------------------------------------------------------ podman
def podman_rootless() -> dict:
    if not shutil.which("podman"):
        return {"classification": NOT_PRESENT, "evidence": {}, "targets": {}}
    version = _run(["podman", "info", "--format", "{{.Host.Security.Rootless}}"])
    rootless = version.stdout.strip() == "true"
    base = _probe_dir()
    target = os.path.join(base, "f")
    before_uid = os.stat(target).st_uid
    image = None
    images = _run(["podman", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    for line in images.stdout.splitlines():
        if line.strip() and "<none>" not in line:
            image = line.strip()
            break
    evidence = {
        "rootless": rootless,
        "image": image,
        "info_stderr": version.stderr.strip()[:160],
    }
    targets = {}
    if image:
        result = _run(
            [
                "podman",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--security-opt",
                "label=disable",
                "-v",
                f"{base}:/mnt",
                image,
                "sh",
                "-c",
                "id -u; cat /proc/self/uid_map; echo rootless > /mnt/f 2>&1; "
                "chown 4242:4242 /mnt/f 2>&1; echo done",
            ]
        )
        evidence["output"] = (result.stdout + result.stderr).strip()[:300]
        after_uid = os.stat(target).st_uid if os.path.exists(target) else None
        evidence["host_file_uid_before"] = before_uid
        evidence["host_file_uid_after"] = after_uid
        # Landing on a uid inside the agent's OWN delegated range is not
        # escalation -- it is the delegation doing exactly what it exists for.
        # Scoring "the uid changed at all" as root-equivalence was a defective
        # test: it reported the safe replacement mechanism as the dangerous one.
        reachable = _reachable_uids()
        evidence["agent_reachable_uid_ranges"] = reachable["description"]
        inside = after_uid is not None and reachable["contains"](after_uid)
        evidence["landed_uid_inside_agent_delegation"] = inside
        targets["B_arbitrary_host_chown"] = after_uid is not None and not inside
        targets["D_transition_outside_delegation"] = targets["B_arbitrary_host_chown"]
    shutil.rmtree(base, ignore_errors=True)
    classification = (
        ROOT_EQUIVALENT if targets.get("B_arbitrary_host_chown") else PRESENT_NON_ESCALATING
    )
    return {
        "classification": classification,
        "evidence": evidence,
        "targets": targets,
        "note": "rootless container root maps to the agent uid or its delegated "
        "subuid range, so it confers nothing the agent does not already "
        "have -- which is exactly why it is a safe replacement for "
        "rootful Docker",
    }


# ------------------------------------------------------------ others
def _reachable_uids() -> dict:
    """The uids the agent principal can already become without escalating."""
    import identity_ranges

    ranges = identity_ranges.agent_reachable_ranges()

    def contains(uid: int) -> bool:
        return any(start <= uid < start + count for start, count in ranges)

    return {
        "ranges": ranges,
        "contains": contains,
        "description": [f"{start}..{start + count - 1}" for start, count in ranges],
    }


def other_container_runtimes(env: dict) -> dict:
    out = {}
    for label in ("containerd", "cri", "lxd", "buildkit", "podman_system"):
        entry = env["container_sockets"].get(label)
        if not entry:
            out[label] = {"classification": NOT_PRESENT}
            continue
        out[label] = {
            "classification": ROOT_EQUIVALENT
            if entry["writable_by_agent"]
            else PRESENT_NON_ESCALATING,
            "evidence": entry,
        }
    return out


def setuid_and_capability_helpers(env: dict) -> dict:
    binaries = env["identity_transition_binaries"]
    interesting = [entry for entry in binaries["setuid_binaries"] if entry["owner_uid"] == 0]
    return {
        "classification": PRESENT_NON_ESCALATING,
        "evidence": {
            "setuid_root_binaries": [entry["path"] for entry in interesting],
            "file_capabilities": binaries["file_capabilities"],
        },
        "targets": {
            "J_alter_own_delegation": False,
            "D_transition_to_authority_uid": "tested in escalations.py",
        },
        "note": "newuidmap/newgidmap carry cap_setuid/cap_setgid and are the "
        "identity-transition path V2 used. They are bounded by "
        "/etc/subuid, which the agent cannot write -- so they reach the "
        "delegated range and nothing else.",
    }


def privileged_helpers_not_exercised(env: dict) -> dict:
    helpers = env["privileged_helpers"]
    present = {name: path for name, path in helpers["binaries"].items() if path}
    return {
        "classification": UNKNOWN,
        "evidence": {
            "present": present,
            "agent_in_wheel_or_sudo": helpers["in_wheel_or_sudo"],
            "sudoers_readable": helpers["sudoers_readable"],
        },
        "targets": {"C_uid_0": UNKNOWN},
        "note": helpers["note"],
        "why_unknown_is_acceptable_here": (
            "UNKNOWN never counts as a pass. It does not need resolving because "
            "Docker already establishes root-equivalence; if Docker were removed "
            "this entry would have to be resolved by the administrator, and the "
            "cutover plan says so."
        ),
    }


def systemd_units(env: dict) -> dict:
    writable = []
    for path in (
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
    ):
        if os.path.isdir(path) and os.access(path, os.W_OK):
            writable.append(path)
    user_dir = os.path.expanduser("~/.config/systemd/user")
    return {
        "classification": ROOT_EQUIVALENT if writable else PRESENT_NON_ESCALATING,
        "evidence": {
            "writable_system_unit_dirs": writable,
            "user_unit_dir": user_dir,
            "user_unit_dir_exists": os.path.isdir(user_dir),
        },
        "note": "user units run as the agent uid and confer nothing new. A "
        "writable system unit directory would be root-equivalent; none is.",
    }


def namespace_handles() -> dict:
    """Whether /proc/*/ns handles of other principals are reachable."""
    reachable = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            st = os.stat(f"/proc/{pid}")
        except OSError:
            continue
        if st.st_uid == os.getuid():
            continue
        try:
            fd = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY)
            os.close(fd)
            reachable.append({"pid": int(pid), "owner_uid": st.st_uid})
        except OSError:
            continue
    return {
        "classification": ROOT_EQUIVALENT if reachable else PRESENT_NON_ESCALATING,
        "evidence": {
            "foreign_namespace_handles_openable": reachable[:10],
            "count": len(reachable),
        },
        "note": "opening another principal's namespace handle requires "
        "ptrace_may_access; a non-empty list would mean the agent can "
        "reach namespaces of principals it does not own",
    }


def build_registry(
    env: dict,
    *,
    active_docker_probe: bool = False,
    acknowledge_disposable: bool = False,
) -> dict:
    registry = {
        "docker_rootful": docker_rootful(
            active=active_docker_probe,
            acknowledge_disposable=acknowledge_disposable,
        ),
        "podman_rootless": podman_rootless(),
        "setuid_capability_helpers": setuid_and_capability_helpers(env),
        "sudo_polkit_interactive": privileged_helpers_not_exercised(env),
        "systemd_units": systemd_units(env),
        "foreign_namespace_handles": namespace_handles(),
    }
    registry.update(other_container_runtimes(env))
    root_equivalent = [
        name for name, entry in registry.items() if entry["classification"] == ROOT_EQUIVALENT
    ]
    authority_equivalent = [
        name for name, entry in registry.items() if entry["classification"] == AUTHORITY_EQUIVALENT
    ]
    unknown = [name for name, entry in registry.items() if entry["classification"] == UNKNOWN]
    import privilege_context

    result = {
        # Binds this registry to the context it was probed from. Without it the
        # same probes run inside a sandbox emit `root_equivalent_paths: []` --
        # a clean registry produced by changing nothing on the host. See
        # `privilege_context.py`; `exclusivity_model.collect()` refuses an
        # inventory whose context is absent or not host-representative.
        "measurement_context": privilege_context.capture(),
        "mechanisms": registry,
        "root_equivalent_paths": root_equivalent,
        "authority_equivalent_paths": authority_equivalent,
        "unknown_paths": unknown,
        "agent_is_root_equivalent": bool(root_equivalent),
        "docker_access_route": docker_access_route(env),
    }
    return identity_pseudonym.pseudonymize(result)


def main() -> int:
    import argparse

    import preflight

    parser = argparse.ArgumentParser()
    parser.add_argument("--active-docker-probe", action="store_true")
    parser.add_argument("--ack-disposable-host", action="store_true")
    args = parser.parse_args()
    if args.ack_disposable_host and not args.active_docker_probe:
        parser.error("--ack-disposable-host requires --active-docker-probe")
    try:
        registry = build_registry(
            preflight.environment(),
            active_docker_probe=args.active_docker_probe,
            acknowledge_disposable=args.ack_disposable_host,
        )
    except ValueError as exc:
        parser.error(str(exc))
    with open(REGISTRY_PATH, "w", encoding="utf-8") as handle:
        json.dump(registry, handle, indent=2, sort_keys=True)
    print(
        json.dumps(
            {name: entry["classification"] for name, entry in registry["mechanisms"].items()},
            indent=2,
        )
    )
    print("root-equivalent:", registry["root_equivalent_paths"])
    print("unknown:", registry["unknown_paths"])
    print("docker route:", registry["docker_access_route"]["routes"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
