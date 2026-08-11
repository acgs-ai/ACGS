#!/usr/bin/env python3
"""Complete read-only privilege topology inventory for the agent principal.

Scope, per the hardening task: supplementary groups, container runtime control
(rootful and rootless), sudo configuration, sudoers.d, polkit rules, pkexec
authorization, systemd escalation paths, and setuid binaries relevant to
privilege acquisition.

Discipline, unchanged from the rest of this package:

    ROOT_EQUIVALENT       measured to confer uid-0-equivalent authority
    NON_ROOT_EQUIVALENT   measured NOT to confer it, with the measurement stated
    UNKNOWN               not established -- never a pass, always blocking

Nothing here mutates. Sockets are connected to and closed without sending a
byte, which measures reachability without invoking any API. No authentication
gate is exercised: a path that requires a password or a polkit prompt is
recorded UNKNOWN and left for an administrator, because guessing is not
measurement and passing an auth gate is outside this task's authority.
"""

from __future__ import annotations

import glob
import grp
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys

import identity_pseudonym

HERE = os.path.dirname(os.path.abspath(__file__))
TOPOLOGY_PATH = os.path.join(HERE, "PRIVILEGE_TOPOLOGY.json")

ROOT_EQUIVALENT = "ROOT_EQUIVALENT"
NON_ROOT_EQUIVALENT = "NON_ROOT_EQUIVALENT"
UNKNOWN = "UNKNOWN"

SETUID_SEARCH_ROOTS = ("/usr", "/bin", "/sbin", "/opt", "/var")

# Groups whose membership is a documented route to root-equivalent authority on
# a typical Linux host. Membership alone is not proof -- each is measured below
# where a measurement exists -- but membership plus an unmeasured mechanism is
# UNKNOWN, never NON_ROOT_EQUIVALENT.
ESCALATING_GROUPS = {
    "docker": "controls a rootful container daemon",
    "lxd": "controls a container daemon that can mount the host filesystem",
    "libvirt": "controls a hypervisor that can attach host block devices",
    "kvm": "raw VM control",
    "disk": "raw block device access bypasses every filesystem permission",
    "root": "the root group",
    "sudo": "sudoers group on Debian-family hosts",
    "wheel": "sudo/polkit administrator group on RPM-family hosts",
    "adm": "reads privileged logs; not itself uid 0",
}

# setuid-root binaries whose escalation is gated on an authentication factor the
# agent does not hold. Present, unexercised, and therefore UNKNOWN.
AUTH_GATED_SETUID = {
    "sudo",
    "su",
    "pkexec",
    "passwd",
    "chsh",
    "chfn",
    "gpasswd",
    "newgrp",
    "chage",
    "unix_chkpwd",
}

# setuid-root binaries whose privilege is bounded by a delegation or a narrow
# kernel operation, measured elsewhere in this package or bounded by design.
BOUNDED_SETUID = {
    "newuidmap": "bounded by /etc/subuid; V3 measured it refusing uid 940",
    "newgidmap": "bounded by /etc/subgid",
    "mount": "bounded by fstab 'user' entries",
    "umount": "bounded by fstab 'user' entries",
    "fusermount": "bounded to the caller's own FUSE mounts",
    "fusermount3": "bounded to the caller's own FUSE mounts",
    "ping": "raw socket only",
    "pam_timestamp_check": "timestamp file only",
    "grub2-set-bootflag": "writes one bootflag byte",
}


def run(cmd: list[str], timeout: int = 30) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "argv": cmd,
            "rc": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except FileNotFoundError:
        return {"argv": cmd, "rc": None, "error": "not_found"}
    except subprocess.TimeoutExpired:
        return {"argv": cmd, "rc": None, "error": "timeout"}


def path_facts(path: str) -> dict:
    try:
        st = os.stat(path)
    except OSError as exc:
        return {"path": path, "exists": False, "error": str(exc)}
    return {
        "path": path,
        "exists": True,
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "owner_uid": st.st_uid,
        "owner_gid": st.st_gid,
        "setuid": bool(st.st_mode & stat.S_ISUID),
        "readable_by_agent": os.access(path, os.R_OK),
        "writable_by_agent": os.access(path, os.W_OK),
    }


def socket_reachable(path: str) -> dict:
    """Connect and close. No bytes sent, no API invoked, nothing mutated."""
    facts = path_facts(path)
    if not facts.get("exists"):
        return {**facts, "connect": "ABSENT"}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect(path)
        facts["connect"] = "ACCEPTED"
    except OSError as exc:
        facts["connect"] = f"REFUSED: {exc.strerror or exc}"
    finally:
        sock.close()
    return facts


def entry(
    name: str,
    classification: str,
    evidence: dict,
    why: str,
    resolves: str | None = None,
) -> dict:
    out = {"classification": classification, "evidence": evidence, "why": why}
    if resolves:
        out["resolved_by"] = resolves
    return out


# --------------------------------------------------------------------------
# 1. groups


def audit_groups() -> dict:
    gids = os.getgroups()
    names = []
    for gid in gids:
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            names.append(f"UNALLOCATED_GID_{gid}")
    held = sorted(set(names) & set(ESCALATING_GROUPS))
    return {
        "kernel_credential_gids": sorted(gids),
        "kernel_credential_groups": sorted(names),
        "escalating_groups_held": {g: ESCALATING_GROUPS[g] for g in held},
        "note": "read from os.getgroups(); the `id` utility can disagree inside "
        "a sandboxed launcher, which is why the kernel credential is "
        "the source here",
    }


# --------------------------------------------------------------------------
# 2. container runtimes


def audit_container_runtimes(groups: dict) -> dict:
    paths = {}
    dock = socket_reachable("/var/run/docker.sock")
    docker_cli = (
        run(["docker", "info", "--format", "{{.Name}}"])
        if shutil.which("docker")
        else {"error": "not_present"}
    )
    rootless = None
    if docker_cli.get("rc") == 0:
        sec = run(["docker", "info", "--format", "{{.SecurityOptions}}"])
        rootless = "rootless" in sec.get("stdout", "").lower()

    reachable = dock.get("connect") == "ACCEPTED"
    if reachable and rootless is False:
        paths["docker_rootful_socket"] = entry(
            "docker_rootful_socket",
            ROOT_EQUIVALENT,
            {
                "socket": dock,
                "docker_info_rc": docker_cli.get("rc"),
                "rootless": rootless,
                "corroborating_measurement": (
                    "ROOT_EQUIVALENT_REGISTRY.json: a container started "
                    "through this socket reported uid_map 0 0 4294967295 and "
                    "chowned a host file to uid 4242"
                ),
            },
            "the daemon runs as uid 0 and executes container specifications "
            "chosen by whoever reaches the socket, including bind mounts of / "
            "with label=disable",
            "remove the agent from group 'docker' and any ACL on the socket",
        )
    elif reachable and rootless:
        paths["docker_rootless_socket"] = entry(
            "docker_rootless_socket",
            NON_ROOT_EQUIVALENT,
            {"socket": dock, "rootless": True},
            "a rootless daemon's container root maps into the caller's own uid "
            "or delegated subuid range, conferring nothing it does not have",
        )
    elif dock.get("exists"):
        paths["docker_socket_present_unreachable"] = entry(
            "docker_socket_present_unreachable",
            NON_ROOT_EQUIVALENT,
            {"socket": dock},
            "socket exists but connect() was refused for this credential",
        )

    ctr = socket_reachable("/run/containerd/containerd.sock")
    paths["containerd_socket"] = entry(
        "containerd_socket",
        ROOT_EQUIVALENT if ctr.get("connect") == "ACCEPTED" else NON_ROOT_EQUIVALENT,
        {"socket": ctr},
        "containerd runs as uid 0; reaching its socket is equivalent to reaching the docker socket",
    )

    for label, sock_path in (
        ("podman_rootless_user_socket", f"/run/user/{os.getuid()}/podman/podman.sock"),
        ("podman_system_socket", "/run/podman/podman.sock"),
    ):
        info = socket_reachable(sock_path)
        if not info.get("exists"):
            continue
        if label.startswith("podman_rootless"):
            paths[label] = entry(
                label,
                NON_ROOT_EQUIVALENT,
                {"socket": info},
                "rootless podman container root maps into the agent's own "
                "delegated subuid range; V3 measured a chown landing on host "
                "uid 528529, inside agent-user:524288:65536",
            )
        else:
            paths[label] = entry(
                label,
                ROOT_EQUIVALENT if info.get("connect") == "ACCEPTED" else NON_ROOT_EQUIVALENT,
                {"socket": info},
                "the podman system service runs as uid 0 when socket-activated",
            )

    # DAC-authorised daemons: the socket permission IS the authorisation, so a
    # completed connect() is the whole escalation.
    for label, sock_path in (
        ("lxd", "/var/lib/lxd/unix.socket"),
        ("buildkit", "/run/buildkit/buildkitd.sock"),
        ("cri", "/run/crio/crio.sock"),
    ):
        info = path_facts(sock_path)
        if info.get("exists"):
            reach = socket_reachable(sock_path)
            paths[f"{label}_socket"] = entry(
                f"{label}_socket",
                ROOT_EQUIVALENT if reach.get("connect") == "ACCEPTED" else NON_ROOT_EQUIVALENT,
                {"socket": reach},
                f"{label} runs as uid 0 and authorises by socket permission "
                f"alone, so a completed connect is the escalation",
            )

    # Authorisation-layered daemons: the socket is deliberately world-connectable
    # and the decision is made by polkit per RPC. A completed connect() proves
    # reachability and NOTHING about authority -- classifying it ROOT_EQUIVALENT
    # would be an over-claim in the alarming direction, and NON_ROOT_EQUIVALENT
    # would be an over-claim in the flattering one. It is UNKNOWN.
    for label, sock_path in (
        ("libvirt", "/var/run/libvirt/libvirt-sock"),
        ("libvirt_ro", "/var/run/libvirt/libvirt-sock-ro"),
    ):
        info = path_facts(sock_path)
        if not info.get("exists"):
            continue
        reach = socket_reachable(sock_path)
        active = run(["systemctl", "is-active", "libvirtd", "virtqemud"])
        paths[f"{label}_socket"] = entry(
            f"{label}_socket",
            UNKNOWN if reach.get("connect") == "ACCEPTED" else NON_ROOT_EQUIVALENT,
            {"socket": reach, "daemon_active": active.get("stdout")},
            "libvirt's socket is world-connectable by design (0666) and "
            "socket-activated; authorisation happens at the RPC layer via "
            "polkit, which was not exercised. A libvirt session that IS "
            "authorised can attach host block devices and is root-equivalent, "
            "so this cannot be dismissed either",
            "administrator checks the libvirt auth_unix_rw setting in "
            "/etc/libvirt/libvirtd.conf and the org.libvirt.unix.manage polkit "
            "action for the agent's groups",
        )

    docker_group_held = "docker" in groups["escalating_groups_held"]
    return {
        "paths": paths,
        "docker_group_held": docker_group_held,
        "rootless_docker": rootless,
    }


# --------------------------------------------------------------------------
# 3-4. sudo, sudoers.d


def audit_sudo() -> dict:
    paths = {}
    if not shutil.which("sudo"):
        paths["sudo"] = entry(
            "sudo", NON_ROOT_EQUIVALENT, {"present": False}, "sudo is not installed"
        )
        return {"paths": paths}

    probe = run(["sudo", "-n", "-l"], timeout=15)
    readable = {p: path_facts(p) for p in ("/etc/sudoers",)}
    drop_in = {}
    try:
        for path in sorted(glob.glob("/etc/sudoers.d/*")):
            drop_in[path] = path_facts(path)
    except OSError as exc:
        drop_in["error"] = str(exc)
    dir_facts = path_facts("/etc/sudoers.d")
    readable_any = readable["/etc/sudoers"].get("readable_by_agent") or any(
        isinstance(v, dict) and v.get("readable_by_agent") for v in drop_in.values()
    )

    if probe.get("rc") == 0:
        paths["sudo"] = entry(
            "sudo",
            ROOT_EQUIVALENT,
            {"probe": probe},
            "`sudo -n -l` succeeded without a password: at least one command "
            "is available NOPASSWD, which is a live escalation path",
        )
    else:
        paths["sudo"] = entry(
            "sudo",
            UNKNOWN,
            {
                "probe": probe,
                "sudoers": readable["/etc/sudoers"],
                "sudoers_d": dir_facts,
                "sudoers_d_entries": drop_in,
                "policy_readable_by_agent": bool(readable_any),
            },
            "sudo is installed and the non-interactive probe was refused with "
            "an authentication demand. Whether this credential is authorised "
            "cannot be read: the policy files are not agent-readable, and "
            "exercising the password gate is outside this task's authority",
            "administrator runs `sudo -l -U <user>` and reads /etc/sudoers plus /etc/sudoers.d/*",
        )
    return {"paths": paths}


# --------------------------------------------------------------------------
# 5-6. polkit rules and pkexec


def audit_polkit() -> dict:
    paths = {}
    pkexec = shutil.which("pkexec")
    rules: dict[str, dict] = {}
    for pattern in (
        "/etc/polkit-1/rules.d/*",
        "/usr/share/polkit-1/rules.d/*",
        "/etc/polkit-1/localauthority/*/*",
        "/var/lib/polkit-1/*",
    ):
        for path in sorted(glob.glob(pattern)):
            rules[path] = path_facts(path)
    readable_rules = {p: f for p, f in rules.items() if f.get("readable_by_agent")}

    # Read only what is already world-readable; look for rules that name the
    # administrator groups this credential is in.
    admin_group_hits: dict[str, list[str]] = {}
    my_groups = set()
    for gid in os.getgroups():
        try:
            my_groups.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    for path in readable_rules:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        hits = [g for g in my_groups if g in text]
        if hits:
            admin_group_hits[path] = sorted(hits)

    if pkexec:
        facts = path_facts(pkexec)
        paths["pkexec"] = entry(
            "pkexec",
            UNKNOWN,
            {
                "binary": facts,
                "polkit_rule_files": len(rules),
                "agent_readable_rule_files": len(readable_rules),
                "rules_naming_a_group_this_credential_holds": admin_group_hits,
                "authority_of_org.freedesktop.policykit.exec": "not queried",
            },
            "pkexec is setuid root and defers to polkit. Whether this "
            "credential is authorised for org.freedesktop.policykit.exec "
            "depends on rules that are partly unreadable here, and the "
            "authorisation itself is an interactive prompt that was not "
            "exercised",
            "administrator enumerates `pkaction --verbose`, reads "
            "/etc/polkit-1/rules.d and confirms which actions allow_active "
            "for the agent's groups",
        )
    else:
        paths["pkexec"] = entry(
            "pkexec", NON_ROOT_EQUIVALENT, {"present": False}, "pkexec is not installed"
        )

    dbus = path_facts("/run/dbus/system_bus_socket")
    if dbus.get("exists"):
        paths["dbus_system_bus"] = entry(
            "dbus_system_bus",
            UNKNOWN,
            {
                "socket": dbus,
                "reachable": socket_reachable("/run/dbus/system_bus_socket").get("connect"),
            },
            "the system bus exposes privileged services (systemd1, "
            "hostname1, packagekit) whose authorisation is polkit-mediated; "
            "which methods this credential may call was not enumerated and "
            "cannot be assumed",
            "administrator enumerates polkit actions for the bus services and "
            "confirms none grant unit control or file writes to the agent",
        )
    return {"paths": paths}


# --------------------------------------------------------------------------
# 7. systemd


def audit_systemd() -> dict:
    paths = {}
    if not shutil.which("systemctl"):
        return {
            "paths": {
                "systemd": entry(
                    "systemd",
                    NON_ROOT_EQUIVALENT,
                    {"present": False},
                    "systemd is not present",
                )
            }
        }

    unit_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
    ]
    writable_dirs = {d: path_facts(d) for d in unit_dirs}
    writable = [d for d, f in writable_dirs.items() if f.get("writable_by_agent")]

    # A root service whose executable (or its directory) the agent can write is
    # a full escalation on the next restart. This is the check that catches a
    # "hidden" path nobody declared.
    listing = run(
        [
            "systemctl",
            "show",
            "--property=Id",
            "--property=User",
            "--property=ExecStart",
            "--all",
            "--type=service",
        ],
        timeout=60,
    )
    writable_execstart = []
    current: dict[str, str] = {}
    for line in listing.get("stdout", "").splitlines():
        if not line.strip():
            if current:
                _classify_unit(current, writable_execstart)
                current = {}
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key] = value
    if current:
        _classify_unit(current, writable_execstart)

    if writable or writable_execstart:
        paths["systemd_unit_control"] = entry(
            "systemd_unit_control",
            ROOT_EQUIVALENT,
            {
                "agent_writable_unit_dirs": writable,
                "root_services_with_agent_writable_exec": writable_execstart,
            },
            "a unit that runs as uid 0 whose definition or executable the "
            "agent can write is root on the next start",
        )
    else:
        paths["systemd_unit_control"] = entry(
            "systemd_unit_control",
            NON_ROOT_EQUIVALENT,
            {"unit_dirs": writable_dirs, "root_services_with_agent_writable_exec": []},
            "no system unit directory is agent-writable and no root service "
            "has an agent-writable executable",
        )

    if shutil.which("systemd-run"):
        paths["systemd_run"] = entry(
            "systemd_run",
            UNKNOWN,
            {
                "binary": path_facts(shutil.which("systemd-run")),
                "note": "`systemd-run --user` is not escalation; `systemd-run` "
                "against the system manager is polkit-mediated and was "
                "not exercised",
            },
            "starting a transient system unit would run as uid 0; whether "
            "polkit authorises this credential to do so is the same "
            "unresolved question as pkexec",
            "resolved together with the polkit enumeration",
        )
    return {"paths": paths}


def _classify_unit(unit: dict, sink: list) -> None:
    user = unit.get("User", "")
    if user not in ("", "root"):
        return
    exec_start = unit.get("ExecStart", "")
    if "path=" not in exec_start:
        return
    binary = exec_start.split("path=", 1)[1].split(";", 1)[0].strip()
    if not binary or not binary.startswith("/"):
        return
    if os.access(binary, os.W_OK) or os.access(os.path.dirname(binary), os.W_OK):
        sink.append(
            {
                "unit": unit.get("Id"),
                "binary": binary,
                "binary_writable": os.access(binary, os.W_OK),
                "dir_writable": os.access(os.path.dirname(binary), os.W_OK),
            }
        )


# --------------------------------------------------------------------------
# 8. setuid binaries


def audit_setuid() -> dict:
    found = []
    for root in SETUID_SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        res = run(
            ["find", root, "-xdev", "-type", "f", "-perm", "-4000", "-print"],
            timeout=180,
        )
        for line in res.get("stdout", "").splitlines():
            if line.strip():
                found.append(line.strip())
    found = sorted(set(found))

    classified = {}
    for path in found:
        name = os.path.basename(path)
        facts = path_facts(path)
        if facts.get("owner_uid") != 0:
            classified[path] = entry(
                path,
                NON_ROOT_EQUIVALENT,
                facts,
                f"setuid to uid {facts.get('owner_uid')}, not root",
            )
        elif facts.get("writable_by_agent"):
            classified[path] = entry(
                path,
                ROOT_EQUIVALENT,
                facts,
                "a setuid-root binary the agent can write is direct root",
            )
        elif name in BOUNDED_SETUID:
            classified[path] = entry(path, NON_ROOT_EQUIVALENT, facts, BOUNDED_SETUID[name])
        elif name in AUTH_GATED_SETUID:
            classified[path] = entry(
                path,
                UNKNOWN,
                facts,
                "setuid root, escalation gated on an authentication factor that was not exercised",
                "administrator confirms the local policy for this binary",
            )
        else:
            classified[path] = entry(
                path,
                UNKNOWN,
                facts,
                "setuid root and not on this package's measured-bounded list; "
                "unrecognised is UNKNOWN, not safe",
                "administrator classifies this binary",
            )
    return {"count": len(found), "paths": classified}


# --------------------------------------------------------------------------

#: Capabilities that confer authority over other principals' files, processes
#: or credentials. Any of these in a file's PERMITTED set is uid-0-adjacent.
ESCALATING_CAPS = {
    "cap_setuid": "assumes any uid, including 0",
    "cap_setgid": "assumes any gid",
    "cap_dac_override": "bypasses every file permission check",
    "cap_dac_read_search": "reads every file, /etc/shadow included",
    "cap_fowner": "bypasses ownership checks on chmod/chown-adjacent ops",
    "cap_chown": "reassigns ownership of any file",
    "cap_sys_admin": "the catch-all capability; mount, namespaces, more",
    "cap_sys_module": "loads kernel modules",
    "cap_sys_ptrace": "attaches to any process, including root's",
    "cap_mknod": "creates device nodes, including raw disks",
    "cap_sys_rawio": "raw device access bypasses the filesystem",
    "cap_bpf": "loads BPF programs",
    "cap_perfmon": "system-wide performance instrumentation",
}

#: Capabilities whose effect is bounded to networking or scheduling. Present on
#: ordinary tools; not authority over another principal's state.
BOUNDED_CAPS = {
    "cap_net_raw",
    "cap_net_bind_service",
    "cap_net_admin",
    "cap_sys_nice",
    "cap_ipc_lock",
    "cap_wake_alarm",
}

#: File capabilities measured elsewhere in this package to be delegation-bound.
BOUNDED_CAP_BINARIES = {
    "newuidmap": "bounded by /etc/subuid; V3 measured it refusing uid 940",
    "newgidmap": "bounded by /etc/subgid",
}

CAP_SEARCH_ROOTS = ("/usr", "/bin", "/sbin", "/opt", "/var")


def parse_caps(text: str) -> dict:
    """Split a getcap string into its capability set and its flags.

    `cap_setuid=ep` and `cap_setuid=ei` are not the same finding. Permitted (p)
    means the file grants the capability on exec; inheritable-only (i, without
    p) grants nothing unless the *caller* already holds it in its own
    inheritable set, so the agent's CapInh is part of the measurement.
    """
    caps, _, flags = text.rpartition("=")
    return {
        "raw": text,
        "capabilities": sorted(c.strip() for c in caps.split(",") if c.strip()),
        "flags": flags.strip(),
        "permitted": "p" in flags,
        "effective": "e" in flags,
        "inheritable_only": "p" not in flags and "i" in flags,
    }


def audit_file_capabilities() -> dict:
    """File capabilities: root-equivalent authority with no setuid bit.

    `audit_setuid` searches `-perm -4000` and therefore cannot see any of
    these. On this host that blind spot hid 11 binaries, one of them
    `/usr/bin/suexec cap_setgid,cap_setuid=ep` -- uid transition authority that
    the setuid sweep is structurally incapable of finding. An inventory that
    does not enumerate this surface is silent about it, and silence is not
    absence.
    """
    getcap = shutil.which("getcap")
    if not getcap:
        return {
            "count": 0,
            "tool_available": False,
            "paths": {
                "capability_sweep": entry(
                    "capability_sweep",
                    UNKNOWN,
                    {"getcap": "not installed"},
                    "the file-capability surface could not be enumerated",
                    "administrator runs `getcap -r /` and classifies the result",
                )
            },
        }

    agent_inheritable = ""
    for line in _proc_status().splitlines():
        if line.startswith("CapInh:"):
            agent_inheritable = line.split(":", 1)[1].strip()

    found: dict[str, str] = {}
    for root in CAP_SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        res = run([getcap, "-r", root], timeout=300)
        for line in res.get("stdout", "").splitlines():
            path, _, caps = line.strip().partition(" ")
            if path and caps:
                found[path] = caps.strip()

    classified = {}
    for path, caps_text in sorted(found.items()):
        parsed = parse_caps(caps_text)
        facts = path_facts(path)
        facts["capabilities"] = parsed
        facts["agent_cap_inheritable"] = agent_inheritable
        name = os.path.basename(path)
        escalating = sorted(set(parsed["capabilities"]) & set(ESCALATING_CAPS))
        bounded = set(parsed["capabilities"]) <= BOUNDED_CAPS

        if facts.get("writable_by_agent"):
            classified[path] = entry(
                path,
                ROOT_EQUIVALENT,
                facts,
                "a capability-bearing binary the agent can write is direct "
                "privilege: the agent chooses the code that runs with it",
            )
        elif not escalating and bounded:
            classified[path] = entry(
                path,
                NON_ROOT_EQUIVALENT,
                facts,
                "every capability on this file is bounded to networking or "
                f"scheduling ({parsed['capabilities']}); none confers "
                "authority over another principal's files, processes or "
                "credentials",
            )
        elif name in BOUNDED_CAP_BINARIES:
            classified[path] = entry(path, NON_ROOT_EQUIVALENT, facts, BOUNDED_CAP_BINARIES[name])
        elif parsed["inheritable_only"]:
            classified[path] = entry(
                path,
                UNKNOWN,
                facts,
                "the escalating capabilities "
                f"{escalating} are inheritable-only (flags "
                f"'{parsed['flags']}'), so the file grants them only to a "
                "caller that already holds them. The agent's CapInh is "
                f"{agent_inheritable}; whether that intersects these "
                "capabilities decides it, and the decision was not exercised",
                "administrator confirms the agent's inheritable set cannot "
                "activate these capabilities",
            )
        else:
            classified[path] = entry(
                path,
                UNKNOWN,
                facts,
                f"file capabilities {escalating} in the permitted set: "
                + "; ".join(ESCALATING_CAPS[c] for c in escalating),
                "administrator confirms whether caller-controlled input can "
                "reach the privileged effect, or removes the file capability",
            )
    return {
        "count": len(found),
        "tool_available": True,
        "agent_cap_inheritable": agent_inheritable,
        "paths": classified,
    }


def _proc_status() -> str:
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def build() -> dict:
    groups = audit_groups()
    sections = {
        "groups": {"summary": groups, "paths": _group_paths(groups)},
        "container_runtimes": audit_container_runtimes(groups),
        "sudo": audit_sudo(),
        "polkit": audit_polkit(),
        "systemd": audit_systemd(),
        "setuid": audit_setuid(),
        "filecaps": audit_file_capabilities(),
    }

    all_paths: dict[str, dict] = {}
    surface_results: dict[str, dict] = {}
    for section, body in sections.items():
        paths = body.get("paths") if isinstance(body, dict) else None
        completed = isinstance(paths, dict)
        surface_results[section] = {
            "status": "SUCCESS" if completed else "ERROR",
            "completed": completed,
            "path_count": len(paths) if completed else 0,
        }
        for name, item in (paths or {}).items():
            all_paths[f"{section}:{name}"] = item

    root_equivalent = sorted(
        k for k, v in all_paths.items() if v["classification"] == ROOT_EQUIVALENT
    )
    unknown = sorted(k for k, v in all_paths.items() if v["classification"] == UNKNOWN)
    non_root = sorted(k for k, v in all_paths.items() if v["classification"] == NON_ROOT_EQUIVALENT)

    result = {
        "read_only": True,
        "mutations_performed": [],
        "agent": {"uid": os.getuid(), "user": pwd.getpwuid(os.getuid()).pw_name},
        "sections": sections,
        "paths": all_paths,
        "surface_results": surface_results,
        "root_equivalent_paths": root_equivalent,
        "unknown_privilege_paths": unknown,
        "non_root_equivalent_paths": non_root,
        "counts": {
            "total": len(all_paths),
            "root_equivalent": len(root_equivalent),
            "unknown": len(unknown),
            "non_root_equivalent": len(non_root),
        },
        "classification_rule": {
            ROOT_EQUIVALENT: "measured to confer uid-0-equivalent authority",
            NON_ROOT_EQUIVALENT: "measured not to, with the measurement stated",
            UNKNOWN: "not established; blocking, never a pass",
        },
    }
    return identity_pseudonym.pseudonymize(result)


def _group_paths(groups: dict) -> dict:
    """Group membership is a route, not a mechanism.

    Membership of an escalating group is recorded as a path in its own right so
    that removing the mechanism while leaving the membership -- or the reverse
    -- cannot silently produce a clean inventory.
    """
    out = {}
    for name, why in groups["escalating_groups_held"].items():
        if name in ("wheel", "sudo", "adm"):
            out[f"membership_{name}"] = entry(
                f"membership_{name}",
                UNKNOWN,
                {"group": name, "held": True},
                f"member of '{name}': {why}. Whether it grants root here "
                f"depends on sudoers/polkit policy that is not agent-readable",
                "administrator reads the local sudo and polkit policy",
            )
        else:
            out[f"membership_{name}"] = entry(
                f"membership_{name}",
                ROOT_EQUIVALENT,
                {"group": name, "held": True},
                f"member of '{name}': {why}",
            )
    return out


def main() -> int:
    topology = build()
    if "--stdout" in sys.argv:
        json.dump(topology, sys.stdout, indent=1, sort_keys=True)
        print()
    else:
        with open(TOPOLOGY_PATH, "w", encoding="utf-8") as handle:
            json.dump(topology, handle, indent=1, sort_keys=True)
    print(f"paths: {topology['counts']}", file=sys.stderr)
    print(f"ROOT_EQUIVALENT: {topology['root_equivalent_paths']}", file=sys.stderr)
    print(f"UNKNOWN:         {topology['unknown_privilege_paths']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
