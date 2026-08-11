#!/usr/bin/env python3
"""Measurement-context fingerprint: proves *where* a privilege inventory was taken.

Why this exists. The hardened verifier consumes `PRIVILEGE_TOPOLOGY.json` with no
binding to the process context that produced it. Measured on this host:

    context            groups            uid_map               NoNewPrivs  sudo -n -l
    sandboxed shell    65534 65534 1000  "1000 1000 1"         1           "the no new
                                                                            privileges flag
                                                                            is set"
    host shell         10 969 1000       "0 0 4294967295"      0           "a password is
                       (wheel, docker)                                      required"

The host did not change between those two rows -- `getent group docker` returns
`docker:x:969:martin` in both. The *credential the measurement was taken under*
changed. Running `privilege_topology.py` in the sandboxed row emits
`root_equivalent_paths == []`, which is indistinguishable, in the JSON, from a
completed cutover. That is a synthetic PASS reachable with no host mutation at
all, and it is the same defect class as the `bool(root_equivalent_paths)` hole:
a fact recorded and a fact consumed that are not the same fact.

So an inventory is admissible evidence only if it was taken in a context that
represents the host agent identity:

    * uid_map maps the full range (0 0 4294967295) -- not a user-namespace slice
      that hides supplementary gids;
    * NoNewPrivs == 0 -- setuid/setgid transitions are observable;
    * no seccomp filter -- probe syscalls are not silently refused.

Any of the three can suppress a privilege path and make a host look clean.
`exclusivity_model` treats a non-representative inventory as *absent*, which
fails closed to BLOCKED_PRIVILEGE_UNCERTAIN.

Read-only: reads /proc/self and calls no external program.
"""

from __future__ import annotations

import hashlib
import json
import os

EXPECTED_CREDENTIAL_SHA256 = "63cc804c8dd4d4fbef0907e0698e944cefeb926b1578165570ea66166731226e"

#: A uid_map of exactly this shape is the initial user namespace's identity map.
#: Anything else is a namespace slice, and a slice can drop supplementary gids
#: (docker gid 969 vanished from `getgroups()` under one).
FULL_RANGE_MAP = (0, 0, 4294967295)


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        return f"<unreadable: {exc}>"


def _status_fields() -> dict:
    out: dict[str, str] = {}
    wanted = {
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapEff",
        "CapPrm",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    }
    for line in _read("/proc/self/status").splitlines():
        key, _, value = line.partition(":")
        if key in wanted:
            out[key] = value.strip()
    return out


def _parse_map(text: str) -> list[tuple[int, int, int]]:
    rows: list[tuple[int, int, int]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            rows.append((int(parts[0]), int(parts[1]), int(parts[2])))
    return rows


#: The policy surfaces a privilege inventory must be able to *see* before its
#: silence about them means anything. A mount namespace that hides
#: /etc/sudoers.d makes "no sudoers entry found" a statement about the
#: namespace, not the host -- the filesystem twin of the credential problem
#: this module exists for.
VISIBILITY_PROBES = (
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/polkit-1/rules.d",
    "/usr/share/polkit-1/rules.d",
    "/etc/subuid",
    "/etc/subgid",
    "/etc/fstab",
    "/var/run/docker.sock",
    "/proc/self/status",
    "/usr/bin/sudo",
)


def _visibility() -> dict:
    """Can this process see the surfaces it is about to draw conclusions from?

    Distinguishes three states that a bare `os.path.exists` conflates:
    present, absent, and *undetermined* -- the last when a parent directory is
    unsearchable, as /etc/libvirt (0700 root) is here. An undetermined path is
    not an absent one, and a report may not treat it as such.
    """
    out: dict[str, dict] = {}
    for path in VISIBILITY_PROBES:
        entry: dict = {}
        parent = os.path.dirname(path) or "/"
        parent_searchable = os.access(parent, os.R_OK | os.X_OK)
        exists = os.path.exists(path)
        if exists:
            entry["state"] = "PRESENT"
            entry["readable_by_agent"] = os.access(path, os.R_OK)
            try:
                st = os.stat(path)
                entry["mode"] = oct(st.st_mode & 0o7777)
                entry["owner_uid"] = st.st_uid
                entry["owner_gid"] = st.st_gid
            except OSError as exc:
                entry["stat_error"] = str(exc)
        elif parent_searchable:
            entry["state"] = "ABSENT"
        else:
            entry["state"] = "UNDETERMINED"
            entry["why"] = f"{parent} is not searchable by this process"
        entry["parent_searchable"] = parent_searchable
        out[path] = entry
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as handle:
            out["_mountinfo_entries"] = {"count": len(handle.read().splitlines())}
    except OSError as exc:
        out["_mountinfo_entries"] = {"error": str(exc)}
    return out


def _namespaces() -> dict:
    out: dict[str, str] = {}
    try:
        names = sorted(os.listdir("/proc/self/ns"))
    except OSError as exc:
        return {"error": str(exc)}
    for name in names:
        try:
            out[name] = os.readlink(os.path.join("/proc/self/ns", name))
        except OSError as exc:
            out[name] = f"<unreadable: {exc}>"
    return out


def capture() -> dict:
    """Fingerprint the context this process is measuring from."""
    status = _status_fields()
    uid_map = _parse_map(_read("/proc/self/uid_map"))
    gid_map = _parse_map(_read("/proc/self/gid_map"))

    full_uid_map = uid_map == [FULL_RANGE_MAP]
    full_gid_map = gid_map == [FULL_RANGE_MAP]
    no_new_privs = status.get("NoNewPrivs") == "0"
    no_seccomp = status.get("Seccomp", "0") == "0"

    disqualifiers = []
    if not full_uid_map:
        disqualifiers.append(f"uid_map is a namespace slice: {uid_map}")
    if not full_gid_map:
        disqualifiers.append(f"gid_map is a namespace slice: {gid_map}")
    if not no_new_privs:
        disqualifiers.append(
            "NoNewPrivs=1: setuid transitions are refused by the kernel, so "
            "every setuid path would measure as denied regardless of the host"
        )
    if not no_seccomp:
        disqualifiers.append(
            f"a seccomp filter is installed (Seccomp={status.get('Seccomp')}): "
            "probe syscalls may be refused without reaching the host"
        )

    visibility = _visibility()
    hidden = sorted(
        path
        for path, entry in visibility.items()
        if not path.startswith("_") and entry.get("state") == "UNDETERMINED"
    )

    context = {
        "status": status,
        "uid_map": uid_map,
        "gid_map": gid_map,
        "getgroups": sorted(os.getgroups()),
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "capabilities": {
            "inheritable": status.get("CapInh"),
            "effective": status.get("CapEff"),
            "permitted": status.get("CapPrm"),
            "bounding": status.get("CapBnd"),
            "ambient": status.get("CapAmb"),
        },
        "namespaces": _namespaces(),
        "filesystem_visibility": visibility,
        # Not a disqualifier: on this host /etc/sudoers.d and
        # /etc/polkit-1/rules.d are unsearchable by DESIGN, and that is the
        # measured fact driving REQUIRES_OPERATOR_EVIDENCE. It is recorded so a
        # reader can tell "the agent may not read it" from "it is not there".
        "undetermined_paths": hidden,
        "host_representative": not disqualifiers,
        "disqualifiers": disqualifiers,
        "requirement": (
            "uid_map == gid_map == [(0, 0, 4294967295)] and NoNewPrivs == 0 and "
            "Seccomp == 0; an inventory taken outside this context is not "
            "evidence about the host and is treated as absent"
        ),
    }
    payload = json.dumps(
        {
            k: context[k]
            for k in (
                "status",
                "uid_map",
                "gid_map",
                "getgroups",
                "uid",
                "euid",
                # a namespace that hides a policy file must not fingerprint the
                # same as one that can read it
                "filesystem_visibility",
            )
        },
        sort_keys=True,
    )
    context["fingerprint_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
    context["credential_sha256"] = credential_digest(context)
    context["host_representative"] = is_host_representative(context)
    if not context["host_representative"]:
        context["disqualifiers"].append(
            "recomputed credential does not match EXPECTED_CREDENTIAL.json"
        )
    return context


def _quad(value: object) -> list[int] | None:
    if not isinstance(value, str):
        return None
    parts = value.split()
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return None
    return [int(part) for part in parts]


def credential_from_context(context: dict | None) -> dict | None:
    """Recompute the complete Linux credential from raw recorded fields."""
    if not isinstance(context, dict):
        return None
    status = context.get("status")
    namespaces = context.get("namespaces")
    if not isinstance(status, dict) or not isinstance(namespaces, dict):
        return None
    uids = _quad(status.get("Uid"))
    gids = _quad(status.get("Gid"))
    groups = status.get("Groups")
    required_caps = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    if (
        uids is None
        or gids is None
        or not isinstance(groups, str)
        or not all(isinstance(status.get(key), str) for key in required_caps)
    ):
        return None
    try:
        supplementary = sorted(int(item) for item in groups.split())
        no_new_privs = int(status["NoNewPrivs"])
        seccomp_mode = int(status["Seccomp"])
        seccomp_filters = int(status["Seccomp_filters"])
    except (KeyError, TypeError, ValueError):
        return None
    uid_map = context.get("uid_map")
    gid_map = context.get("gid_map")
    user_namespace = namespaces.get("user")
    if not isinstance(uid_map, list) or not isinstance(gid_map, list):
        return None
    if not isinstance(user_namespace, str):
        return None
    return {
        "uids": dict(zip(("real", "effective", "saved", "filesystem"), uids, strict=True)),
        "gids": dict(zip(("real", "effective", "saved", "filesystem"), gids, strict=True)),
        "supplementary_gids": supplementary,
        "capabilities": {
            "inheritable": status["CapInh"],
            "permitted": status["CapPrm"],
            "effective": status["CapEff"],
            "bounding": status["CapBnd"],
            "ambient": status["CapAmb"],
        },
        "no_new_privs": no_new_privs,
        "seccomp_mode": seccomp_mode,
        "seccomp_filters": seccomp_filters,
        "uid_map": uid_map,
        "gid_map": gid_map,
        "user_namespace": user_namespace,
    }


def credential_digest(context: dict | None) -> str | None:
    credential = credential_from_context(context)
    if credential is None:
        return None
    payload = json.dumps(credential, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def is_host_representative(context: dict | None) -> bool:
    """Accept only a recomputed credential matching the sealed expected digest."""
    return credential_digest(context) == EXPECTED_CREDENTIAL_SHA256


def main() -> int:
    context = capture()
    print(json.dumps(context, indent=1, sort_keys=True))
    representative = is_host_representative(context)
    print(f"\nhost_representative: {representative}")
    for item in context["disqualifiers"]:
        print(f"  - {item}")
    return 0 if representative else 1


if __name__ == "__main__":
    raise SystemExit(main())
