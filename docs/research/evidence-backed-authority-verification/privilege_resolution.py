#!/usr/bin/env python3
"""Resolve every UNKNOWN privilege path into a terminal classification.

Input:  PRIVILEGE_TOPOLOGY.json      (the "before" inventory, 36 UNKNOWN)
Output: PRIVILEGE_TOPOLOGY_FINAL.json

Four terminal states, and only four:

    ROOT_EQUIVALENT             measured to confer uid-0-equivalent authority
    NON_ROOT_EQUIVALENT         measured to be bounded, with the bound named
    NOT_PRESENT                 the mechanism does not exist on this host
    REQUIRES_OPERATOR_EVIDENCE  the discriminator is a fact the agent cannot
                                read; the exact command that answers it is
                                recorded

REQUIRES_OPERATOR_EVIDENCE IS NOT A PASS. It is the honest name for what was
previously UNKNOWN, and it blocks exactly as hard: `exclusivity_model` unions it
into the blocking set. Renaming 36 UNKNOWNs into it and reporting "0 UNKNOWN"
would be laundering, which is why the counts below report both the terminal
classification and the blocking status, and why the regression suite asserts
that operator-evidence paths can never reach VERIFIED.

Every classification here is produced by a *discriminator*: a specific fact,
read from a specific place, that decides the question. Where no discriminator is
readable, the path lands in REQUIRES_OPERATOR_EVIDENCE rather than being argued
into a bucket. `_DEFAULT` for an unrecognised setuid binary is
REQUIRES_OPERATOR_EVIDENCE, so adding a new setuid binary to this host makes the
verdict worse, never better.

Read-only. Executes `rpm` queries and `pkaction` (both enumeration-only), reads
world-readable policy files, and mutates nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import privilege_context  # noqa: E402

BEFORE = os.path.join(HERE, "PRIVILEGE_TOPOLOGY.json")
AFTER = os.path.join(HERE, "PRIVILEGE_TOPOLOGY_FINAL.json")

ROOT_EQUIVALENT = "ROOT_EQUIVALENT"
NON_ROOT_EQUIVALENT = "NON_ROOT_EQUIVALENT"
NOT_PRESENT = "NOT_PRESENT"
OPERATOR = "REQUIRES_OPERATOR_EVIDENCE"
UNKNOWN = "UNKNOWN"

TERMINAL = (ROOT_EQUIVALENT, NON_ROOT_EQUIVALENT, NOT_PRESENT, OPERATOR)
#: Anything in here forbids a closure claim.
BLOCKING = (ROOT_EQUIVALENT, OPERATOR, UNKNOWN)


def run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "argv": cmd,
            "rc": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"argv": cmd, "error": str(exc)}


def readable(path: str) -> dict:
    """Whether a policy file can be read, and its content if so.

    Three states, not two. `/etc/libvirt` is 0700 root, so `os.path.exists`
    returns False for `/etc/libvirt/libvirtd.conf` whether the file is there or
    not: its existence is UNDETERMINED. Reporting that as ABSENT would turn "the
    agent may not look" into "there is nothing there" -- the same substitution
    of silence for absence this package exists to prevent.
    """
    parent = os.path.dirname(path) or "/"
    parent_searchable = os.access(parent, os.R_OK | os.X_OK)
    out: dict = {
        "path": path,
        "exists": os.path.exists(path),
        "parent_searchable": parent_searchable,
    }
    if not out["exists"]:
        out["state"] = "ABSENT" if parent_searchable else "UNDETERMINED"
        if not parent_searchable:
            out["why"] = f"{parent} is not searchable by the agent"
        return out
    out["state"] = "PRESENT"
    try:
        st = os.stat(path)
        out["mode"] = oct(stat.S_IMODE(st.st_mode))
        out["owner_uid"] = st.st_uid
    except OSError as exc:
        out["stat_error"] = str(exc)
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            out["content"] = handle.read()
        out["readable_by_agent"] = True
    except OSError as exc:
        out["readable_by_agent"] = False
        out["read_error"] = str(exc)
    return out


def dir_writable_by_agent(path: str) -> dict:
    out: dict = {"path": path, "exists": os.path.isdir(path)}
    if out["exists"]:
        try:
            st = os.stat(path)
            out["mode"] = oct(stat.S_IMODE(st.st_mode))
            out["owner_uid"] = st.st_uid
        except OSError as exc:
            out["stat_error"] = str(exc)
        out["writable_by_agent"] = os.access(path, os.W_OK)
    return out


#: rpm records file digests with whatever algorithm the package was built with.
#: 1Password's package on this host uses MD5 (32 hex chars) while Fedora's use
#: SHA256 (64) -- comparing a SHA256 against an MD5 produced a false MISMATCH on
#: the first run of this program. The digest's own length selects the algorithm.
DIGEST_ALGOS = {32: "md5", 40: "sha1", 64: "sha256"}


def hash_file(path: str, algo: str = "sha256") -> str | None:
    try:
        digest = hashlib.new(algo)
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def sha256_file(path: str) -> str | None:
    return hash_file(path, "sha256")


def load_json(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


class Facts:
    """Every host fact the rules below consult, measured once."""

    def __init__(self) -> None:
        self.rpm = shutil.which("rpm")
        self.pkaction = shutil.which("pkaction")
        self.fstab = readable("/etc/fstab")
        self.at_allow = readable("/etc/at.allow")
        self.at_deny = readable("/etc/at.deny")
        self.cron_allow = readable("/etc/cron.allow")
        self.cron_deny = readable("/etc/cron.deny")
        self.qemu_bridge = readable("/etc/qemu/bridge.conf")
        self.gshadow = readable("/etc/gshadow")
        self.sudoers = readable("/etc/sudoers")
        self.polkit_local = dir_writable_by_agent("/etc/polkit-1/rules.d")
        self.polkit_local["listable_by_agent"] = os.access(
            "/etc/polkit-1/rules.d", os.R_OK | os.X_OK
        )
        self.polkit_default = readable("/usr/share/polkit-1/rules.d/50-default.rules")
        self.dbus_services = dir_writable_by_agent("/usr/share/dbus-1/system-services")
        self.dbus_conf = dir_writable_by_agent("/etc/dbus-1/system.d")
        self.groups = sorted(os.getgroups())
        self._pkactions: dict[str, dict] = {}

    def pkaction_for(self, action_id: str) -> dict:
        if action_id not in self._pkactions:
            if not self.pkaction:
                self._pkactions[action_id] = {"available": False}
            else:
                probe = run([self.pkaction, "--action-id", action_id, "--verbose"])
                implicit = {}
                for line in probe.get("stdout", "").splitlines():
                    if "implicit" in line and ":" in line:
                        key, _, value = line.partition(":")
                        implicit[key.strip()] = value.strip()
                probe["implicit"] = implicit
                probe["available"] = True
                self._pkactions[action_id] = probe
        return self._pkactions[action_id]

    def fstab_user_mounts(self, fstype_hint: str) -> list[str]:
        """fstab lines granting an unprivileged user the right to mount.

        This is the discriminator for the setuid mount helpers: without a
        `user`/`users` option there is no entry an unprivileged caller may
        mount, and the helper refuses.
        """
        content = self.fstab.get("content") or ""
        hits = []
        for line in content.splitlines():
            bare = line.strip()
            if not bare or bare.startswith("#"):
                continue
            fields = bare.split()
            if len(fields) < 4:
                continue
            options = fields[3].split(",")
            if "user" in options or "users" in options:
                if fstype_hint in ("", fields[2]):
                    hits.append(bare)
        return hits

    def package_of(self, path: str) -> dict:
        """Owning package plus a file-level integrity check.

        Compares the digest rpm recorded for exactly this file at build time
        against the same digest computed now -- precise, and far cheaper than
        verifying every file of a large package.
        """
        out: dict = {"packaged": False}
        out["binary_hash"] = sha256_file(path)
        if not self.rpm:
            out["rpm_available"] = False
            out["integrity"] = "NOT_PACKAGED"
            return out
        # Query by FILE, not by a reconstructed NVR: an NVR round-trip can
        # resolve to a different installed build and compare the wrong digests.
        # The NVR goes on its own line -- rpm refuses a scalar tag inside an
        # array iterator ("array iterator used with different sized arrays").
        owner = run(
            [
                self.rpm,
                "-qf",
                "--qf",
                "NVR\t%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"
                "[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEMODES:octal}\n]",
                path,
            ]
        )
        if owner.get("rc") != 0:
            out["query"] = owner.get("stdout") or owner.get("stderr")
            out["integrity"] = "NOT_PACKAGED"
            return out
        for line in owner.get("stdout", "").splitlines():
            fields = line.split("\t")
            if len(fields) == 2 and fields[0] == "NVR":
                out["package_owner"] = fields[1].strip()
            elif len(fields) == 3 and fields[0] == path:
                out["packaged"] = True
                out["expected_hash"] = fields[1].strip()
                out["expected_mode"] = fields[2].strip()
        if not out["packaged"]:
            out["integrity"] = "NOT_PACKAGED"
            return out

        expected = out.get("expected_hash") or ""
        algo = DIGEST_ALGOS.get(len(expected))
        out["digest_algorithm"] = algo or f"unrecognised ({len(expected)} chars)"
        measured = hash_file(path, algo) if algo else None
        out["measured_digest"] = measured
        if not expected:
            out["integrity"] = "NO_RECORDED_DIGEST"
        elif measured is None and out["binary_hash"] is None:
            # 4711 / 4750 setuid binaries are execute-only: the agent cannot
            # read the bytes, so it cannot attest to them. Fail closed.
            out["integrity"] = "FILE_UNREADABLE_BY_AGENT"
        elif measured is None:
            out["integrity"] = "NO_RECORDED_DIGEST"
        else:
            out["integrity"] = "MATCH" if measured == expected else "MISMATCH"

        # A digest match attests the *bytes*. The setuid bit is separate state:
        # /opt/1Password/chrome-sandbox matches its package byte-for-byte while
        # the package declares mode 100755 and the disk carries 4755. That
        # privilege was added after packaging and has no vendor provenance.
        expected_mode = out.get("expected_mode") or ""
        if expected_mode.isdigit():
            out["setuid_declared_by_package"] = bool(int(expected_mode, 8) & 0o4000)
            try:
                actual = os.stat(path).st_mode
                out["setuid_on_disk"] = bool(actual & stat.S_ISUID)
                out["mode_matches_package"] = stat.S_IMODE(actual) == int(expected_mode, 8) & 0o7777
            except OSError as exc:
                out["stat_error"] = str(exc)
        return out

    def capabilities(self, path: str) -> str:
        getcap = shutil.which("getcap")
        if not getcap:
            return "getcap unavailable"
        probe = run([getcap, path])
        return probe.get("stdout") or "none"


def file_facts(path: str) -> dict:
    out: dict = {"path": path, "exists": os.path.exists(path)}
    if not out["exists"]:
        return out
    try:
        st = os.stat(path)
    except OSError as exc:
        out["stat_error"] = str(exc)
        return out
    out["mode"] = oct(stat.S_IMODE(st.st_mode))
    out["owner_uid"] = st.st_uid
    out["owner_gid"] = st.st_gid
    out["setuid"] = bool(st.st_mode & stat.S_ISUID)
    out["setgid"] = bool(st.st_mode & stat.S_ISGID)
    out["writable_by_agent"] = os.access(path, os.W_OK)
    return out


# --------------------------------------------------------------------------
# Setuid rules. Each returns (classification, privilege_effect, discriminator,
# evidence, operator_action).
# --------------------------------------------------------------------------


def _packaged_bound(pkg: dict, effect: str, bound: str) -> tuple:
    """A bounded helper is bounded only if it is the binary the vendor shipped.

    An unpackaged or modified setuid-root binary has no provenance, so the
    design argument that bounds it does not apply to the bytes on disk.
    """
    provenance = {
        "packaged": pkg.get("packaged"),
        "package_owner": pkg.get("package_owner"),
        "integrity": pkg.get("integrity"),
        "digest_algorithm": pkg.get("digest_algorithm"),
        "setuid_declared_by_package": pkg.get("setuid_declared_by_package"),
        "setuid_on_disk": pkg.get("setuid_on_disk"),
        "mode_matches_package": pkg.get("mode_matches_package"),
    }
    if not (pkg.get("packaged") and pkg.get("integrity") == "MATCH"):
        return (
            OPERATOR,
            effect,
            "no verified provenance for these bytes "
            f"(integrity={pkg.get('integrity')}), so the design bound cannot be "
            "attributed to the binary actually on disk",
            {"bound_if_provenance_held": bound, "provenance": provenance},
            "operator establishes provenance for this binary (vendor manifest, "
            "checksum, or a package whose digest the agent can read) or removes "
            "the setuid bit",
        )
    if pkg.get("setuid_on_disk") and pkg.get("setuid_declared_by_package") is False:
        # The bytes are the vendor's; the privilege is not.
        return (
            OPERATOR,
            effect,
            "the bytes match the package but the package declares mode "
            f"{pkg.get('expected_mode')} while the disk carries setuid: the "
            "privilege was granted after packaging and no vendor statement "
            "bounds it",
            {"bound_if_provenance_held": bound, "provenance": provenance},
            "operator determines who set the setuid bit and whether the vendor "
            "intends this binary to run as root; if not, `chmod u-s` it",
        )
    return (
        NON_ROOT_EQUIVALENT,
        effect,
        "owning package identified, the on-disk digest equals the digest rpm "
        "recorded for this file at build time, and the setuid bit is the one "
        "the package declares",
        {"bound": bound, "provenance": provenance},
        None,
    )


def rule_chrome_sandbox(path: str, facts: Facts, pkg: dict) -> tuple:
    return _packaged_bound(
        pkg,
        "creates a user/PID namespace for a browser renderer and execs only the "
        "target passed by its own zygote; it does not take a caller-chosen "
        "command",
        "bounded by the SUID sandbox protocol: the helper refuses to run unless "
        "invoked as the sandbox host of its own process tree",
    )


def rule_arbitrary_root_exec(path: str, facts: Facts, pkg: dict) -> tuple:
    return (
        OPERATOR,
        "arbitrary command execution as uid 0, gated on an authentication factor",
        "the gate is the authorisation policy, which is unreadable by the "
        "agent (/etc/sudoers is 0440 root, /etc/polkit-1/rules.d is 0700 root)",
        {
            "sudoers_readable": facts.sudoers.get("readable_by_agent"),
            "polkit_local_listable": facts.polkit_local.get("listable_by_agent"),
            "package": pkg.get("package_owner"),
        },
        "operator runs `sudo -l -U martin`, reads /etc/sudoers, "
        "/etc/sudoers.d/* and /etc/polkit-1/rules.d/*, and removes any entry "
        "granting this identity a root command",
    )


def rule_self_scoped_credential(path: str, facts: Facts, pkg: dict) -> tuple:
    return _packaged_bound(
        pkg,
        "edits the invoking user's own account record after PAM "
        "authentication; it takes no caller-chosen command and writes no "
        "caller-chosen path",
        "bounded to the caller's own row in /etc/passwd, /etc/shadow or the "
        "PAM timestamp; it cannot grant a group or a uid the caller lacks",
    )


def rule_gpasswd(path: str, facts: Facts, pkg: dict) -> tuple:
    return (
        OPERATOR,
        "administers group membership; root-equivalent exactly when the agent "
        "administers a privileged group, because adding itself to `docker` or "
        "`wheel` re-opens a closed path",
        "the administrator list lives in /etc/gshadow, which is 0000 root and "
        "unreadable by the agent",
        {
            "gshadow_readable": facts.gshadow.get("readable_by_agent"),
            "gshadow_mode": facts.gshadow.get("mode"),
        },
        "operator reads /etc/gshadow and confirms this identity administers no "
        "group (an empty admin field on every privileged group)",
    )


def rule_job_scheduler(path: str, facts: Facts, pkg: dict) -> tuple:
    allow = facts.at_allow if "at" in os.path.basename(path) else facts.cron_allow
    deny = facts.at_deny if "at" in os.path.basename(path) else facts.cron_deny
    classification, effect, disc, bound, action = _packaged_bound(
        pkg,
        "writes into the job spool directory as root, then the daemon runs the "
        "job as the *submitting* user",
        "bounded: a submitted job executes under the caller's own uid, so it "
        "confers no authority the caller does not already hold",
    )
    return (
        classification,
        effect,
        disc,
        {
            "bound": bound,
            "allow_file": {
                "path": allow["path"],
                "exists": allow.get("exists"),
            },
            "deny_file": {
                "path": deny["path"],
                "exists": deny.get("exists"),
                "content": (deny.get("content") or "").strip(),
            },
            "note": "the allow/deny files decide *who may submit*, not *as whom "
            "the job runs*; they are recorded because they bound the blast "
            "radius, not because they change the classification",
        },
        action,
    )


def rule_mount_helper(path: str, facts: Facts, pkg: dict) -> tuple:
    hint = "nfs" if "nfs" in os.path.basename(path) else ""
    hits = facts.fstab_user_mounts(hint)
    if hits:
        return (
            OPERATOR,
            "mounts a filesystem as root",
            "fstab grants an unprivileged user the right to mount an entry, so "
            "the mount source and options are partly caller-influenced",
            {"fstab_user_entries": hits},
            "operator reviews these fstab entries; a user-mountable entry "
            "without nosuid/nodev is root-equivalent",
        )
    if not facts.fstab.get("readable_by_agent"):
        return (
            OPERATOR,
            "mounts a filesystem as root",
            "/etc/fstab could not be read, so the absence of user-mountable entries is unproven",
            {"fstab": facts.fstab},
            "operator reads /etc/fstab and confirms no `user`/`users` entry",
        )
    classification, effect, disc, bound, action = _packaged_bound(
        pkg,
        "mounts a filesystem as root",
        "bounded: with no `user`/`users` entry in fstab the helper refuses an "
        "unprivileged caller, and it accepts no caller-chosen mount source",
    )
    return (
        classification,
        effect,
        f"{disc}; and /etc/fstab contains no `user`/`users` entry ({len(hits)} matches)",
        {"bound": bound, "fstab_user_entries": hits},
        action,
    )


def rule_qemu_bridge_helper(path: str, facts: Facts, pkg: dict) -> tuple:
    content = (facts.qemu_bridge.get("content") or "").strip()
    allows = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not facts.qemu_bridge.get("exists"):
        return (
            NON_ROOT_EQUIVALENT,
            "attaches a tap device to a bridge as root",
            "/etc/qemu/bridge.conf does not exist, and the helper denies every "
            "bridge when it has no allow list",
            {"bridge_conf": facts.qemu_bridge},
            None,
        )
    if any(entry.split()[-1] == "all" for entry in allows if entry.split()):
        return (
            ROOT_EQUIVALENT,
            "attaches a tap device to any bridge as root",
            "/etc/qemu/bridge.conf allows `all`, so the caller chooses the "
            "bridge and can bridge onto arbitrary host networks",
            {"allow_entries": allows},
            "operator restricts /etc/qemu/bridge.conf to named bridges",
        )
    classification, effect, disc, bound, action = _packaged_bound(
        pkg,
        "attaches a tap device to a bridge as root",
        f"bounded by the allow list in /etc/qemu/bridge.conf: {allows}",
    )
    return (
        classification,
        effect,
        f"{disc}; and the readable allow list names specific bridges",
        {"bound": bound, "allow_entries": allows},
        action,
    )


def rule_dbus_launch_helper(path: str, facts: Facts, pkg: dict) -> tuple:
    writable = bool(facts.dbus_services.get("writable_by_agent")) or bool(
        facts.dbus_conf.get("writable_by_agent")
    )
    if writable:
        return (
            ROOT_EQUIVALENT,
            "launches a system service as the user named in its .service file",
            "a D-Bus system-service directory is agent-writable, so the agent "
            "chooses the binary and the uid it runs as",
            {"services": facts.dbus_services, "conf": facts.dbus_conf},
            "operator removes agent write access to the D-Bus system service directories",
        )
    classification, effect, disc, bound, action = _packaged_bound(
        pkg,
        "launches a system service as the user named in its .service file",
        "bounded: the service files it may launch live in root-owned "
        "directories the agent cannot write, so it takes no caller-chosen "
        "binary",
    )
    return (
        classification,
        effect,
        f"{disc}; and neither D-Bus system-service directory is agent-writable",
        {
            "bound": bound,
            "services": facts.dbus_services,
            "conf": facts.dbus_conf,
        },
        action,
    )


def rule_polkit_agent_helper(path: str, facts: Facts, pkg: dict) -> tuple:
    return _packaged_bound(
        pkg,
        "authenticates the caller to polkitd over a private channel; it execs "
        "nothing and writes no caller-chosen path",
        "bounded: it is the credential-checking half of the polkit "
        "conversation. It cannot grant an action -- polkitd does that, and "
        "polkitd's decision is the separately-classified pkexec path",
    )


def rule_readonly_reporter(path: str, facts: Facts, pkg: dict) -> tuple:
    return _packaged_bound(
        pkg,
        "reports system and process statistics to a desktop client",
        "bounded: it discloses information and performs no write, no exec and "
        "no credential change. Information disclosure is not uid-0 authority "
        "under the classification criteria",
    )


#: basename -> rule. Anything absent from this table falls to
#: REQUIRES_OPERATOR_EVIDENCE, so a newly-added setuid binary degrades the
#: verdict rather than being silently tolerated.
SETUID_RULES = {
    "chrome-sandbox": rule_chrome_sandbox,
    "su": rule_arbitrary_root_exec,
    "sudo": rule_arbitrary_root_exec,
    "pkexec": rule_arbitrary_root_exec,
    "userhelper": rule_arbitrary_root_exec,
    "passwd": rule_self_scoped_credential,
    "chage": rule_self_scoped_credential,
    "chfn": rule_self_scoped_credential,
    "chsh": rule_self_scoped_credential,
    "newgrp": rule_self_scoped_credential,
    "unix_chkpwd": rule_self_scoped_credential,
    "gpasswd": rule_gpasswd,
    "at": rule_job_scheduler,
    "crontab": rule_job_scheduler,
    "mount.nfs": rule_mount_helper,
    "fusermount-glusterfs": rule_mount_helper,
    "qemu-bridge-helper": rule_qemu_bridge_helper,
    "dbus-daemon-launch-helper": rule_dbus_launch_helper,
    "polkit-agent-helper-1": rule_polkit_agent_helper,
    "libgtop_server2": rule_readonly_reporter,
}


def resolve_setuid(path_id: str, facts: Facts) -> dict:
    binary = path_id.split(":", 1)[1]
    disk = file_facts(binary)
    if not disk["exists"]:
        return {
            "classification": NOT_PRESENT,
            "privilege_effect": "none: the binary is gone",
            "discriminator": "os.path.exists() is False for this path",
            "evidence": disk,
        }
    pkg = facts.package_of(binary)
    caps = facts.capabilities(binary)
    rule = SETUID_RULES.get(os.path.basename(binary))
    if rule is None:
        classification = OPERATOR
        effect = "setuid-root binary with no measured bound"
        disc = (
            "no discriminator is defined for this binary, and an unclassified "
            "setuid-root binary is treated as unresolved, never as safe"
        )
        evidence: object = {"basename": os.path.basename(binary)}
        action = (
            "operator determines whether caller-controlled input can reach a "
            "privileged effect (arbitrary exec, arbitrary write, namespace or "
            "device manipulation, credential change); if not needed, remove "
            "the setuid bit"
        )
    else:
        classification, effect, disc, evidence, action = rule(binary, facts, pkg)
    entry = {
        "classification": classification,
        "privilege_effect": effect,
        "discriminator": disc,
        "evidence": {
            "file": disk,
            "capabilities": caps,
            "package_owner": pkg.get("package_owner"),
            "binary_hash": pkg.get("binary_hash") or sha256_file(binary),
            "expected_hash": pkg.get("expected_hash"),
            "integrity": pkg.get("integrity"),
            "rule": evidence,
        },
    }
    if action:
        entry["operator_action"] = action
    return entry


# --------------------------------------------------------------------------
# Non-setuid surfaces.
# --------------------------------------------------------------------------


def resolve_polkit_action(facts: Facts, action_id: str, effect: str, action: str) -> dict:
    probe = facts.pkaction_for(action_id)
    admin = facts.polkit_default.get("content") or ""
    admin_groups = [
        token.split(":", 1)[1].strip('"]) ')
        for token in admin.split()
        if token.startswith('"unix-group:') or token.startswith("unix-group:")
    ]
    agent_group_names = []
    for gid in facts.groups:
        try:
            import grp

            agent_group_names.append(grp.getgrgid(gid).gr_name)
        except (KeyError, OSError):
            agent_group_names.append(str(gid))
    overlap = sorted(set(admin_groups) & set(agent_group_names))
    return {
        "classification": OPERATOR,
        "privilege_effect": effect,
        "discriminator": (
            "the readable half of the policy is measured below; the deciding "
            "half, /etc/polkit-1/rules.d, is 0700 root and can return "
            "polkit.Result.YES (no password) for this action"
        ),
        "evidence": {
            "action_id": action_id,
            "implicit": probe.get("implicit"),
            "admin_identities_from_50_default": admin_groups,
            "agent_groups": agent_group_names,
            "agent_is_admin_identity": bool(overlap),
            "overlap": overlap,
            "polkit_local_rules_listable_by_agent": facts.polkit_local.get("listable_by_agent"),
        },
        "operator_action": action,
    }


def resolve_non_setuid(path_id: str, before: dict, facts: Facts) -> dict | None:
    if path_id == "groups:membership_wheel":
        entry = resolve_polkit_action(
            facts,
            "org.freedesktop.policykit.exec",
            "membership of the polkit administrator group and, on RPM-family "
            "hosts, the conventional sudoers group: it is the identity that "
            "authenticates privileged actions, not a mechanism of its own",
            "operator removes this identity from `wheel` (`gpasswd -d martin "
            "wheel`) after confirming no other admin identity depends on it",
        )
        entry["privilege_effect"] = entry["privilege_effect"]
        entry["evidence"]["group_roster"] = before.get("evidence", {}).get(
            "roster_members"
        ) or before.get("evidence", {}).get("roster")
        return entry
    if path_id == "sudo:sudo":
        probe = (before.get("evidence", {}) or {}).get("probe", {})
        stderr = (probe.get("stderr") or "").lower()
        entry_exists = "password is required" in stderr
        return {
            "classification": OPERATOR,
            "privilege_effect": "arbitrary command execution as uid 0 if the policy grants it",
            "discriminator": (
                "`sudo -n -l` distinguishes *no entry* ('not allowed to run "
                "sudo') from *an entry behind a password* ('a password is "
                "required'). It cannot reveal which commands the entry grants, "
                "and /etc/sudoers is 0440 root"
            ),
            "evidence": {
                "probe": probe,
                "sudoers_entry_exists_for_agent": entry_exists,
                "sudoers_readable_by_agent": facts.sudoers.get("readable_by_agent"),
                "sudoers_mode": facts.sudoers.get("mode"),
                "interpretation": "an entry exists; its command set is "
                "unmeasured. `ALL=(ALL) ALL` would be root-equivalent"
                if entry_exists
                else "no entry was demonstrated",
            },
            "operator_action": "operator runs `sudo -l -U martin` and reads "
            "/etc/sudoers plus /etc/sudoers.d/*; any root-capable entry for "
            "this identity must be removed",
        }
    if path_id == "polkit:pkexec":
        return resolve_polkit_action(
            facts,
            "org.freedesktop.policykit.exec",
            "runs an arbitrary program as another user, including root",
            "operator reads /etc/polkit-1/rules.d/* for a rule returning YES on "
            "this action, and removes this identity from the admin group",
        )
    if path_id == "polkit:dbus_system_bus":
        return resolve_polkit_action(
            facts,
            "org.freedesktop.systemd1.manage-units",
            "the system bus carries privileged RPCs (StartTransientUnit among "
            "them); reachability is by design and authority is decided per RPC "
            "by polkit",
            "operator enumerates the local polkit rules and confirms no rule "
            "grants this identity a privileged system-bus action without "
            "authentication",
        )
    if path_id == "systemd:systemd_run":
        return resolve_polkit_action(
            facts,
            "org.freedesktop.systemd1.manage-units",
            "starts a transient unit under the system manager, which runs as root by default",
            "operator confirms no polkit rule grants this identity "
            "org.freedesktop.systemd1.manage-units without authentication",
        )
    if path_id in (
        "container_runtimes:libvirt_socket",
        "container_runtimes:libvirt_ro_socket",
    ):
        entry = resolve_polkit_action(
            facts,
            "org.libvirt.unix.manage",
            "an authorised libvirt session can attach host block devices to a "
            "guest, which is root-equivalent; the socket is world-connectable "
            "by design and decides nothing",
            "operator reads /etc/libvirt/libvirtd.conf (auth_unix_rw, "
            "unix_sock_group) and confirms this identity is in no group the "
            "libvirt polkit rules grant",
        )
        libvirt_rules = readable("/usr/share/polkit-1/rules.d/50-libvirt.rules")
        entry["evidence"]["libvirt_rules"] = {
            "path": libvirt_rules["path"],
            "readable_by_agent": libvirt_rules.get("readable_by_agent"),
            "content": libvirt_rules.get("content"),
        }
        entry["evidence"]["libvirtd_conf"] = readable("/etc/libvirt/libvirtd.conf")
        entry["evidence"]["socket_from_before"] = before.get("evidence", {}).get("socket")
        return entry
    return None


#: Linux capability numbers, for intersecting a file's inheritable-only set
#: with the agent's own CapInh. Bit 35 is cap_wake_alarm -- worth stating,
#: because this host's CapInh is 0x800000000 and reading that as cap_bpf (an
#: easy off-by-a-few) would have changed a classification.
CAP_BITS = {
    "cap_chown": 0,
    "cap_dac_override": 1,
    "cap_dac_read_search": 2,
    "cap_fowner": 3,
    "cap_fsetid": 4,
    "cap_kill": 5,
    "cap_setgid": 6,
    "cap_setuid": 7,
    "cap_setpcap": 8,
    "cap_linux_immutable": 9,
    "cap_net_bind_service": 10,
    "cap_net_broadcast": 11,
    "cap_net_admin": 12,
    "cap_net_raw": 13,
    "cap_ipc_lock": 14,
    "cap_ipc_owner": 15,
    "cap_sys_module": 16,
    "cap_sys_rawio": 17,
    "cap_sys_chroot": 18,
    "cap_sys_ptrace": 19,
    "cap_sys_pacct": 20,
    "cap_sys_admin": 21,
    "cap_sys_boot": 22,
    "cap_sys_nice": 23,
    "cap_sys_resource": 24,
    "cap_sys_time": 25,
    "cap_sys_tty_config": 26,
    "cap_mknod": 27,
    "cap_lease": 28,
    "cap_audit_write": 29,
    "cap_audit_control": 30,
    "cap_setfcap": 31,
    "cap_mac_override": 32,
    "cap_mac_admin": 33,
    "cap_syslog": 34,
    "cap_wake_alarm": 35,
    "cap_block_suspend": 36,
    "cap_audit_read": 37,
    "cap_perfmon": 38,
    "cap_bpf": 39,
    "cap_checkpoint_restore": 40,
}


def resolve_filecaps(path_id: str, before: dict, facts: Facts) -> dict:
    """File capabilities: authority with no setuid bit for the setuid sweep to find.

    Three discriminators, in order of decisiveness, all measured:

      1. can the agent execute the file at all? DAC decides this, and a file it
         cannot exec grants it nothing regardless of the capabilities on it;
      2. are the capabilities inheritable-only? Then the file grants only what
         the caller already holds -- intersect with the agent's CapInh;
      3. otherwise the capability is in the permitted set and takes effect on
         exec, so the bound has to come from the program's own logic, which is
         not readable from here.
    """
    binary = path_id.split(":", 1)[1]
    disk = file_facts(binary)
    if not disk["exists"]:
        return {
            "classification": NOT_PRESENT,
            "privilege_effect": "none: the file is gone",
            "discriminator": "os.path.exists() is False",
            "evidence": disk,
        }

    evidence = (before or {}).get("evidence", {})
    parsed = evidence.get("capabilities", {})
    caps = parsed.get("capabilities", [])
    pkg = facts.package_of(binary)
    executable = os.access(binary, os.X_OK)
    base = {
        "file": disk,
        "capabilities": parsed,
        "executable_by_agent": executable,
        "package_owner": pkg.get("package_owner"),
        "binary_hash": pkg.get("binary_hash"),
        "integrity": pkg.get("integrity"),
    }

    if not executable:
        return {
            "classification": NON_ROOT_EQUIVALENT,
            "privilege_effect": f"would confer {caps} on exec",
            "discriminator": (
                f"the agent cannot execute this file: mode {disk.get('mode')}, "
                f"owner {disk.get('owner_uid')}:{disk.get('owner_gid')}, and "
                f"os.access(X_OK) is False for credential {sorted(os.getgroups())}. "
                "A capability on a file the caller may not exec is not a path "
                "for that caller"
            ),
            "evidence": base,
        }

    if parsed.get("inheritable_only"):
        inh_hex = evidence.get("agent_cap_inheritable") or "0"
        try:
            inh_mask = int(inh_hex, 16)
        except ValueError:
            inh_mask = None
        if inh_mask is None:
            activatable = None
        else:
            activatable = sorted(
                cap for cap in caps if cap in CAP_BITS and inh_mask & (1 << CAP_BITS[cap])
            )
        base["agent_cap_inheritable"] = inh_hex
        base["capabilities_the_agent_could_activate"] = activatable
        if activatable == []:
            return {
                "classification": NON_ROOT_EQUIVALENT,
                "privilege_effect": f"would confer {caps} to a caller that already holds them",
                "discriminator": (
                    f"the capabilities are inheritable-only (flags "
                    f"'{parsed.get('flags')}', no 'p'), so exec grants only "
                    f"what the caller's own inheritable set contains. The "
                    f"agent's CapInh is {inh_hex}, whose intersection with "
                    f"{caps} is empty -- computed bit by bit, not assumed"
                ),
                "evidence": base,
            }
        return {
            "classification": OPERATOR,
            "privilege_effect": f"confers {activatable} on exec",
            "discriminator": "inheritable-only, but the agent's inheritable "
            f"set intersects the file's capabilities: {activatable}",
            "evidence": base,
            "operator_action": "operator removes the capability, or confirms "
            "the agent's inheritable set cannot contain it at runtime",
        }

    escalating = sorted(
        cap
        for cap in caps
        if cap
        not in (
            "cap_net_raw",
            "cap_net_bind_service",
            "cap_net_admin",
            "cap_sys_nice",
            "cap_ipc_lock",
            "cap_wake_alarm",
        )
    )
    if not escalating:
        return {
            "classification": NON_ROOT_EQUIVALENT,
            "privilege_effect": f"confers {caps} on exec",
            "discriminator": "every capability is bounded to networking or "
            "scheduling; none confers authority over another principal's "
            "files, processes or credentials",
            "evidence": base,
        }
    return {
        "classification": OPERATOR,
        "privilege_effect": f"confers {escalating} on exec, in the permitted set",
        "discriminator": (
            "the agent can execute this file and the capabilities take effect "
            "on exec, so the only remaining bound is the program's own logic, "
            "which is not measurable read-only"
        ),
        "evidence": base,
        "operator_action": "operator determines whether caller-controlled "
        "input reaches the privileged effect, or removes the file capability "
        f"(`setcap -r {binary}`)",
    }


def carrier_analysis(path_id: str, registry: dict | None, attacks: dict | None) -> dict:
    """The carrier and the boundary, for a path classified ROOT_EQUIVALENT.

    Answers three questions with measurements rather than convention: what the
    carrier is, which kernel-enforced boundary it crosses, and what was
    observed on the other side. The middle answer is the interesting one and it
    is *not* "a boundary was bypassed".
    """
    mech = ((registry or {}).get("mechanisms") or {}).get("docker_rootful", {})
    route = (registry or {}).get("docker_access_route", {})
    probe = (
        ((attacks or {}).get("attacks") or {})
        .get("container_roots", {})
        .get("H_rootful_container_root", {})
    )
    socket = file_facts("/var/run/docker.sock")
    credential = sorted(os.getgroups())
    socket_gid = socket.get("owner_gid")

    common = {
        "kernel_enforced_boundary_crossed": "NONE",
        "boundary_explanation": (
            "No kernel boundary is defeated. The kernel's DAC check on "
            f"connect(2) to a mode-{socket.get('mode')} socket owned by "
            f"uid {socket.get('owner_uid')} gid {socket_gid} *passes*, because "
            f"gid {socket_gid} is in the agent's credential {credential}. "
            "Authority is granted at the socket and then exercised by a "
            "daemon already running as uid 0 -- so there is no exploit to "
            "detect, no boundary to harden, and nothing for a sandbox, "
            "capability drop or seccomp filter to stop. That is precisely why "
            "it is root-equivalent: the only remedy is to stop granting it."
        ),
        "classification": ROOT_EQUIVALENT,
        "classification_basis": (
            "measurement, not convention: a container started through this "
            "socket wrote to the host filesystem and the resulting file was "
            f"owned by uid {mech.get('evidence', {}).get('host_file_uid_after')}, "
            "which the agent cannot produce by any other measured route"
        ),
        "measured_evidence": {
            "socket": socket,
            "agent_credential_gids": credential,
            "socket_group_in_credential": socket_gid in credential,
            "rootless_daemon": mech.get("evidence", {}).get("rootless_daemon"),
            "container_uid_map": mech.get("evidence", {}).get("container_uid_map"),
            "host_file_uid_after_write": mech.get("evidence", {}).get("host_file_uid_after"),
            "attack_H_verdict": probe.get("verdict"),
            "attack_H_changed_canonical": probe.get("changed_canonical"),
            "targets_reached": mech.get("targets"),
            "selinux_note": mech.get("note"),
        },
        "evidence_provenance": (
            "ROOT_EQUIVALENCE_REGISTRY.json and attack_results.json, both "
            "produced by the sanctioned V3 attack suite. No new escalation was "
            "attempted by this pass."
        ),
    }

    if path_id == "groups:membership_docker":
        return dict(
            common,
            carrier="supplementary group membership: gid "
            f"{socket_gid} (docker) present in the process credential",
            mechanism_detail=(
                "The credential is the carrier. `getgroups(2)` returns "
                f"{credential}; group `docker` is gid {socket_gid}. Membership "
                "is what makes the DAC check on the socket succeed, so this "
                "path and the socket path are one mechanism observed at two "
                "layers -- both are listed because removing either one alone "
                "does not necessarily remove the other (an ACL entry can "
                "replace the group)."
            ),
            removal=route.get("minimal_removal"),
            routes_measured=route.get("routes"),
        )
    return dict(
        common,
        carrier=f"AF_UNIX stream socket {socket.get('path')} "
        f"(mode {socket.get('mode')}, {socket.get('owner_uid')}:{socket_gid}) "
        "speaking the Docker Engine API",
        mechanism_detail=(
            "connect(2) succeeds under DAC, then `POST /containers/create` "
            "with a host bind mount and `--security-opt label=disable`, then "
            "`POST /containers/{id}/start`. The container's first process runs "
            "with the host's real uid 0 (`container_uid_map` = "
            f"{mech.get('evidence', {}).get('container_uid_map')}), so writes "
            "through the bind mount land on the host as root."
        ),
        acl_measured=route.get("acl"),
        removal=route.get("minimal_removal"),
    )


def build() -> dict:
    context = privilege_context.capture()
    with open(BEFORE, "rb") as handle:
        raw = handle.read()
    before = json.loads(raw.decode("utf-8"))

    result: dict = {
        "measurement_context": context,
        "admissible": context["host_representative"],
        "read_only": True,
        "mutations_performed": [],
        "source_inventory": {
            "path": os.path.basename(BEFORE),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "counts": before.get("counts"),
        },
        "classification_rule": {
            ROOT_EQUIVALENT: "measured to confer uid-0-equivalent authority",
            NON_ROOT_EQUIVALENT: "measured bounded, with the bound named and "
            "the provenance of the bytes verified",
            NOT_PRESENT: "the mechanism does not exist on this host",
            OPERATOR: "the deciding fact is unreadable by the agent; the exact "
            "command that answers it is recorded. BLOCKING, never a pass",
        },
        "blocking_classifications": list(BLOCKING),
    }

    if not context["host_representative"]:
        result["paths"] = {}
        result["counts"] = {}
        result["refusal"] = (
            "this process is not measuring the host agent identity, so any "
            "inventory it produced would describe the sandbox. Disqualifiers: "
            + "; ".join(context["disqualifiers"])
        )
        return result

    facts = Facts()
    paths: dict[str, dict] = {}
    # Read-only inputs for the root-path carrier analysis. Both were produced
    # by the sanctioned attack suite; this pass attempts no escalation of its
    # own and merely reads what that suite already measured.
    registry_json = load_json(os.path.join(HERE, "ROOT_EQUIVALENCE_REGISTRY.json"))
    attacks_json = load_json(os.path.join(HERE, "attack_results.json"))

    for path_id, entry in sorted(before["paths"].items()):
        prior = entry.get("classification")
        if prior in (ROOT_EQUIVALENT, NON_ROOT_EQUIVALENT):
            resolved = {
                "classification": prior,
                "privilege_effect": entry.get("why", ""),
                "discriminator": "carried forward from the source inventory, "
                "which measured it in a host-representative context",
                "evidence": entry.get("evidence", {}),
            }
        elif path_id.startswith("setuid:"):
            resolved = resolve_setuid(path_id, facts)
        elif path_id.startswith("filecaps:"):
            resolved = resolve_filecaps(path_id, entry, facts)
        else:
            resolved = resolve_non_setuid(path_id, entry, facts) or {
                "classification": OPERATOR,
                "privilege_effect": entry.get("why", ""),
                "discriminator": "no discriminator is defined for this surface",
                "evidence": entry.get("evidence", {}),
                "operator_action": entry.get("resolved_by"),
            }
        resolved["surface"] = path_id.split(":", 1)[0]
        resolved["prior_classification"] = prior
        resolved["blocking"] = resolved["classification"] in BLOCKING
        if resolved["classification"] == ROOT_EQUIVALENT:
            resolved["carrier_analysis"] = carrier_analysis(path_id, registry_json, attacks_json)
        paths[path_id] = resolved

    buckets: dict[str, list[str]] = {name: [] for name in TERMINAL}
    buckets[UNKNOWN] = []
    for path_id, entry in paths.items():
        buckets.setdefault(entry["classification"], []).append(path_id)

    result["paths"] = paths
    result["root_equivalent_paths"] = sorted(buckets[ROOT_EQUIVALENT])
    result["non_root_equivalent_paths"] = sorted(buckets[NON_ROOT_EQUIVALENT])
    result["not_present_paths"] = sorted(buckets[NOT_PRESENT])
    result["requires_operator_evidence_paths"] = sorted(buckets[OPERATOR])
    result["unknown_privilege_paths"] = sorted(buckets[UNKNOWN])
    result["blocking_paths"] = sorted(p for p, e in paths.items() if e["blocking"])
    result["counts"] = {
        "total": len(paths),
        "root_equivalent": len(buckets[ROOT_EQUIVALENT]),
        "non_root_equivalent": len(buckets[NON_ROOT_EQUIVALENT]),
        "not_present": len(buckets[NOT_PRESENT]),
        "requires_operator_evidence": len(buckets[OPERATOR]),
        "unknown": len(buckets[UNKNOWN]),
        "blocking": len(result["blocking_paths"]),
    }
    return result


def main() -> int:
    result = build()
    print(json.dumps(result.get("counts", {}), indent=1, sort_keys=True))
    print(f"admissible: {result['admissible']}")
    if not result["admissible"]:
        # Do NOT write. The refusal payload would replace a host-measured
        # inventory with `paths: {}`, destroying evidence that can only be
        # recovered by an unsandboxed re-run. Failing closed must not also
        # fail destructively.
        print(result["refusal"])
        if os.path.exists(AFTER):
            print(f"left intact: {os.path.basename(AFTER)}")
        return 2
    with open(AFTER, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1, sort_keys=True)
    print(f"root_equivalent:  {result['root_equivalent_paths']}")
    print(f"operator_evidence: {len(result['requires_operator_evidence_paths'])}")
    for path_id in result["requires_operator_evidence_paths"]:
        print(f"  - {path_id}")
    print(f"unknown remaining: {result['unknown_privilege_paths']}")
    return 0 if not result["blocking_paths"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
