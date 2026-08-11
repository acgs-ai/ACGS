#!/usr/bin/env python3
"""Deterministic evidence checklist for every REQUIRES_OPERATOR_EVIDENCE path.

Input:  PRIVILEGE_TOPOLOGY_FINAL.json
Output: OPERATOR_EVIDENCE_CHECKLIST.json

Each item separates three things that are routinely conflated:

  readable_evidence      what the agent already measured, with the values
  privileged_only        the artifact that decides it, and who can obtain it
  policy_inference       what the readable half *suggests* -- explicitly marked
                         as inference, never promoted to a measurement

and states a `decision_rule`: the answer that makes the path ROOT_EQUIVALENT
and the answer that makes it NON_ROOT_EQUIVALENT. An operator who runs the
listed command gets a classification, not an opinion.

If `privileged_only` is non-empty the path stays blocking. That is the intended
outcome, not a failure: proof that cannot be obtained without privileged access
is proof this pass may not manufacture.

Read-only. Reads one JSON file and writes one.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FINAL = os.path.join(HERE, "PRIVILEGE_TOPOLOGY_FINAL.json")
OUT = os.path.join(HERE, "OPERATOR_EVIDENCE_CHECKLIST.json")

SUDO_POLICY = {
    "minimum_artifact": "the sudoers policy that applies to this identity",
    "commands": [
        "sudo -l -U martin",
        "cat /etc/sudoers",
        "cat /etc/sudoers.d/*",
    ],
    "privileged_only": [
        "/etc/sudoers (0440 root:root)",
        "/etc/sudoers.d (0750 root:root -- not listable by the agent)",
    ],
    "policy_inference": (
        "`sudo -n -l` returned 'a password is required' rather than 'not "
        "allowed to run sudo', so an entry matching this identity exists. The "
        "commands it grants are not inferable, and a Fedora default of "
        "`%wheel ALL=(ALL) ALL` would be root-equivalent"
    ),
    "decision_rule": {
        "ROOT_EQUIVALENT": "any entry granting this identity a command as root, "
        "or any NOPASSWD entry, or a command with a documented shell escape",
        "NON_ROOT_EQUIVALENT": "no entry for this identity or any group it "
        "holds, verified with `sudo -l -U martin` run as root",
    },
}

POLKIT_LOCAL = {
    "minimum_artifact": "the local polkit rules that apply to this action",
    "commands": [
        "ls -la /etc/polkit-1/rules.d",
        "cat /etc/polkit-1/rules.d/*.rules",
        "pkcheck --action-id <action> --process $$ ",
    ],
    "privileged_only": ["/etc/polkit-1/rules.d (0750 root:polkitd -- not listable by the agent)"],
    "policy_inference": (
        "the readable half is measured: 50-default.rules sets AdminIdentities "
        "to unix-group:wheel and the agent holds wheel, so admin "
        "authentication is available to this identity. A local rule returning "
        "polkit.Result.YES would remove the password entirely -- that file is "
        "the deciding artifact and it is unreadable"
    ),
    "decision_rule": {
        "ROOT_EQUIVALENT": "a local rule returns YES for this action for a "
        "group the agent holds, or the operator accepts admin authentication "
        "as reachable by the agent runtime",
        "NON_ROOT_EQUIVALENT": "no local rule grants it, and the agent is "
        "removed from every AdminIdentity group",
    },
}

CHECKS: dict[str, dict] = {
    "sudo:sudo": SUDO_POLICY,
    "setuid:/usr/bin/sudo": SUDO_POLICY,
    "groups:membership_wheel": {
        "minimum_artifact": "every policy that names `wheel` as an authority",
        "commands": [
            "sudo -l -U martin",
            "grep -rn wheel /etc/sudoers /etc/sudoers.d /etc/polkit-1/rules.d",
        ],
        "privileged_only": [
            "/etc/sudoers, /etc/sudoers.d",
            "/etc/polkit-1/rules.d",
        ],
        "policy_inference": (
            "wheel is measured to be the polkit AdminIdentity on this host "
            "(50-default.rules, world-readable). Whether it is also a sudoers "
            "authority is the unreadable half"
        ),
        "decision_rule": {
            "ROOT_EQUIVALENT": "wheel grants a root command via sudoers, or "
            "admin authentication is reachable by the agent runtime",
            "NON_ROOT_EQUIVALENT": "the identity is removed from wheel "
            "(`gpasswd -d martin wheel`), which resolves this path by removal "
            "rather than by evidence",
        },
    },
    "polkit:pkexec": POLKIT_LOCAL,
    "setuid:/usr/bin/pkexec": POLKIT_LOCAL,
    "polkit:dbus_system_bus": POLKIT_LOCAL,
    "systemd:systemd_run": POLKIT_LOCAL,
    "setuid:/usr/bin/su": {
        "minimum_artifact": "the PAM stack for `su` and the target account's credential state",
        "commands": [
            "cat /etc/pam.d/su",
            "getent shadow root | cut -d: -f2 | head -c1",
        ],
        "privileged_only": ["/etc/shadow (0000 root:root)"],
        "policy_inference": (
            "su is setuid root and grants arbitrary root execution on "
            "successful authentication; whether this identity can authenticate "
            "as root is not measurable read-only"
        ),
        "decision_rule": {
            "ROOT_EQUIVALENT": "pam_wheel with trust, an empty/known root "
            "password, or any rule letting this identity authenticate as root",
            "NON_ROOT_EQUIVALENT": "root login is locked and no PAM rule "
            "grants this identity a password-free transition",
        },
    },
    "setuid:/usr/bin/userhelper": {
        "minimum_artifact": "the usermode console.apps configuration",
        "commands": ["ls -la /etc/security/console.apps", "cat /etc/pam.d/*"],
        "privileged_only": [],
        "policy_inference": (
            "userhelper runs configured applications with elevated privilege "
            "after PAM authentication; the binary is mode 4711 so the agent "
            "cannot even hash it"
        ),
        "decision_rule": {
            "ROOT_EQUIVALENT": "a console.apps entry runs a root program without authentication",
            "NON_ROOT_EQUIVALENT": "every entry authenticates, and the package digest verifies",
        },
    },
    "setuid:/usr/bin/gpasswd": {
        "minimum_artifact": "the group administrator lists in /etc/gshadow",
        "commands": ["cat /etc/gshadow", "grep -E '^(docker|wheel):' /etc/gshadow"],
        "privileged_only": ["/etc/gshadow (0000 root:root)"],
        "policy_inference": (
            "gpasswd lets a group administrator add members. If this identity "
            "administers `docker` or `wheel` it can restore a removed "
            "root-equivalent path at will, which would make gate 1 reversible "
            "by the agent"
        ),
        "decision_rule": {
            "ROOT_EQUIVALENT": "this identity appears in the administrator "
            "field of any privileged group",
            "NON_ROOT_EQUIVALENT": "the administrator field of every "
            "privileged group is empty or names other principals",
        },
    },
}

UNREADABLE_BINARY = {
    "minimum_artifact": "provenance for bytes the agent cannot read",
    "commands": [
        "rpm -Vf <path>",
        "sha256sum <path>   # as root; the binary is execute-only",
    ],
    "privileged_only": ["the binary's own bytes (mode 4711 / 4750)"],
    "policy_inference": (
        "the owning package is known and records a digest, but the agent "
        "cannot read the file to compare against it, so the design argument "
        "that would bound this helper cannot be attached to the bytes on disk"
    ),
    "decision_rule": {
        "ROOT_EQUIVALENT": "the digest differs from the package's, or the file is unpackaged",
        "NON_ROOT_EQUIVALENT": "`rpm -Vf` reports no digest or mode deviation for this path",
    },
}

UNCLASSIFIED_SETUID = {
    "minimum_artifact": "a statement of what caller-controlled input reaches the privileged effect",
    "commands": [
        "rpm -qf <path> && rpm -Vf <path>",
        "getcap <path>",
        "strings -a <path> | grep -iE 'exec|system|/bin/sh'",
    ],
    "privileged_only": [],
    "policy_inference": (
        "no discriminator is defined for this binary, so it is unresolved by "
        "construction rather than by any finding against it"
    ),
    "decision_rule": {
        "ROOT_EQUIVALENT": "caller input reaches arbitrary exec, arbitrary "
        "write, namespace escape, device/mount manipulation or credential "
        "change",
        "NON_ROOT_EQUIVALENT": "the effect is bounded and the bound is named; "
        "otherwise remove the setuid bit (`chmod u-s`) and re-run the "
        "inventory, which reclassifies it without needing the analysis",
    },
}

LIBVIRT = {
    "minimum_artifact": "the libvirt socket authentication mode",
    "commands": [
        "grep -E '^(auth_unix_rw|unix_sock_group|unix_sock_rw_perms)' "
        "/etc/libvirt/libvirtd.conf /etc/libvirt/virtqemud.conf",
        "pkaction --action-id org.libvirt.unix.manage --verbose",
        "systemctl is-active libvirtd virtqemud",
    ],
    "privileged_only": ["/etc/libvirt/* (the directory is 0700 root:root)"],
    "policy_inference": (
        "measured: the socket is world-connectable by design, the daemons were "
        "inactive, the action's implicit authorisation is auth_admin_keep, and "
        "50-libvirt.rules grants password-free access to group `libvirt` only "
        "-- which the agent does not hold. What is NOT known is whether "
        "auth_unix_rw is set to 'none', which would bypass polkit entirely. "
        "The existence of libvirtd.conf is itself UNDETERMINED, not absent: "
        "/etc/libvirt is unsearchable"
    ),
    "decision_rule": {
        "ROOT_EQUIVALENT": "auth_unix_rw = 'none' with a socket the agent can "
        "write, or a polkit rule granting the agent org.libvirt.unix.manage: "
        "an authorised session can attach host block devices",
        "NON_ROOT_EQUIVALENT": "polkit-gated with the agent in no granted "
        "group, confirmed by reading the config as root",
    },
}

CHROME_SANDBOX_UNVERIFIED = {
    "minimum_artifact": "an account of the setuid bit the package does not declare",
    "commands": [
        "rpm -Vf /opt/1Password/chrome-sandbox",
        "rpm -q --qf '[%{FILENAMES}\\t%{FILEMODES:octal}\\n]' 1password | grep chrome-sandbox",
    ],
    "privileged_only": [],
    "policy_inference": (
        "the bytes match the package exactly; the package declares mode 100755 "
        "and the disk carries 4755, so the privilege was granted after "
        "packaging by an installer or an administrator. A digest match attests "
        "bytes, not privileges"
    ),
    "decision_rule": {
        "ROOT_EQUIVALENT": "the setuid bit was not deliberate, or the helper "
        "accepts a caller-chosen target",
        "NON_ROOT_EQUIVALENT": "the vendor documents the setuid requirement "
        "for its sandbox and the bit is intentional",
    },
}


def check_for(path_id: str, entry: dict) -> dict:
    if path_id in CHECKS:
        return CHECKS[path_id]
    if path_id.startswith("container_runtimes:libvirt"):
        return LIBVIRT
    if path_id.startswith("setuid:"):
        binary = path_id.split(":", 1)[1]
        if entry.get("evidence", {}).get("integrity") == "FILE_UNREADABLE_BY_AGENT":
            return UNREADABLE_BINARY
        if "chrome-sandbox" in binary:
            return CHROME_SANDBOX_UNVERIFIED
        return UNCLASSIFIED_SETUID
    return UNCLASSIFIED_SETUID


def build() -> dict:
    with open(FINAL, encoding="utf-8") as handle:
        final = json.load(handle)

    items = []
    for path_id in sorted(final.get("requires_operator_evidence_paths", [])):
        entry = final["paths"][path_id]
        template = check_for(path_id, entry)
        evidence = entry.get("evidence", {})
        privileged_only = list(template["privileged_only"])
        # Derived, not hand-maintained: any binary the agent cannot read needs
        # privileged access regardless of which template matched it. The table
        # said `userhelper` needed only analysis while its bytes are behind
        # mode 4711 -- the measurement corrects the table, not the reverse.
        if evidence.get("integrity") == "FILE_UNREADABLE_BY_AGENT":
            mode = evidence.get("file", {}).get("mode")
            privileged_only.append(
                f"the binary's own bytes (mode {mode} -- execute-only for the agent)"
            )
        readable = {
            key: value
            for key, value in evidence.items()
            if key not in ("rule",) and not isinstance(value, (dict, list))
        }
        for key in ("file", "socket", "implicit", "probe"):
            if isinstance(evidence.get(key), dict):
                readable[key] = evidence[key]
        items.append(
            {
                "path": path_id,
                "surface": entry.get("surface"),
                "privilege_effect": entry.get("privilege_effect"),
                "discriminator": entry.get("discriminator"),
                "minimum_artifact": template["minimum_artifact"],
                "commands": template["commands"],
                "readable_evidence": readable,
                "privileged_only_evidence": privileged_only,
                "policy_inference": template["policy_inference"],
                "decision_rule": template["decision_rule"],
                "obtainable_by_agent": not privileged_only,
                "blocks_until_answered": True,
            }
        )

    obtainable = [i["path"] for i in items if i["obtainable_by_agent"]]
    return {
        "generated_from": {
            "file": os.path.basename(FINAL),
            "counts": final.get("counts"),
            "measurement_context_fingerprint": final.get("measurement_context", {}).get(
                "fingerprint_sha256"
            ),
        },
        "items": items,
        "counts": {
            "total": len(items),
            "requires_privileged_access": len(items) - len(obtainable),
            "analysis_only_no_privilege_needed": len(obtainable),
        },
        "analysis_only_paths": obtainable,
        "rule": (
            "an item whose privileged_only_evidence is non-empty cannot be "
            "closed by this agent under any circumstances; it retains blocker "
            "state. An item with an empty list needs analysis, not privilege, "
            "and is still blocking until that analysis is recorded as a "
            "measurement in privilege_resolution.py's rule table"
        ),
        "read_only": True,
        "mutations_performed": [],
    }


def main() -> int:
    checklist = build()
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(checklist, handle, indent=1, sort_keys=True)
    counts = checklist["counts"]
    print(f"operator-evidence items: {counts['total']}")
    print(f"  need privileged access: {counts['requires_privileged_access']}")
    print(f"  need analysis only:     {counts['analysis_only_no_privilege_needed']}")
    for path in checklist["analysis_only_paths"]:
        print(f"    - {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
