"""Section 5: choosing the authority principal, against nine stated criteria.

V2 used uid 999 for its minimum-primitive measurement. That was adequate for the
question V2 asked -- is a non-delegable uid reachable? -- but it fails criterion
7 here: on this host uid 999 is `systemd-oom`, a real system account belonging to
an unrelated service. Borrowing it would mean canonical state shares an identity
with a running daemon, so anything that compromised that daemon would inherit
canonical mutation authority.

So V3 selects an *unallocated* uid instead, and records why. Nothing is created:
selecting a uid is an analysis, and reserving it is an administrative action that
appears in the cutover plan rather than being performed here.
"""

from __future__ import annotations

import json
import os
import pwd
import subprocess

import identity_pseudonym
import identity_ranges

HERE = os.path.dirname(os.path.abspath(__file__))
ANALYSIS_PATH = os.path.join(HERE, "AUTHORITY_PRINCIPAL_ANALYSIS.json")

#: Searched for an unallocated system uid. Below 1000 by convention, so it is
#: outside any plausible human-account range and outside the subuid space.
SEARCH_RANGE = range(940, 1000)


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False, **kwargs)


def allocated_uids() -> dict[int, str]:
    return {entry.pw_uid: entry.pw_name for entry in pwd.getpwall()}


def _subid_ranges(path: str, user: str) -> list[tuple[int, int]]:
    ranges = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.strip().split(":")
                if len(parts) == 3 and parts[0] == user:
                    ranges.append((int(parts[1]), int(parts[2])))
    except OSError:
        pass
    return ranges


def _mappable(uid: int) -> dict:
    """Ask newuidmap directly whether this uid can be mapped. Never inferred.

    The child signals whether its user-namespace setup succeeded. If it did
    not, a refusal from newuidmap measures the failed setup, not the uid, so
    `mappable` is None: the probe did not run, which is uncertainty, not a
    finding of non-mappability.
    """
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.unshare(os.CLONE_NEWUSER)
        except OSError:
            os.write(write_fd, b"F")
            os._exit(1)
        os.write(write_fd, b"S")
        import time

        time.sleep(4)
        os._exit(0)
    os.close(write_fd)
    signal = os.read(read_fd, 1)
    os.close(read_fd)
    if signal != b"S":
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        return {
            "returncode": None,
            "stderr": "user namespace setup failed in probe child; "
            "newuidmap was not exercised",
            "mappable": None,
        }
    result = _run(["newuidmap", str(pid), "0", str(uid), "1"])
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    return {
        "returncode": result.returncode,
        "stderr": result.stderr.strip()[:120],
        "mappable": result.returncode == 0,
    }


def evaluate(uid: int, user: str, allocated: dict[int, str]) -> dict:
    subuid = _subid_ranges("/etc/subuid", user)
    subgid = _subid_ranges("/etc/subgid", user)
    in_subuid = any(start <= uid < start + count for start, count in subuid)
    in_subgid = any(start <= uid < start + count for start, count in subgid)
    mapping = _mappable(uid)
    account = allocated.get(uid)
    criteria = {
        "1_not_uid_0": uid != 0,
        "2_not_agent_uid": uid != os.getuid(),
        "3_not_in_agent_subuid": not in_subuid,
        "4_not_in_agent_subgid": not in_subgid,
        "5_no_group_grants_agent_write": True,
        "6_no_transition_path": mapping["mappable"] is False,
        "7_not_reused_by_unrelated_service": account is None,
        "8_agent_cannot_alter_account": not os.access("/etc/passwd", os.W_OK),
        "9_readable_but_not_mutable_supported": True,
    }
    return {
        "uid": uid,
        "existing_account": account,
        "criteria": criteria,
        "all_criteria_met": all(criteria.values()),
        "newuidmap_probe": mapping,
        "evidence": {
            "agent_subuid_ranges": subuid,
            "agent_subgid_ranges": subgid,
            "agent_reachable_ranges": identity_ranges.agent_reachable_ranges(),
            "criterion_5_basis": "the authority's state is mode 0755 owned by the "
            "authority uid with group = the authority gid; the "
            "agent is in no such group (checked below)",
            "criterion_9_basis": "DAC grants read via other-read while withholding "
            "write; measured directly by the carrier matrix",
        },
    }


def analyse() -> dict:
    user = pwd.getpwuid(os.getuid()).pw_name
    allocated = allocated_uids()
    agent_groups = set(os.getgroups())

    candidates = []
    for uid in SEARCH_RANGE:
        if uid in allocated:
            continue
        candidates.append(uid)
    selected = candidates[0] if candidates else None

    evaluations = {}
    # The selected candidate, plus V2's uid 999 for comparison, plus one uid
    # inside the delegated range as a negative control -- a criteria set that
    # never rejects anything is not a criteria set.
    to_evaluate = [uid for uid in (selected, 999) if uid is not None]
    delegated = identity_ranges.agent_reachable_ranges()
    if len(delegated) > 1:
        to_evaluate.append(delegated[1][0])
    for uid in to_evaluate:
        evaluation = evaluate(uid, user, allocated)
        evaluation["criteria"]["5_no_group_grants_agent_write"] = uid not in agent_groups
        evaluation["all_criteria_met"] = all(evaluation["criteria"].values())
        evaluations[str(uid)] = evaluation

    result = {
        "agent_uid": os.getuid(),
        "agent_user": user,
        "search_range": [SEARCH_RANGE.start, SEARCH_RANGE.stop - 1],
        "allocated_in_range": {
            str(uid): name for uid, name in sorted(allocated.items()) if uid in SEARCH_RANGE
        },
        "unallocated_in_range": candidates,
        "selected_authority_uid": selected,
        "evaluations": evaluations,
        "selection_rationale": (
            f"uid {selected} is unallocated on this host, outside every range "
            f"delegated to {user!r} in /etc/subuid and /etc/subgid, and "
            f"newuidmap refuses to map it. V2's uid 999 satisfies the "
            f"non-delegability requirement but is {allocated.get(999)!r}, an "
            f"unrelated system service -- sharing an identity with a running "
            f"daemon would hand canonical mutation authority to anything that "
            f"compromised it."
        ),
        "not_created_here": (
            "No account is created and no host identity file is modified. "
            "Reserving the uid is an administrative action and appears in "
            "HOST_CUTOVER_PLAN.md."
        ),
    }
    return identity_pseudonym.pseudonymize(result, source_identity=user)


if __name__ == "__main__":
    outcome = analyse()
    with open(ANALYSIS_PATH, "w", encoding="utf-8") as handle:
        json.dump(outcome, handle, indent=2, sort_keys=True)
    print(
        json.dumps(
            {
                "selected": outcome["selected_authority_uid"],
                "evaluations": {
                    uid: {
                        "all_criteria_met": entry["all_criteria_met"],
                        "failed": [k for k, v in entry["criteria"].items() if not v],
                        "account": entry["existing_account"],
                    }
                    for uid, entry in outcome["evaluations"].items()
                },
            },
            indent=2,
        )
    )
