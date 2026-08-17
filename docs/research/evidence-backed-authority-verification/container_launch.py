"""Runs as PID 1 inside the authority container. Establishes ownership, then
drops to the two authority uids and never regains them.

This file exists because the agent principal cannot start a process as another
uid without a privileged helper. That is the finding, not a workaround: under
the cutover plan systemd starts each service with `User=`, this file does not
exist, and no root process is present in the authority domain at all.

What it does, in order:

1. chown the bind-mounted store, runtime and code directories to the authority
   principal, so that from this moment the agent uid owns none of them;
2. fork and drop to uid <authority+1> for the decision layer;
3. fork and drop to uid <authority> for the broker;
4. reap.

`setgroups([])` before `setuid` matters: without it the child keeps root's
supplementary groups and the drop is incomplete.
"""

from __future__ import annotations

import os
import sys
import time

AUTHORITY_UID = int(os.environ["CSPA3_AUTHORITY_UID"])
AUTHORITY_GID = AUTHORITY_UID
DECISION_UID = AUTHORITY_UID + 1
STORE = "/srv/canonical"
RUNTIME = "/srv/run"
CODE = "/srv/code"


def own(path: str, uid: int, gid: int, mode: int) -> None:
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            os.chown(full, uid, gid, follow_symlinks=False)
            if not os.path.islink(full):
                os.chmod(full, 0o755 if os.path.isdir(full) else 0o644)


def drop_and_run(uid: int, gid: int, argv: list[str]) -> int:
    pid = os.fork()
    if pid == 0:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if os.getuid() != uid or os.geteuid() != uid:
            sys.stderr.write(f"privilege drop to {uid} failed\n")
            os._exit(126)
        os.execvp(argv[0], argv)
        os._exit(127)
    return pid


def main() -> int:
    resource = os.environ["CSPA3_RESOURCE"]
    actor = os.environ["CSPA3_ACTOR"]
    agent_uid = int(os.environ["CSPA3_AGENT_UID"])

    os.makedirs(os.path.join(STORE, "files"), exist_ok=True)
    # Readable by everyone, writable only by the authority. Section 8's
    # "read permitted, write denied, metadata mutation denied".
    own(STORE, AUTHORITY_UID, AUTHORITY_GID, 0o755)
    # 0771: both authority uids share gid 940 and must create the sockets, the
    # key file and the ready files here. The agent gets --x, enough to traverse
    # to a socket it may connect to, not enough to list the directory or to
    # unlink and replace an endpoint (attack K).
    own(RUNTIME, AUTHORITY_UID, AUTHORITY_GID, 0o771)
    # Code is owned by the authority and not writable by the agent: section 11
    # treats an agent-replaceable broker as an authority-equivalent path.
    own(CODE, AUTHORITY_UID, AUTHORITY_GID, 0o755)

    common = [
        sys.executable,
        os.path.join(CODE, "v3_authority.py"),
        "--resource",
        resource,
        "--actor",
        actor,
        "--agent-uid",
        str(agent_uid),
        "--key-file",
        os.path.join(RUNTIME, "authority.key"),
    ]
    decision_pid = drop_and_run(
        DECISION_UID,
        AUTHORITY_GID,
        [
            *common,
            "--mode",
            "decide",
            "--socket",
            os.path.join(RUNTIME, "decide.sock"),
            "--ready-file",
            os.path.join(RUNTIME, "decide.ready"),
        ],
    )
    broker_pid = drop_and_run(
        AUTHORITY_UID,
        AUTHORITY_GID,
        [
            *common,
            "--mode",
            "broker",
            "--store",
            STORE,
            "--socket",
            os.path.join(RUNTIME, "broker.sock"),
            "--ready-file",
            os.path.join(RUNTIME, "broker.ready"),
        ],
    )
    with open(os.path.join(RUNTIME, "pids.json"), "w", encoding="utf-8") as handle:
        handle.write(f'{{"decision": {decision_pid}, "broker": {broker_pid}}}')
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main())
