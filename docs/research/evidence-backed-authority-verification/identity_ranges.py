"""Which uids the agent principal can already reach, as a set of ranges.

Used to keep a recurring measurement error out of the results: an operation that
lands on a uid the agent could already become is not an escalation. The rootless
container probe originally scored `chown 4242` inside the container -- which maps
to host uid 528530, inside the agent's own delegated subuid range -- as
root-equivalence. It is the opposite: it is the delegation behaving correctly.
"""

from __future__ import annotations

import os
import pwd


def agent_reachable_ranges(user: str | None = None) -> list[tuple[int, int]]:
    """The agent's own uid, plus every range delegated to it in /etc/subuid."""
    user = user or pwd.getpwuid(os.getuid()).pw_name
    ranges: list[tuple[int, int]] = [(os.getuid(), 1)]
    try:
        with open("/etc/subuid", encoding="utf-8") as handle:
            for line in handle:
                parts = line.strip().split(":")
                if len(parts) == 3 and parts[0] == user:
                    ranges.append((int(parts[1]), int(parts[2])))
    except OSError:
        pass
    return ranges


def is_reachable(uid: int) -> bool:
    return any(start <= uid < start + count for start, count in agent_reachable_ranges())
