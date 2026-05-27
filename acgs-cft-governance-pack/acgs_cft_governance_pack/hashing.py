from __future__ import annotations

import hashlib
import json
from typing import Any


def hash_json(value: Any, *, canonicalize: bool = True) -> str:
    if canonicalize:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8",
        )
    else:
        encoded = str(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def merkle_root(values: list[Any]) -> str:
    leaves = [hash_json(value) for value in values]
    if not leaves:
        return hash_json("")
    while len(leaves) > 1:
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        leaves = [
            hash_json(leaves[index] + leaves[index + 1], canonicalize=False) for index in range(0, len(leaves), 2)
        ]
    return leaves[0]
