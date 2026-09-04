"""Count exact-head ChatGPT Codex connector comments for the review gate.

The trusted workflow checks only issue comments posted by the connector bot. A
comment qualifies when its connector-owned metadata is complete, cites the full
pull-request head SHA, and its summary table says the code review completed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any

CONNECTOR_BOT = "chatgpt-codex-connector[bot]"
FULL_SHA_RE = r"[0-9a-f]{40}"
SECURITY_REVIEW_METADATA_RE = re.compile(
    r"<!--\s*codex-security-review:v1\s+(\{.*?\})\s*-->",
    re.IGNORECASE | re.DOTALL,
)
COMPLETED_CODE_REVIEW_ROW_RE = re.compile(
    r"^\|\s*📝\s*\*\*Code Review\*\*\s*\|\s*✅\s*\*\*Completed\*\*[^\n|]*"
    r"\|\s*`([0-9a-f]{7,40})`\s*\|",
    re.IGNORECASE | re.MULTILINE,
)


def _pages(payload: Any) -> list[Mapping[str, Any]]:
    """Flatten ``gh api --paginate --slurp`` output or a bare list/object."""
    if payload is None:
        return []
    if isinstance(payload, Mapping):
        if "user" not in payload and payload.get("message"):
            raise ValueError(f"GitHub API error: {payload['message']}")
        return [payload]
    if not isinstance(payload, Sequence) or isinstance(payload, (str, bytes)):
        return []
    items: list[Mapping[str, Any]] = []
    for page in payload:
        if isinstance(page, Sequence) and not isinstance(page, (str, bytes, Mapping)):
            items.extend(item for item in page if isinstance(item, Mapping))
        elif isinstance(page, Mapping):
            items.append(page)
    return items


def _cited_shas(body: str) -> set[str]:
    reviewed_prefixes = {
        match.group(1).lower() for match in COMPLETED_CODE_REVIEW_ROW_RE.finditer(body)
    }
    if not reviewed_prefixes:
        return set()
    cited: set[str] = set()
    for match in SECURITY_REVIEW_METADATA_RE.finditer(body):
        try:
            metadata = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        head_sha = metadata.get("headSha")
        if metadata.get("status") == "completed" and isinstance(head_sha, str):
            if re.fullmatch(FULL_SHA_RE, head_sha, re.IGNORECASE):
                normalized = head_sha.lower()
                if any(normalized.startswith(prefix) for prefix in reviewed_prefixes):
                    cited.add(normalized)
    return cited


def count_comments(payload: Any, *, sha: str, bot: str = CONNECTOR_BOT) -> int:
    if not re.fullmatch(FULL_SHA_RE, sha, re.IGNORECASE):
        return 0
    expected = sha.lower()
    return sum(
        1
        for item in _pages(payload)
        if (item.get("user") or {}).get("login") == bot
        and expected in _cited_shas(item.get("body") or "")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--bot", default=CONNECTOR_BOT)
    args = parser.parse_args(argv)
    payload = json.load(sys.stdin)
    print(count_comments(payload, sha=args.sha, bot=args.bot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
