"""Count SHA-bound ChatGPT Codex connector evidence for the required review gate.

Used by `.github/workflows/codex-code-review.yml`. Empty-body reviews, dismissed
reviews, and the connector's "create an environment" stub are not evidence.
Issue comments count only when they contain ``**Reviewed commit:** `sha``` matching
the current head (how Codex records a clean pass).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any

CONNECTOR_BOT = "chatgpt-codex-connector[bot]"
REVIEW_STATES = frozenset({"COMMENTED", "APPROVED", "CHANGES_REQUESTED"})
ENV_STUB = "create an environment for this repo"
REVIEWED_COMMIT_RE = re.compile(
    r"\*\*Reviewed commit:\*\*\s*`([0-9a-f]{7,40})`",
    re.IGNORECASE,
)
SHA_PREFIX_LEN = 10


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


def count_reviews(payload: Any, *, sha: str, bot: str = CONNECTOR_BOT) -> int:
    if len(sha) < SHA_PREFIX_LEN:
        return 0
    n = 0
    for item in _pages(payload):
        user = (item.get("user") or {}).get("login")
        body = item.get("body") or ""
        if user != bot:
            continue
        if item.get("commit_id") != sha:
            continue
        if item.get("state") not in REVIEW_STATES:
            continue
        if not body.strip():
            continue
        if ENV_STUB.lower() in body.lower():
            continue
        n += 1
    return n


def _cited_sha_matches(cited: str, sha: str) -> bool:
    return sha.startswith(cited) or cited.startswith(sha[: len(cited)])


def count_comments(payload: Any, *, sha: str, bot: str = CONNECTOR_BOT) -> int:
    if len(sha) < SHA_PREFIX_LEN:
        return 0
    n = 0
    for item in _pages(payload):
        user = (item.get("user") or {}).get("login")
        body = item.get("body") or ""
        if user != bot:
            continue
        if any(
            _cited_sha_matches(match.group(1), sha) for match in REVIEWED_COMMIT_RE.finditer(body)
        ):
            n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("reviews", "comments"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--bot", default=CONNECTOR_BOT)
    args = parser.parse_args(argv)
    payload = json.load(sys.stdin)
    if args.kind == "reviews":
        print(count_reviews(payload, sha=args.sha, bot=args.bot))
    else:
        print(count_comments(payload, sha=args.sha, bot=args.bot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
