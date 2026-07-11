#!/usr/bin/env python3
"""Verify literal SHA-1 commit ancestry without revision-walking metadata."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from collections import deque
from pathlib import Path
from typing import BinaryIO

GIT = "/usr/bin/git"
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
HEADER_KEY_RE = re.compile(rb"[a-z][a-z0-9-]*\Z")
MAX_BATCH_HEADER_BYTES = 256
MAX_COMMIT_BYTES = 1024 * 1024
MAX_PARENTS = 64
MAX_VISITED_COMMITS = 100_000
READ_CHUNK_BYTES = 1024 * 1024


class LiteralAncestryError(RuntimeError):
    """The raw object graph could not be authenticated within fixed bounds."""


def _require_oid(value: str, label: str) -> str:
    if OID_RE.fullmatch(value) is None:
        raise LiteralAncestryError(f"{label} must be a full lowercase SHA-1 OID")
    return value


def _readline_bounded(stream: BinaryIO) -> bytes:
    line = stream.readline(MAX_BATCH_HEADER_BYTES + 1)
    if not line or len(line) > MAX_BATCH_HEADER_BYTES or not line.endswith(b"\n"):
        raise LiteralAncestryError("malformed or oversized cat-file batch header")
    return line[:-1]


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, READ_CHUNK_BYTES))
        if not chunk:
            raise LiteralAncestryError("truncated cat-file object payload")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_commit_parents(payload: bytes) -> tuple[str, ...]:
    separator = payload.find(b"\n\n")
    if separator < 0:
        raise LiteralAncestryError("commit payload has no header terminator")
    raw_headers = payload[:separator].split(b"\n")
    if not raw_headers or not raw_headers[0].startswith(b"tree "):
        raise LiteralAncestryError("commit payload does not begin with a tree header")
    parents: list[str] = []
    seen_tree = False
    parent_block_open = True
    previous_key: bytes | None = None
    for index, line in enumerate(raw_headers):
        if not line or b"\0" in line or b"\r" in line:
            raise LiteralAncestryError("malformed commit header")
        if line.startswith(b" "):
            if previous_key is None or previous_key in {b"tree", b"parent"}:
                raise LiteralAncestryError("invalid commit header continuation")
            continue
        key, separator_byte, value = line.partition(b" ")
        if not separator_byte or HEADER_KEY_RE.fullmatch(key) is None or not value:
            raise LiteralAncestryError("malformed commit header")
        previous_key = key
        if key == b"tree":
            if index != 0 or seen_tree or re.fullmatch(rb"[0-9a-f]{40}", value) is None:
                raise LiteralAncestryError("malformed tree header")
            seen_tree = True
        elif key == b"parent":
            if not parent_block_open or re.fullmatch(rb"[0-9a-f]{40}", value) is None:
                raise LiteralAncestryError("malformed parent header")
            parents.append(value.decode("ascii"))
            if len(parents) > MAX_PARENTS:
                raise LiteralAncestryError("commit parent bound exceeded")
        else:
            parent_block_open = False
    if not seen_tree:
        raise LiteralAncestryError("commit tree header is missing")
    return tuple(parents)


class GitObjectBatch:
    def __init__(self, repo: Path) -> None:
        if not repo.is_absolute() or repo.resolve(strict=True) != repo or not repo.is_dir():
            raise LiteralAncestryError("repository path must be an absolute canonical directory")
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "HOME": "/dev/null",
            "XDG_CONFIG_HOME": "/dev/null",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        try:
            self.process = subprocess.Popen(
                [GIT, "--no-replace-objects", "-C", str(repo), "cat-file", "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
            )
        except OSError as exc:
            raise LiteralAncestryError(f"cannot start trusted cat-file process: {exc}") from exc
        if self.process.stdin is None or self.process.stdout is None:
            self._abort()
            raise LiteralAncestryError("cat-file process pipes are unavailable")

    def _abort(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()

    def close(self) -> None:
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            return_code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            self._abort()
            raise LiteralAncestryError("cat-file process did not terminate") from exc
        if return_code != 0:
            raise LiteralAncestryError("cat-file process failed")

    def __enter__(self) -> GitObjectBatch:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is not None:
            self._abort()
        else:
            self.close()

    def read_commit(self, oid: str) -> tuple[str, ...]:
        requested = _require_oid(oid, "object")
        assert self.process.stdin is not None and self.process.stdout is not None
        try:
            self.process.stdin.write(requested.encode("ascii") + b"\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LiteralAncestryError("cat-file process rejected an object query") from exc
        header = _readline_bounded(self.process.stdout)
        fields = header.split(b" ")
        if len(fields) == 2 and fields[1] == b"missing":
            raise LiteralAncestryError(f"commit object is missing: {requested}")
        if len(fields) != 3:
            raise LiteralAncestryError("malformed cat-file object header")
        header_oid, object_type, raw_size = fields
        if header_oid != requested.encode("ascii") or object_type != b"commit":
            raise LiteralAncestryError("cat-file returned the wrong OID or a non-commit object")
        if not raw_size.isdigit() or (len(raw_size) > 1 and raw_size.startswith(b"0")):
            raise LiteralAncestryError("cat-file returned a malformed object size")
        size = int(raw_size)
        if size > MAX_COMMIT_BYTES:
            raise LiteralAncestryError("commit object size bound exceeded")
        payload = _read_exact(self.process.stdout, size)
        if self.process.stdout.read(1) != b"\n":
            raise LiteralAncestryError("cat-file object framing is malformed")
        canonical = b"commit " + str(size).encode("ascii") + b"\0" + payload
        actual_oid = hashlib.sha1(canonical).hexdigest()
        if actual_oid != requested:
            raise LiteralAncestryError("commit object hash mismatch")
        return _parse_commit_parents(payload)


def _walk_literal_ancestry(
    batch: GitObjectBatch,
    ancestor: str,
    descendant: str,
    *,
    max_visited: int = MAX_VISITED_COMMITS,
) -> bool:
    pending = deque([descendant])
    visited: set[str] = set()
    while pending:
        oid = pending.popleft()
        if oid in visited:
            continue
        if len(visited) >= max_visited:
            raise LiteralAncestryError("visited commit bound exceeded")
        visited.add(oid)
        parents = batch.read_commit(oid)
        if oid == ancestor:
            return True
        pending.extend(parent for parent in parents if parent not in visited)
    return False


def verify_literal_ancestry(repo: Path, ancestor: str, descendant: str) -> None:
    ancestor = _require_oid(ancestor, "ancestor")
    descendant = _require_oid(descendant, "descendant")
    with GitObjectBatch(repo) as batch:
        if not _walk_literal_ancestry(batch, ancestor, descendant):
            raise LiteralAncestryError("ancestor is not in the literal commit parent graph")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: verify_literal_ancestry.py <absolute-repo> <ancestor> <descendant>",
            file=sys.stderr,
        )
        return 2
    try:
        verify_literal_ancestry(Path(arguments[0]), arguments[1], arguments[2])
    except (LiteralAncestryError, OSError, ValueError) as exc:
        print(f"literal ancestry verification failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
