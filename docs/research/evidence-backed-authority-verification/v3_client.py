"""Agent-side client. Untrusted by construction; every value it computes is
recomputed by the broker from the store's own bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct

MAX_MESSAGE = 1 << 20


def request(path: str, payload: dict, timeout: float = 30.0) -> dict:
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(path)
        body = json.dumps(payload, separators=(",", ":")).encode()
        conn.sendall(struct.pack(">I", len(body)) + body)
        header = _recv_exact(conn, 4)
        (length,) = struct.unpack(">I", header)
        if length > MAX_MESSAGE:
            raise OSError("oversized reply")
        return json.loads(_recv_exact(conn, length))
    finally:
        conn.close()


def _recv_exact(conn, count: int) -> bytes:
    chunks = []
    while count:
        chunk = conn.recv(count)
        if not chunk:
            raise OSError("peer closed mid-message")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def manifest(store: str) -> dict:
    files_dir = os.path.join(store, "files")
    entries = {}
    for dirpath, dirnames, filenames in os.walk(files_dir):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, files_dir)
            st = os.lstat(full)
            with open(full, "rb") as handle:
                entries[rel] = {
                    "sha256": hashlib.sha256(handle.read()).hexdigest(),
                    "exec": bool(st.st_mode & 0o111),
                }
    return entries


def state_hash(store: str) -> str:
    return hashlib.sha256(
        json.dumps(manifest(store), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def predicted_after(store: str, path: str, payload: bytes, executable: bool) -> str:
    entries = manifest(store)
    entries[path] = {"sha256": hashlib.sha256(payload).hexdigest(), "exec": executable}
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def decide(dep, path: str, payload: bytes, executable: bool = False) -> dict:
    return request(
        dep.decide_socket,
        {
            "kind": "decide",
            "actor": dep.actor,
            "path": path,
            "expected_before_hash": state_hash(dep.store),
            "expected_after_hash": predicted_after(dep.store, path, payload, executable),
            "content_sha256": hashlib.sha256(payload).hexdigest(),
        },
    )


def promote(dep, receipt: dict, payload: bytes, executable: bool = False) -> dict:
    return request(
        dep.broker_socket,
        {
            "kind": "promote",
            "receipt": receipt,
            "content_b64": base64.b64encode(payload).decode(),
            "executable": executable,
        },
    )


def propose(dep, path: str, payload: bytes, executable: bool = False) -> dict:
    decision = decide(dep, path, payload, executable)
    if decision.get("result") != "ALLOW":
        return {"stage": "decision", **decision}
    result = promote(dep, decision["receipt"], payload, executable)
    return {"stage": "promotion", "receipt": decision["receipt"], **result}


def status(dep) -> dict:
    return request(dep.broker_socket, {"kind": "status"})
