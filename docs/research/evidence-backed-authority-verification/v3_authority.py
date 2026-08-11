"""The V3 authority: minimum broker + minimum decision layer, section 9.

Deliberately much smaller than V2's. Section 9 says implement the smallest
prototype that proves the OS authority boundary, not to rebuild the governance
architecture, so the state model is one flat set of files and one operation
class. Everything that made V2's broker large -- scope prefixes, mutation-set
hashing, tree adoption, symlink escape analysis -- is policy, and policy is not
what V3 is testing.

Two processes, two non-delegable uids:

    --mode decide   uid <authority+1>   holds the key, mints receipts
    --mode broker   uid <authority>     owns canonical state, verifies only

The nine broker requirements map to `promote()` below in order: canonicalize,
restrict to the store, verify the receipt, bind to the exact before-state, bind
to the exact requested effect, perform the mutation itself, emit the resulting
hash, reject replay, and never hand out a writable descriptor. The last one is
structural: there is no code path here that sends a file descriptor, and the
channel is plain length-prefixed JSON.

Both processes run inside a container in this demonstration, because the agent
cannot launch a process as another uid without a privileged helper -- which is
the finding, not a workaround. Under the cutover plan each is a systemd service.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import signal
import socket
import struct
import threading
import time
import uuid

MAX_MESSAGE = 1 << 20
_PEERCRED = struct.Struct("3i")
RECEIPT_VERSION = "cspa3-receipt-v1"
SIGNED_FIELDS = (
    "receipt_version",
    "actor",
    "resource",
    "operation",
    "path",
    "expected_before_hash",
    "expected_after_hash",
    "content_sha256",
    "nonce",
    "issued_at",
)

OK = "PROMOTED"
DENIED_SCHEMA = "DENIED_SCHEMA"
DENIED_SIGNATURE = "DENIED_SIGNATURE"
DENIED_REPLAY = "DENIED_REPLAY"
DENIED_PEER = "DENIED_PEER"
DENIED_RESOURCE = "DENIED_RESOURCE"
DENIED_PATH_ESCAPE = "DENIED_PATH_ESCAPE"
DENIED_STALE = "DENIED_STALE"
DENIED_EFFECT_MISMATCH = "DENIED_EFFECT_MISMATCH"
DENIED_UNKNOWN_REQUEST = "DENIED_UNKNOWN_REQUEST"


# ------------------------------------------------------------ canonical state
class Store:
    def __init__(self, root: str):
        self.root = os.path.realpath(root)

    @property
    def files_dir(self) -> str:
        return os.path.join(self.root, "files")

    @property
    def ledger(self) -> str:
        return os.path.join(self.root, "LEDGER.jsonl")

    def manifest(self) -> dict:
        entries = {}
        for dirpath, dirnames, filenames in os.walk(self.files_dir):
            dirnames.sort()
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.files_dir)
                st = os.lstat(full)
                with open(full, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                entries[rel] = {
                    "sha256": digest,
                    "exec": bool(st.st_mode & 0o111),
                }
        return entries

    def state_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self.manifest(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def resolve(self, relative: str) -> str | None:
        """Canonicalize and confine. Returns None if it leaves the store."""
        if os.path.isabs(relative):
            return None
        candidate = os.path.realpath(os.path.join(self.files_dir, relative))
        base = os.path.realpath(self.files_dir)
        if candidate != base and not candidate.startswith(base + os.sep):
            return None
        return candidate

    def write(self, resolved: str, payload: bytes, executable: bool) -> None:
        os.makedirs(os.path.dirname(resolved), exist_ok=True)
        temporary = resolved + f".staging-{uuid.uuid4().hex}"
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o755 if executable else 0o644,
        )
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temporary, resolved)
        dir_fd = os.open(os.path.dirname(resolved), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def append_ledger(self, record: dict) -> None:
        fd = os.open(self.ledger, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(
                fd,
                (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            )
            os.fsync(fd)
        finally:
            os.close(fd)


# ------------------------------------------------------------ receipts
def _payload(receipt: dict) -> bytes:
    return json.dumps(
        {field: receipt[field] for field in SIGNED_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sign(receipt: dict, key: bytes) -> dict:
    signed = dict(receipt)
    signed["tag"] = hmac.new(key, _payload(signed), hashlib.sha256).hexdigest()
    return signed


def verify(receipt: dict, key: bytes) -> bool:
    try:
        expected = hmac.new(key, _payload(receipt), hashlib.sha256).hexdigest()
    except (KeyError, TypeError):
        return False
    return hmac.compare_digest(expected, str(receipt.get("tag", "")))


def schema_errors(receipt) -> list[str]:
    if not isinstance(receipt, dict):
        return ["receipt is not an object"]
    errors = []
    allowed = set(SIGNED_FIELDS) | {"tag"}
    missing = [f for f in allowed if f not in receipt]
    if missing:
        errors.append(f"missing {sorted(missing)}")
    extra = [f for f in receipt if f not in allowed]
    if extra:
        errors.append(f"unknown {sorted(extra)}")
    if receipt.get("receipt_version") != RECEIPT_VERSION:
        errors.append("bad receipt_version")
    if receipt.get("operation") != "write_file":
        errors.append("unsupported operation")
    for field in (
        "expected_before_hash",
        "expected_after_hash",
        "content_sha256",
        "nonce",
        "tag",
    ):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != 64:
            errors.append(f"{field} must be 64 hex chars")
    return errors


# ------------------------------------------------------------ channel
def _send(conn, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    conn.sendall(struct.pack(">I", len(body)) + body)


def _recv_exact(conn, count: int) -> bytes:
    chunks = []
    while count:
        chunk = conn.recv(count)
        if not chunk:
            raise OSError("peer closed mid-message")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def _recv(conn) -> dict:
    (length,) = struct.unpack(">I", _recv_exact(conn, 4))
    if length > MAX_MESSAGE:
        raise OSError(f"declared length {length} exceeds cap")
    return json.loads(_recv_exact(conn, length))


def peer_of(conn) -> dict:
    pid, uid, gid = _PEERCRED.unpack(
        conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size)
    )
    return {"pid": pid, "uid": uid, "gid": gid}


def serve(path: str, handler, accept_uids: tuple[int, ...]) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(path):
        os.unlink(path)
    sock.bind(path)
    os.chmod(path, 0o666)
    sock.listen(16)

    def loop():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    def _handle(conn):
        try:
            peer = peer_of(conn)
            if peer["uid"] not in accept_uids:
                _send(conn, {"result": DENIED_PEER, "peer": peer})
                return
            _send(conn, handler(_recv(conn), peer))
        except (OSError, ValueError) as exc:
            try:
                _send(conn, {"result": "MALFORMED", "detail": str(exc)})
            except OSError:
                pass
        finally:
            conn.close()

    threading.Thread(target=loop, daemon=True).start()
    return sock


# ------------------------------------------------------------ decision layer
class Decision:
    def __init__(self, key: bytes, resource: str, actors: tuple[str, ...]):
        self.key = key
        self.resource = resource
        self.actors = actors

    def handle(self, request: dict, peer: dict) -> dict:
        if request.get("kind") != "decide":
            return {"result": DENIED_UNKNOWN_REQUEST}
        if request.get("actor") not in self.actors:
            return {"result": "DENIED", "reason": "actor not permitted"}
        required = (
            "path",
            "expected_before_hash",
            "expected_after_hash",
            "content_sha256",
        )
        if any(not isinstance(request.get(field), str) for field in required):
            return {"result": "DENIED", "reason": "missing bindings"}
        receipt = {
            "receipt_version": RECEIPT_VERSION,
            "actor": request["actor"],
            "resource": self.resource,
            "operation": "write_file",
            "path": request["path"],
            "expected_before_hash": request["expected_before_hash"],
            "expected_after_hash": request["expected_after_hash"],
            "content_sha256": request["content_sha256"],
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "issued_at": time.time(),
        }
        return {"result": "ALLOW", "receipt": sign(receipt, self.key)}


# ------------------------------------------------------------ broker
class Broker:
    def __init__(self, store: Store, key: bytes, resource: str, actors: tuple[str, ...]):
        self.store = store
        self.key = key
        self.resource = resource
        self.actors = actors
        self._consumed: set[str] = set()

    def handle(self, request: dict, peer: dict) -> dict:
        kind = request.get("kind")
        if kind == "status":
            return {
                "result": "STATUS",
                "uid": os.getuid(),
                "state_hash": self.store.state_hash(),
                "peer": peer,
            }
        if kind != "promote":
            return {"result": DENIED_UNKNOWN_REQUEST, "kind": kind}
        return self.promote(request, peer)

    def promote(self, request: dict, peer: dict) -> dict:
        receipt = request.get("receipt")
        errors = schema_errors(receipt)
        if errors:
            return self._deny(DENIED_SCHEMA, {"errors": errors}, peer)
        if not verify(receipt, self.key):
            return self._deny(DENIED_SIGNATURE, {}, peer)
        if receipt["nonce"] in self._consumed:
            return self._deny(DENIED_REPLAY, {"nonce": receipt["nonce"]}, peer)
        if receipt["actor"] not in self.actors:
            return self._deny(DENIED_PEER, {"actor": receipt["actor"]}, peer)
        if receipt["resource"] != self.resource:
            return self._deny(DENIED_RESOURCE, {"claimed": receipt["resource"]}, peer)

        resolved = self.store.resolve(receipt["path"])
        if resolved is None:
            return self._deny(DENIED_PATH_ESCAPE, {"path": receipt["path"]}, peer)

        before = self.store.state_hash()
        if before != receipt["expected_before_hash"]:
            return self._deny(
                DENIED_STALE,
                {"actual": before, "receipt": receipt["expected_before_hash"]},
                peer,
            )

        # The bytes are carried by the request, but what they must hash to is
        # carried by the *receipt*. The broker recomputes rather than trusting
        # either, so a request that swaps the payload after authorization fails
        # here rather than being promoted.
        try:
            payload = base64.b64decode(request.get("content_b64", ""), validate=True)
        except (ValueError, TypeError) as exc:
            return self._deny(DENIED_EFFECT_MISMATCH, {"detail": str(exc)}, peer)
        if hashlib.sha256(payload).hexdigest() != receipt["content_sha256"]:
            return self._deny(
                DENIED_EFFECT_MISMATCH,
                {"reason": "payload does not match the authorized content hash"},
                peer,
            )

        self.store.write(resolved, payload, bool(request.get("executable")))
        after = self.store.state_hash()
        if after != receipt["expected_after_hash"]:
            # The effect was performed but is not the authorized one. Say so
            # rather than reporting success; the ledger records both hashes.
            self.store.append_ledger(
                {
                    "event": "effect_mismatch",
                    "at": time.time(),
                    "peer": peer,
                    "before": before,
                    "after": after,
                    "expected_after": receipt["expected_after_hash"],
                    "nonce": receipt["nonce"],
                }
            )
            self._consumed.add(receipt["nonce"])
            return {
                "result": DENIED_EFFECT_MISMATCH,
                "state_hash": after,
                "expected_after_hash": receipt["expected_after_hash"],
            }

        self._consumed.add(receipt["nonce"])
        self.store.append_ledger(
            {
                "event": "promotion",
                "at": time.time(),
                "peer": peer,
                "actor": receipt["actor"],
                "path": receipt["path"],
                "before": before,
                "after": after,
                "nonce": receipt["nonce"],
                "tag": receipt["tag"],
            }
        )
        return {
            "result": OK,
            "state_hash": after,
            "matches_receipt": after == receipt["expected_after_hash"],
        }

    def _deny(self, result: str, detail: dict, peer: dict) -> dict:
        self.store.append_ledger(
            {
                "event": "denial",
                "at": time.time(),
                "result": result,
                "detail": detail,
                "peer": peer,
            }
        )
        return {"result": result, "detail": detail}


# ------------------------------------------------------------ entry point
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("broker", "decide"), required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--store")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--agent-uid", type=int, required=True)
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()

    if args.mode == "decide":
        key = os.urandom(32)
        fd = os.open(args.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        handler = Decision(key, args.resource, (args.actor,)).handle
    else:
        # The broker waits for the decision layer to publish the key. The file
        # is mode 0640 owned by the decision uid with the authority group, so
        # the agent cannot read it.
        for _ in range(600):
            if os.path.exists(args.key_file) and os.path.getsize(args.key_file) == 32:
                break
            time.sleep(0.05)
        with open(args.key_file, "rb") as handle:
            key = handle.read()
        store = Store(args.store)
        os.makedirs(store.files_dir, exist_ok=True)
        handler = Broker(store, key, args.resource, (args.actor,)).handle

    serve(args.socket, handler, accept_uids=(args.agent_uid,))
    with open(args.ready_file, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "mode": args.mode,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "pid": os.getpid(),
            },
            handle,
        )
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main())
