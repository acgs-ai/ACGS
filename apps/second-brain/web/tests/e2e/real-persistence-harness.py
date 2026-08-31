from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import TextIOBase
from pathlib import Path
from typing import BinaryIO
from urllib.request import urlopen
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ADMIN_URL = (
    "postgresql+psycopg://second_brain_owner:second_brain_owner_dev@127.0.0.1:55439/postgres"
)
DB_PATTERN = re.compile(r"second_brain_test_[0-9a-f]{32}")
OWNER_ID = "11111111-1111-4111-8111-111111111111"
WORKSPACE_ID = "22222222-2222-4222-8222-222222222222"
WEB_ROOT = Path(__file__).resolve().parents[2]
SERVICE_ROOT = WEB_ROOT.parent / "service"
API_PORT, WEB_PORT, STATUS_PORT = 3320, 3302, 3321
LOG_LIMIT_BYTES = 64 * 1024
CLEANUP_TIMEOUT_SECONDS = 8.0
CLEANUP_TERM_GRACE_SECONDS = 0.5
SEEDED_PRIVATE_TEXT = b"PRIVATE_E2E_SOURCE_STRING_DO_NOT_LOG"
stop = threading.Event()
private_log_leaks: list[str] = []
private_log_lock = threading.Lock()
recovery_errors: list[str] = []
recovery_complete = threading.Event()


def scan_private_marker(tail: bytes, chunk: bytes) -> tuple[bytes, bool]:
    combined = tail + chunk
    keep = len(SEEDED_PRIVATE_TEXT) - 1
    return combined[-keep:], SEEDED_PRIVATE_TEXT in combined


def record_private_leak(name: str) -> None:
    with private_log_lock:
        if name not in private_log_leaks:
            private_log_leaks.append(name)
    stop.set()


@dataclass
class Child:
    name: str
    process: subprocess.Popen[bytes]
    stream: BinaryIO
    log: bytearray = field(default_factory=bytearray)
    lock: threading.Lock = field(default_factory=threading.Lock)
    reader: threading.Thread | None = None
    scan_tail: bytes = b""

    def append(self, chunk: bytes) -> None:
        found = False
        with self.lock:
            self.log.extend(chunk)
            if len(self.log) > LOG_LIMIT_BYTES:
                del self.log[: len(self.log) - LOG_LIMIT_BYTES]
            self.scan_tail, found = scan_private_marker(self.scan_tail, chunk)
        if found:
            record_private_leak(self.name)

    def snapshot(self) -> bytes:
        with self.lock:
            return bytes(self.log)


@dataclass
class BoundedTextCapture(TextIOBase):
    name: str
    log: bytearray = field(default_factory=bytearray)
    scan_tail: bytes = b""
    lock: threading.Lock = field(default_factory=threading.Lock)

    def write(self, value: str) -> int:
        chunk = value.encode("utf-8", errors="replace")
        found = False
        with self.lock:
            self.log.extend(chunk)
            if len(self.log) > LOG_LIMIT_BYTES:
                del self.log[: len(self.log) - LOG_LIMIT_BYTES]
            self.scan_tail, found = scan_private_marker(self.scan_tail, chunk)
        if found:
            record_private_leak(self.name)
        return len(value)

    def snapshot(self) -> bytes:
        with self.lock:
            return bytes(self.log)


@dataclass
class RecoveryProofStatus:
    state: str = "pending"
    code: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self) -> dict[str, str]:
        with self.lock:
            payload = {"state": self.state}
            if self.code is not None:
                payload["code"] = self.code
            return payload

    def succeed(self) -> None:
        with self.lock:
            if self.state != "pending":
                raise RuntimeError("recovery proof status is already terminal")
            self.state = "success"

    def fail(self, code: str) -> None:
        if code not in {"recovery_failed", "recovery_timeout"}:
            raise ValueError("invalid recovery proof error code")
        with self.lock:
            if self.state != "pending":
                raise RuntimeError("recovery proof status is already terminal")
            self.state = "error"
            self.code = code


children: list[Child] = []
children_lock = threading.Lock()
cleanup_started = False
migration_log = BoundedTextCapture("migration")


def clean_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.startswith("SECOND_BRAIN_")}


def available(port: int) -> bool:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def wait_url(url: str, child: Child) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if stop.is_set():
            raise RuntimeError(f"stopped while waiting for {url}")
        if child.process.poll() is not None:
            raise RuntimeError(f"{child.name} exited with status {child.process.returncode}")
        try:
            with urlopen(url, timeout=0.5) as response:
                if response.status == 200:
                    return
        except OSError:
            if stop.wait(0.1):
                raise RuntimeError(f"stopped while waiting for {url}") from None
    raise RuntimeError(f"timed out waiting for {url}")


def _drain(child: Child) -> None:
    while chunk := child.stream.read(4096):
        child.append(chunk)


def spawn(name: str, args: list[str], cwd: Path, env: dict[str, str]) -> Child:
    with children_lock:
        if cleanup_started:
            raise RuntimeError("child process cleanup has begun")
        process = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if process.stdout is None:
            raise RuntimeError(f"{name} log pipe was not created")
        child = Child(name=name, process=process, stream=process.stdout)
        child.reader = threading.Thread(target=_drain, args=(child,), daemon=True)
        child.reader.start()
        children.append(child)
        return child


def begin_child_cleanup() -> list[Child]:
    global cleanup_started
    with children_lock:
        cleanup_started = True
        return list(children)


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    return True


def terminate_child_process_groups(cleanup_children: list[Child], *, deadline: float) -> list[str]:
    errors: list[str] = []
    for child in cleanup_children:
        try:
            os.killpg(child.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    term_deadline = min(deadline, time.monotonic() + CLEANUP_TERM_GRACE_SECONDS)
    while time.monotonic() < term_deadline:
        for child in cleanup_children:
            child.process.poll()
        if not any(_process_group_exists(child.process.pid) for child in cleanup_children):
            break
        time.sleep(0.01)

    for child in cleanup_children:
        if _process_group_exists(child.process.pid):
            try:
                os.killpg(child.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    while time.monotonic() < deadline:
        for child in cleanup_children:
            child.process.poll()
        if not any(_process_group_exists(child.process.pid) for child in cleanup_children):
            break
        time.sleep(0.01)

    for child in cleanup_children:
        child.process.poll()
        if child.process.returncode is None:
            errors.append(f"{child.name} process did not terminate")
        if _process_group_exists(child.process.pid):
            errors.append(f"{child.name} process group did not terminate")
    return errors


def join_cleanup_threads(
    cleanup_children: list[Child], threads: list[threading.Thread], *, deadline: float
) -> list[str]:
    errors: list[str] = []
    named_threads = [(thread.name, thread) for thread in threads]
    named_threads.extend(
        (f"{child.name} log reader", child.reader)
        for child in cleanup_children
        if child.reader is not None
    )
    for name, thread in named_threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            errors.append(f"{name} did not terminate")
    return errors


def cleanup_children_and_threads(
    cleanup_children: list[Child], threads: list[threading.Thread], *, deadline: float
) -> list[str]:
    errors = terminate_child_process_groups(cleanup_children, deadline=deadline)
    errors.extend(join_cleanup_threads(cleanup_children, threads, deadline=deadline))
    return errors


def status_http_response(snapshot: dict[str, str]) -> tuple[int, dict[str, str]]:
    state = snapshot.get("state")
    if state == "pending":
        return 202, {"state": "pending"}
    if state == "success":
        return 200, {"state": "success"}
    return 503, {"state": "error", "code": snapshot.get("code", "recovery_failed")}


def start_status_server(
    status: RecoveryProofStatus,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class StatusHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/status":
                self.send_error(404)
                return
            response_status, payload = status_http_response(status.snapshot())
            encoded = json.dumps(payload, separators=(",", ":")).encode("ascii")
            self.send_response(response_status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", STATUS_PORT), StatusHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        name="recovery-status-server",
        daemon=False,
    )
    thread.start()
    return server, thread


def kill(child: Child) -> None:
    if child.process.poll() is None:
        os.killpg(child.process.pid, signal.SIGKILL)
        child.process.wait(timeout=5)
    if child.reader:
        child.reader.join(timeout=5)
        if child.reader.is_alive():
            raise RuntimeError(f"{child.name} log reader did not terminate after SIGKILL")


def wait_for_database(
    engine_url: str, query: str, parameters: dict[str, object], description: str
) -> tuple[object, ...]:
    deadline = time.monotonic() + 30
    engine = create_engine(engine_url)
    try:
        while time.monotonic() < deadline:
            if stop.is_set():
                raise RuntimeError(f"stopped while waiting for {description}")
            with engine.connect() as connection:
                row = connection.execute(text(query), parameters).one_or_none()
            if row is not None:
                return tuple(row)
            if stop.wait(0.05):
                raise RuntimeError(f"stopped while waiting for {description}")
    finally:
        engine.dispose()
    raise RuntimeError(f"timed out waiting for {description}")


def prove_killed_worker_recovery(database_url: str, worker_env: dict[str, str]) -> None:
    claim_program = """
import time
from second_brain.config import get_worker_settings
from second_brain.db import (attest_runtime_role, attest_worker_role, create_session_factory,
    create_worker_content_engine, create_worker_dispatcher_engine)
from second_brain.storage import FilesystemStorage
from second_brain.worker import IngestionWorker, provider_from_settings
s=get_worker_settings()
content=create_worker_content_engine(s)
dispatcher=create_worker_dispatcher_engine(s)
attest_runtime_role(content)
attest_worker_role(dispatcher)
w=IngestionWorker(create_session_factory(content),FilesystemStorage(s.storage_root,s.max_upload_bytes),provider_from_settings(s),s,'browser-e2e-killed-claim',dispatcher_session_factory=create_session_factory(dispatcher),lease_seconds=1)
assert w.claim(1) is not None
print('claimed',flush=True)
time.sleep(60)
"""
    try:
        job_id, source_id = wait_for_database(
            database_url,
            "SELECT id,source_id FROM ingestion_jobs WHERE state='queued' "
            "ORDER BY created_at,id LIMIT 1",
            {},
            "the browser-created queued ingestion job",
        )
        claimant = spawn(
            "worker-killed-claim",
            [sys.executable, "-c", claim_program],
            SERVICE_ROOT,
            worker_env,
        )
        wait_for_database(
            database_url,
            "SELECT id FROM ingestion_jobs WHERE id=:job AND state='processing' "
            "AND lease_owner='browser-e2e-killed-claim'",
            {"job": job_id},
            "the isolated worker claim",
        )
        killed_pid = claimant.process.pid
        kill(claimant)
        wait_for_database(
            database_url,
            "SELECT id FROM ingestion_jobs WHERE id=:job AND state='processing' "
            "AND lease_expires_at<=clock_timestamp()",
            {"job": job_id},
            "the killed worker lease to expire",
        )
        replacement = spawn(
            "worker-replacement",
            [
                sys.executable,
                "-m",
                "second_brain.worker",
                "--worker-id",
                "browser-e2e-replacement",
            ],
            SERVICE_ROOT,
            worker_env,
        )
        if replacement.process.pid == killed_pid:
            raise RuntimeError("replacement worker did not use a distinct process")
        wait_for_database(
            database_url,
            "SELECT id FROM ingestion_jobs WHERE id=:job AND state='ready'",
            {"job": job_id},
            "the replacement worker to complete the job",
        )
        engine = create_engine(database_url)
        try:
            with engine.connect() as connection:
                events = list(
                    connection.execute(
                        text(
                            "SELECT to_state,reason_class FROM ingestion_job_events "
                            "WHERE job_id=:job ORDER BY occurred_at,id"
                        ),
                        {"job": job_id},
                    )
                )
                counts = connection.execute(
                    text(
                        "SELECT "
                        "(SELECT count(*) FROM documents WHERE source_version_id IN "
                        " (SELECT id FROM source_versions WHERE source_id=:source)),"
                        "(SELECT count(*) FROM chunks WHERE source_version_id IN "
                        " (SELECT id FROM source_versions WHERE source_id=:source)),"
                        "(SELECT count(*) FROM embeddings WHERE chunk_id IN "
                        " (SELECT chunk.id FROM chunks AS chunk JOIN source_versions AS version "
                        "  ON version.id=chunk.source_version_id WHERE version.source_id=:source)),"
                        "(SELECT attempts FROM ingestion_jobs WHERE id=:job),"
                        "(SELECT count(*) FROM ingestion_job_events WHERE job_id=:job "
                        " AND reason_class='processing_retry')"
                    ),
                    {"source": source_id, "job": job_id},
                ).one()
        finally:
            engine.dispose()
        if [tuple(event) for event in events] != [
            ("queued", "capture_queued"),
            ("processing", "claimed"),
            ("processing", "lease_reclaimed"),
            ("ready", "semantic_available"),
        ]:
            raise RuntimeError(
                "ingestion history did not preserve queued/claim/reclaim/ready order"
            )
        if tuple(counts) != (1, 1, 1, 2, 0):
            raise RuntimeError("worker recovery did not produce exactly one artifact lineage")
    except BaseException as error:
        recovery_errors.append(f"{type(error).__name__}: {error}")
        stop.set()
    finally:
        recovery_complete.set()


def require_recovery_completion(
    recovery: threading.Thread,
    complete: threading.Event,
    errors: list[str],
    *,
    timeout: float,
) -> None:
    if not complete.wait(timeout=timeout):
        raise RuntimeError("worker recovery proof did not complete")
    recovery.join(timeout=timeout)
    if recovery.is_alive():
        raise RuntimeError("worker recovery proof did not terminate")
    if errors:
        raise RuntimeError("; ".join(errors))


def publish_recovery_status(
    recovery: threading.Thread,
    errors: list[str],
    status: RecoveryProofStatus,
    *,
    timeout: float,
) -> None:
    recovery.join(timeout=timeout)
    if recovery.is_alive():
        status.fail("recovery_timeout")
    elif errors:
        status.fail("recovery_failed")
    else:
        status.succeed()


def final_private_log_recheck() -> None:
    for captured in [migration_log, *children]:
        if SEEDED_PRIVATE_TEXT in captured.snapshot():
            record_private_leak(captured.name)


def emit_failure_logs() -> None:
    for captured in [migration_log, *children]:
        output = captured.snapshot().replace(SEEDED_PRIVATE_TEXT, b"[REDACTED PRIVATE SOURCE TEXT]")
        if not output:
            continue
        sys.stderr.write(f"\n--- bounded {captured.name} log (last {len(output)} bytes) ---\n")
        sys.stderr.write(output.decode("utf-8", errors="replace"))
        if not output.endswith(b"\n"):
            sys.stderr.write("\n")


def main() -> None:
    if not all(available(port) for port in (API_PORT, WEB_PORT, STATUS_PORT)):
        raise RuntimeError("reserved E2E port is already in use")
    database = f"second_brain_test_{uuid4().hex}"
    if not DB_PATTERN.fullmatch(database):
        raise RuntimeError("unsafe disposable database name")
    storage = Path(tempfile.mkdtemp(prefix="second-brain-e2e-"))
    server = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    database_url = make_url(ADMIN_URL).set(database=database)
    failed = False
    recovery: threading.Thread | None = None
    recovery_publisher: threading.Thread | None = None
    status_server: ThreadingHTTPServer | None = None
    status_thread: threading.Thread | None = None
    try:
        recovery_status = RecoveryProofStatus()
        status_server, status_thread = start_status_server(recovery_status)
        with server.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database}"')
        config = Config(SERVICE_ROOT / "alembic.ini")
        config.set_main_option("script_location", str(SERVICE_ROOT / "migrations"))
        config.set_main_option("sqlalchemy.url", database_url.render_as_string(hide_password=False))
        with redirect_stdout(migration_log), redirect_stderr(migration_log):
            command.upgrade(config, "head")
        admin = create_engine(database_url)
        with admin.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": OWNER_ID, "email": "e2e@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'E2E')"),
                {"id": WORKSPACE_ID, "owner": OWNER_ID},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id,user_id,role) "
                    "VALUES (:workspace,:owner,'owner')"
                ),
                {"workspace": WORKSPACE_ID, "owner": OWNER_ID},
            )
        admin.dispose()
        app_url = database_url.set(
            username="second_brain_app", password="second_brain_app_dev"
        ).render_as_string(hide_password=False)
        worker_url = database_url.set(
            username="second_brain_worker", password="second_brain_worker_dev"
        ).render_as_string(hide_password=False)
        shared = clean_env()
        api_env = shared | {
            "SECOND_BRAIN_APP_ENV": "test",
            "SECOND_BRAIN_AUTH_MODE": "trusted_proxy",
            "SECOND_BRAIN_BIND_HOST": "127.0.0.1",
            "SECOND_BRAIN_BIND_PORT": str(API_PORT),
            "SECOND_BRAIN_DATABASE_URL": app_url,
            "SECOND_BRAIN_STORAGE_ROOT": str(storage),
            "SECOND_BRAIN_MODEL_PROVIDER": "fake",
            "SECOND_BRAIN_TRUSTED_PROXY_SECRET": "e2e-proxy-secret-material-at-least-32-bytes",
            "SECOND_BRAIN_TRUSTED_PROXY_NETWORK": "127.0.0.1/32",
            "SECOND_BRAIN_TRUSTED_ASSERTION_ISSUER": "e2e-issuer",
            "SECOND_BRAIN_TRUSTED_ASSERTION_AUDIENCE": "e2e-audience",
            "SECOND_BRAIN_PUBLIC_ORIGIN": f"http://127.0.0.1:{WEB_PORT}",
        }
        worker_env = shared | {
            "SECOND_BRAIN_WORKER_CONTENT_DATABASE_URL": app_url,
            "SECOND_BRAIN_WORKER_DISPATCHER_DATABASE_URL": worker_url,
            "SECOND_BRAIN_WORKER_STORAGE_ROOT": str(storage),
            "SECOND_BRAIN_WORKER_MODEL_PROVIDER": "fake",
        }
        web_env = shared | {
            "SECOND_BRAIN_API_URL": f"http://127.0.0.1:{API_PORT}",
            "SECOND_BRAIN_PUBLIC_ORIGIN": f"http://127.0.0.1:{WEB_PORT}",
            "SECOND_BRAIN_WEB_APP_ENV": "test",
            "SECOND_BRAIN_WEB_AUTH_MODE": "session",
            "SECOND_BRAIN_WEB_BIND_HOST": "127.0.0.1",
            "SECOND_BRAIN_WEB_PORT": str(WEB_PORT),
        }
        api = spawn("api", [sys.executable, "-m", "second_brain.launcher"], SERVICE_ROOT, api_env)
        wait_url(f"http://127.0.0.1:{API_PORT}/api/v1/health", api)
        web = spawn("web", ["fnm", "exec", "--using", "24", "pnpm", "start"], WEB_ROOT, web_env)
        wait_url(f"http://127.0.0.1:{WEB_PORT}/today", web)
        recovery = threading.Thread(
            target=prove_killed_worker_recovery,
            args=(database_url.render_as_string(hide_password=False), worker_env),
            name="worker-recovery-proof",
            daemon=False,
        )
        recovery.start()
        recovery_publisher = threading.Thread(
            target=publish_recovery_status,
            args=(recovery, recovery_errors, recovery_status),
            kwargs={"timeout": 35},
            name="worker-recovery-status-publisher",
            daemon=False,
        )
        recovery_publisher.start()
        stop.wait()
        require_recovery_completion(recovery, recovery_complete, recovery_errors, timeout=5)
        recovery_publisher.join(timeout=5)
        if recovery_publisher.is_alive():
            raise RuntimeError("worker recovery status publisher did not terminate")
        if private_log_leaks:
            raise RuntimeError(
                "seeded private source text appeared in child logs: " + ", ".join(private_log_leaks)
            )
    except BaseException:
        failed = True
        raise
    finally:
        cleanup_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        cleanup_children = begin_child_cleanup()
        stop.set()
        cleanup_errors = terminate_child_process_groups(cleanup_children, deadline=cleanup_deadline)
        if status_server is not None:
            status_server.shutdown()
            status_server.server_close()
        cleanup_threads = [
            thread for thread in (recovery, recovery_publisher, status_thread) if thread is not None
        ]
        cleanup_errors.extend(
            join_cleanup_threads(
                cleanup_children,
                cleanup_threads,
                deadline=cleanup_deadline,
            )
        )
        final_private_log_recheck()
        if private_log_leaks or cleanup_errors:
            failed = True
        try:
            with server.connect() as connection:
                connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=:name AND pid<>pg_backend_pid()"
                    ),
                    {"name": database},
                )
                connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database}"')
        finally:
            server.dispose()
        if storage.parent == Path(tempfile.gettempdir()) and storage.name.startswith(
            "second-brain-e2e-"
        ):
            shutil.rmtree(storage)
        if failed:
            emit_failure_logs()
        if cleanup_errors:
            sys.stderr.write("\ncleanup failures: " + "; ".join(cleanup_errors) + "\n")
        if sys.exc_info()[0] is None:
            if private_log_leaks:
                raise RuntimeError(
                    "seeded private source text appeared in captured logs: "
                    + ", ".join(sorted(private_log_leaks))
                )
            if cleanup_errors:
                raise RuntimeError("; ".join(cleanup_errors))


for caught_signal in (signal.SIGINT, signal.SIGTERM):
    signal.signal(caught_signal, lambda _signal, _frame: stop.set())

if __name__ == "__main__":
    main()
