import hashlib
import hmac
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from sqlalchemy import create_engine, text

from second_brain.auth import assertion_signing_payload
from second_brain.config import Settings
from second_brain.launcher import server_config

PROXY_SECRET = "real-socket-proxy-secret-material-at-least-32-bytes"


def _seed_membership(admin_url: str) -> tuple[str, str]:
    owner, workspace = uuid4(), uuid4()
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner, "email": f"{owner}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'socket')"),
                {"id": workspace, "owner": owner},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id,user_id,role) "
                    "VALUES (:workspace,:owner,'owner')"
                ),
                {"workspace": workspace, "owner": owner},
            )
    finally:
        engine.dispose()
    return str(owner), str(workspace)


def _assertion(owner: str, workspace: str) -> dict[str, Any]:
    now = int(time.time())
    assertion: dict[str, Any] = {
        "issuer": "socket-issuer",
        "audience": "socket-audience",
        "issued_at": now,
        "expires_at": now + 60,
        "nonce": str(uuid4()),
        "owner_id": owner,
        "workspace_id": workspace,
    }
    assertion["signature"] = hmac.new(
        PROXY_SECRET.encode(), assertion_signing_payload(assertion), hashlib.sha256
    ).hexdigest()
    return assertion


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_launcher_explicitly_disables_proxy_rewriting_and_access_log() -> None:
    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://second_brain_app@unused/test"
    )
    config = server_config(settings)
    assert config.proxy_headers is False
    assert config.forwarded_allow_ips == ""
    assert config.access_log is False
    assert config.server_header is False


def test_real_socket_uses_peer_not_forwarded_header_and_hides_raw_target(
    database_urls: Any,
) -> None:
    owner, workspace = _seed_membership(database_urls.admin)
    port = _free_port()
    api_env = {
        key: value for key, value in os.environ.items() if not key.startswith("SECOND_BRAIN_")
    }
    api_env.update(
        {
            "SECOND_BRAIN_APP_ENV": "production",
            "SECOND_BRAIN_AUTH_MODE": "trusted_proxy",
            "SECOND_BRAIN_BIND_HOST": "127.0.0.1",
            "SECOND_BRAIN_BIND_PORT": str(port),
            "SECOND_BRAIN_DATABASE_URL": database_urls.app,
            "SECOND_BRAIN_TRUSTED_PROXY_SECRET": PROXY_SECRET,
            "SECOND_BRAIN_TRUSTED_PROXY_NETWORK": "127.0.0.1/32",
            "SECOND_BRAIN_TRUSTED_ASSERTION_ISSUER": "socket-issuer",
            "SECOND_BRAIN_TRUSTED_ASSERTION_AUDIENCE": "socket-audience",
            "SECOND_BRAIN_PUBLIC_ORIGIN": "https://brain.example.test",
        }
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "second_brain.launcher"],
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        env=api_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    output = ""
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{base_url}/api/v1/health", timeout=0.25).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            raise AssertionError("production launcher did not become ready")

        trusted = httpx.post(
            f"{base_url}/api/v1/auth/exchange",
            json=_assertion(owner, workspace),
            headers={"x-forwarded-for": "198.51.100.99"},
            timeout=3,
        )
        untrusted_transport = httpx.HTTPTransport(local_address="127.0.0.2")
        with httpx.Client(transport=untrusted_transport) as untrusted_client:
            untrusted = untrusted_client.post(
                f"{base_url}/api/v1/auth/exchange",
                json=_assertion(owner, workspace),
                headers={"x-forwarded-for": "127.0.0.1"},
                timeout=3,
            )
        marker = "RAW-SERVER-LOG-PRIVATE-PATH-b751"
        assert httpx.get(f"{base_url}/{marker}?q={marker}", timeout=3).status_code == 404
        assert trusted.status_code == 200
        assert "server" not in trusted.headers
        assert untrusted.status_code == 403
        assert "server" not in untrusted.headers
        assert untrusted.json()["code"] == "trusted_proxy_required"
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        output = stdout + stderr
    assert "RAW-SERVER-LOG-PRIVATE-PATH-b751" not in output
    assert '"GET /' not in output


def test_live_api_and_one_shot_worker_persist_without_logging_content(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = _seed_membership(database_urls.admin)
    port = _free_port()
    marker = "LIVE-PRIVATE-INGESTION-MARKER-18d4"
    env = {key: value for key, value in os.environ.items() if not key.startswith("SECOND_BRAIN_")}
    env.update(
        {
            "SECOND_BRAIN_APP_ENV": "test",
            "SECOND_BRAIN_AUTH_MODE": "development_headers",
            "SECOND_BRAIN_BIND_HOST": "127.0.0.1",
            "SECOND_BRAIN_BIND_PORT": str(port),
            "SECOND_BRAIN_DATABASE_URL": database_urls.app,
            "SECOND_BRAIN_STORAGE_ROOT": os.fspath(tmp_path / "objects"),
            "SECOND_BRAIN_MODEL_PROVIDER": "fake",
        }
    )
    service_root = os.fspath(os.path.dirname(os.path.dirname(__file__)))
    process = subprocess.Popen(
        [sys.executable, "-m", "second_brain.launcher"],
        cwd=service_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    output = ""
    worker_output = ""
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{base_url}/api/v1/health", timeout=0.25).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            raise AssertionError("ingestion launcher did not become ready")
        headers = {
            "x-second-brain-owner-id": owner,
            "x-second-brain-workspace-id": workspace,
        }
        captured = httpx.post(
            f"{base_url}/api/v1/captures/text",
            headers=headers,
            json={
                "title": "Live persisted note",
                "content": f"live durable lexical evidence {marker}",
            },
            timeout=3,
        )
        assert captured.status_code == 202
        worker = subprocess.run(
            [sys.executable, "-m", "second_brain.worker", "--once"],
            cwd=service_root,
            env={
                **{
                    key: value
                    for key, value in os.environ.items()
                    if not key.startswith("SECOND_BRAIN_")
                },
                "SECOND_BRAIN_WORKER_CONTENT_DATABASE_URL": database_urls.app,
                "SECOND_BRAIN_WORKER_DISPATCHER_DATABASE_URL": database_urls.worker,
                "SECOND_BRAIN_WORKER_STORAGE_ROOT": os.fspath(tmp_path / "objects"),
                "SECOND_BRAIN_WORKER_MODEL_PROVIDER": "fake",
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        worker_output = worker.stdout + worker.stderr
        opened = httpx.get(
            f"{base_url}/api/v1/sources/{captured.json()['source_id']}/content",
            headers=headers,
            timeout=3,
        )
        job = httpx.get(
            f"{base_url}/api/v1/jobs/{captured.json()['job_id']}",
            headers=headers,
            timeout=3,
        )
        assert opened.status_code == 200
        assert marker in opened.json()["extracted_text"]
        assert job.status_code == 200
        assert job.json()["state"] == "ready"
        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                persisted = connection.execute(
                    text(
                        "SELECT source.processing_state,count(DISTINCT chunk.id),"
                        "count(DISTINCT embedding.id),min(vector_dims(embedding.embedding)) "
                        "FROM sources AS source "
                        "JOIN source_versions AS version ON version.source_id=source.id "
                        "JOIN chunks AS chunk ON chunk.source_version_id=version.id "
                        "JOIN embeddings AS embedding ON embedding.chunk_id=chunk.id "
                        "WHERE source.id=:source GROUP BY source.processing_state"
                    ),
                    {"source": captured.json()["source_id"]},
                ).one()
        finally:
            admin.dispose()
        assert persisted == ("ready", 1, 1, 8)
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        output = stdout + stderr
    assert marker not in output
    assert marker not in worker_output


def test_real_socket_slow_request_body_hits_absolute_deadline_without_persistence(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = _seed_membership(database_urls.admin)
    port = _free_port()
    env = {key: value for key, value in os.environ.items() if not key.startswith("SECOND_BRAIN_")}
    env.update(
        {
            "SECOND_BRAIN_APP_ENV": "test",
            "SECOND_BRAIN_AUTH_MODE": "development_headers",
            "SECOND_BRAIN_BIND_HOST": "127.0.0.1",
            "SECOND_BRAIN_BIND_PORT": str(port),
            "SECOND_BRAIN_DATABASE_URL": database_urls.app,
            "SECOND_BRAIN_STORAGE_ROOT": os.fspath(tmp_path / "slow-body-objects"),
            "SECOND_BRAIN_REQUEST_BODY_TIMEOUT_SECONDS": "0.05",
        }
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "second_brain.launcher"],
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    response = b""
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if (
                    httpx.get(f"http://127.0.0.1:{port}/api/v1/health", timeout=0.25).status_code
                    == 200
                ):
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            raise AssertionError("slow-body launcher did not become ready")
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            client.settimeout(2)
            client.sendall(
                (
                    "POST /api/v1/captures/text HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: 100\r\n"
                    f"x-second-brain-owner-id: {owner}\r\n"
                    f"x-second-brain-workspace-id: {workspace}\r\n"
                    "Connection: close\r\n\r\n{"
                ).encode()
            )
            time.sleep(0.08)
            while True:
                block = client.recv(4096)
                if not block:
                    break
                response += block
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
    assert response.startswith(b"HTTP/1.1 408")
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM sources WHERE owner_id=:owner"), {"owner": owner}
                )
                == 0
            )
    finally:
        admin.dispose()
    assert not list((tmp_path / "slow-body-objects").rglob("*"))
