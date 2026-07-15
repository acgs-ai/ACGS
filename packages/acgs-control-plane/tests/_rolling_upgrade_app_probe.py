"""Isolated subprocess probe for the control-plane rolling-upgrade tests.

The caller controls ``PYTHONPATH``.  Consequently this file can exercise either
an immutable historical wheel or the reviewed source tree without importing
both implementations into one interpreter.  The line-oriented protocol never
returns API keys or database URLs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings

try:
    from acgs_control_plane.migrations import StartupSchemaPreflightError
except ImportError:  # The immutable pre-migration candidate has no migrations module.
    StartupSchemaPreflightError = None  # type: ignore[assignment,misc]


def _write(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _safe_error(exc: BaseException) -> dict[str, str]:
    """Classify exact trusted exception identities without class metadata access."""
    exception_type = type(exc)
    if exception_type is OperationalError:
        code = "database-operation-refused"
    elif StartupSchemaPreflightError is not None and exception_type is StartupSchemaPreflightError:
        code = "schema-preflight-refused"
    else:
        code = "unexpected-refusal"
    return {"error_code": code, "status": "refused"}


def _settings() -> Settings:
    return Settings(
        database_url=os.environ["ACP_PROBE_DATABASE_URL"],
        audit_dir=Path(os.environ["ACP_PROBE_AUDIT_DIR"]),
        bootstrap_token=os.environ.get("ACP_PROBE_BOOTSTRAP_TOKEN") or None,
        create_tables=False,
        runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
    )


def _module_origin() -> str:
    import acgs_control_plane

    return str(Path(acgs_control_plane.__file__).resolve())


def _start_once() -> int:
    try:
        app = create_app(_settings())
    except BaseException as exc:
        _write({**_safe_error(exc), "module_origin": _module_origin()})
        return 0
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            ready = client.get("/readyz")
            _write(
                {
                    "module_origin": _module_origin(),
                    "ready_body": ready.json(),
                    "ready_status": ready.status_code,
                    "status": "started",
                }
            )
    finally:
        app.state.engine.dispose()
    return 0


def _server() -> int:
    try:
        app = create_app(_settings())
    except BaseException as exc:
        _write({**_safe_error(exc), "module_origin": _module_origin()})
        return 0

    api_key = os.environ.get("ACP_PROBE_API_KEY")
    headers = {"X-API-Key": api_key} if api_key else {}
    org_id: str | None = None
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            _write({"module_origin": _module_origin(), "pid": os.getpid(), "status": "started"})
            for raw_line in sys.stdin:
                try:
                    request = json.loads(raw_line)
                    command = request["command"]
                    if command == "stop":
                        _write({"status": "stopped"})
                        return 0
                    if command == "health":
                        response = client.get("/healthz")
                    elif command == "ready":
                        response = client.get("/readyz")
                    elif command == "bootstrap":
                        response = client.post(
                            "/orgs",
                            headers={"X-Bootstrap-Token": os.environ["ACP_PROBE_BOOTSTRAP_TOKEN"]},
                            json={
                                "name": request["name"],
                                "admin_name": "Rolling Upgrade Admin",
                                "admin_email": "rolling-admin@example.com",
                            },
                        )
                        if response.status_code == 201:
                            body = response.json()
                            org_id = body["org_id"]
                            _write(
                                {
                                    "admin_user_id": body["admin_user_id"],
                                    "org_id": org_id,
                                    "status_code": response.status_code,
                                }
                            )
                            continue
                    elif command == "use_org":
                        org_id = str(request["org_id"])
                        _write({"org_id": org_id, "status": "selected"})
                        continue
                    elif command == "get_org":
                        response = client.get(f"/orgs/{org_id}", headers=headers)
                    elif command == "list_users":
                        response = client.get(f"/orgs/{org_id}/users", headers=headers)
                    elif command == "create_user":
                        response = client.post(
                            f"/orgs/{org_id}/users",
                            headers=headers,
                            json={
                                "name": request["name"],
                                "email": request["email"],
                                "role": "viewer",
                            },
                        )
                    else:
                        _write({"error_type": "UnknownCommand", "status": "refused"})
                        continue
                    body = response.json()
                    if isinstance(body, dict):
                        body = {
                            key: value
                            for key, value in body.items()
                            if "key" not in key.lower() and "token" not in key.lower()
                        }
                    _write({"body": body, "status_code": response.status_code})
                except BaseException as exc:
                    _write(_safe_error(exc))
    finally:
        app.state.engine.dispose()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "start-once"))
    args = parser.parse_args()
    if args.mode == "start-once":
        return _start_once()
    return _server()


if __name__ == "__main__":
    raise SystemExit(main())
