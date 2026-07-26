"""Importable multiprocessing worker for tenant bootstrap conformance tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings


def post_bootstrap_from_spawned_process(
    _index: int,
    *,
    body: dict[str, Any],
    headers: dict[str, str],
) -> tuple[int, dict[str, Any]]:
    database_url = os.environ["ACP_TEST_POSTGRES_URL"]
    with tempfile.TemporaryDirectory(prefix="acp-tenant-bootstrap-race-") as audit_dir:
        app = create_app(
            Settings(
                database_url=database_url,
                audit_dir=Path(audit_dir),
                create_tables=False,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )
        try:
            with TestClient(app) as client:
                result = client.post("/v1/tenant-bootstrap", json=body, headers=headers)
                return result.status_code, result.json()
        finally:
            app.state.engine.dispose()
