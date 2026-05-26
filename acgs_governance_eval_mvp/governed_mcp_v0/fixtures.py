"""Fixture-tree builder for governed MCP v0 tests / demos.

Creates the on-disk evidence tree that a fresh ``GovernedMCPServer``
expects: fixtures/fs, fixtures/database.sqlite3, constitution.json,
deploy_state.json, github_state.json, and an empty receipts/ dir.

Lives outside ``_io.py`` because it is setup-time fixture seeding, not
runtime IO — separating the two keeps the runtime surface area smaller.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ._io import _write_json
from .models import RuntimeTargets


def create_fixture_environment(root: Path) -> RuntimeTargets:
    targets = RuntimeTargets(root=root)
    targets.fs_dir.mkdir(parents=True, exist_ok=True)
    targets.receipts_dir.mkdir(parents=True, exist_ok=True)
    (targets.fs_dir / "readme.txt").write_text("sandbox fixture\n", encoding="utf-8")
    _write_json(
        targets.constitution_path,
        {
            "id": "governed-mcp-v0",
            "policies": [
                "guard-side-effects",
                "fixture-only-targets",
                "deterministic-replay",
            ],
        },
    )
    with sqlite3.connect(targets.sqlite_path) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT OR IGNORE INTO records (id, value) VALUES (1, 'fixture')")
        connection.commit()
    _write_json(
        targets.deploy_state_path,
        {"service": "sandbox-api", "environment": "sandbox", "status": "ready"},
    )
    _write_json(
        targets.github_state_path,
        {"issues": {"sandbox/repo#1": {"title": "fixture issue"}}, "mutations": []},
    )
    return targets
