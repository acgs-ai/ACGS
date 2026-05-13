#!/usr/bin/env python3
"""Smoke-check Vercel internal-doc denial and SPA fallback routing."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTERNAL_DOC_PATHS = (
    "/AGENTS.md",
    "/CLAUDE.md",
    "/DESIGN.md",
    "/DEPLOY.md",
    "/nested/AGENTS.md",
    "/nested/deeper/CLAUDE.md",
    "/nested/DESIGN.md",
    "/nested/deeper/DEPLOY.md",
)


def load_vercel_config() -> dict[str, object]:
    return json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))


def test_internal_doc_paths_have_a_404_route() -> None:
    config = load_vercel_config()
    deny_routes = [
        route
        for route in config.get("routes", [])
        if isinstance(route, dict) and route.get("status") == 404
    ]

    assert deny_routes, "vercel.json must include a 404 route for internal docs"
    compiled = [re.compile(str(route["src"])) for route in deny_routes]
    for path in INTERNAL_DOC_PATHS:
        assert any(pattern.fullmatch(path) for pattern in compiled), f"{path} is not denied"


def test_internal_doc_paths_are_not_rewritten_to_spa_fallback() -> None:
    config = load_vercel_config()
    rewrites = config.get("rewrites", [])

    for rewrite in rewrites:
        if not isinstance(rewrite, dict):
            continue
        source = str(rewrite.get("source", ""))
        destination = str(rewrite.get("destination", ""))
        assert not (
            "AGENTS.md" in source and destination == "/index.html"
        ), "internal docs must not be denied by SPA rewrite"


def test_spa_fallback_remains_for_marketing_routes() -> None:
    config = load_vercel_config()
    routes = config.get("routes", [])

    assert {"src": "/(.*)", "dest": "/"} in routes
