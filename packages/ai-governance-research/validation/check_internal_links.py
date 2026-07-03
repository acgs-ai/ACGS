#!/usr/bin/env python3
"""Validate that relative Markdown links point to files inside this docs hub."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def main() -> int:
    missing: list[str] = []
    checked = 0
    for path in sorted(ROOT.rglob("*.md")):
        checked += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in LINK_RE.finditer(text):
            target = match.group(1).split("#", 1)[0].split("?", 1)[0].strip()
            if not target or re.match(r"^[a-zA-Z0-9+.-]+:", target):
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                missing.append(f"{path.relative_to(ROOT)} -> {target} (outside hub)")
                continue
            if not resolved.exists():
                missing.append(f"{path.relative_to(ROOT)} -> {target} (missing)")
    if missing:
        print("broken internal markdown links:")
        for item in missing:
            print(f"- {item}")
        return 1
    print(f"internal markdown links ok: {checked} markdown files checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
