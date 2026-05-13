#!/usr/bin/env python3
"""Verify DESIGN.md color tokens remain wired to runtime CSS variables.

Stdlib-only on purpose: this script should run in the Vite package without
requiring the Python governance-pack dependencies.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN_TO_CSS = {
    'paper': 'paper',
    'paper-alt': 'paper-2',
    'paper-deep': 'paper-3',
    'card': 'card',
    'ink': 'ink',
    'ink-secondary': 'ink-2',
    'ink-tertiary': 'ink-3',
    'muted': 'muted',
    'muted-light': 'muted-2',
    'line': 'line',
    'line-soft': 'line-soft',
    'line-softer': 'line-softer',
    'rust': 'accent',
    'rust-hover': 'accent-2',
    'rust-soft': 'accent-soft',
    'parchment': 'boundary',
    'parchment-ink': 'boundary-ink',
    'parchment-line': 'boundary-line',
    'risk-confirmed': 'risk-lo',
    'risk-partial': 'risk-mid',
    'risk-blocked': 'risk-hi',
}


def load_design_colors() -> dict[str, str]:
    design = (ROOT / 'DESIGN.md').read_text(encoding='utf-8')
    try:
        frontmatter = design.split('---', 2)[1]
    except IndexError as exc:
        raise SystemExit('DESIGN.md is missing YAML front matter') from exc

    colors: dict[str, str] = {}
    in_colors = False
    for line in frontmatter.splitlines():
        if line == 'colors:':
            in_colors = True
            continue
        if in_colors and line and not line.startswith(' '):
            break
        if not in_colors:
            continue
        match = re.fullmatch(r'  ([a-z0-9-]+): "(#[0-9A-Fa-f]{6})"', line)
        if match:
            colors[match.group(1).lower()] = match.group(2).lower()
    return colors


def load_css_vars() -> dict[str, str]:
    css = (ROOT / 'src/index.css').read_text(encoding='utf-8')
    return {
        name: value.lower()
        for name, value in re.findall(r'--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})', css)
    }


def main() -> int:
    colors = load_design_colors()
    css_vars = load_css_vars()
    mismatches: list[str] = []
    for design_name, css_name in DESIGN_TO_CSS.items():
        design_value = colors.get(design_name)
        css_value = css_vars.get(css_name)
        if design_value != css_value:
            mismatches.append(f'{design_name}={design_value!r} != --{css_name}={css_value!r}')
    if mismatches:
        print('DESIGN.md and src/index.css token mismatches:', file=sys.stderr)
        for mismatch in mismatches:
            print(f'  - {mismatch}', file=sys.stderr)
        return 1
    print(f'DESIGN.md color tokens match src/index.css for {len(DESIGN_TO_CSS)} runtime variables.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
