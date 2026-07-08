"""CLI entry point: run the benchmark and emit the report.

Examples::

    # Score the gove-zone reference target, print the report, write JSON.
    uv run --package gove-zone python -m acgs_benchmark --json report.json

    # Markdown report to stdout.
    uv run --package gove-zone python -m acgs_benchmark --format markdown

    # Just validate the corpus loads (no target needed).
    python -m acgs_benchmark --list
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from acgs_benchmark import SCHEMA_VERSION
from acgs_benchmark.report import render_markdown, render_text
from acgs_benchmark.schema import CATEGORIES, default_suite_dir, load_suite
from acgs_benchmark.scoring import run_benchmark


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acgs_benchmark",
        description="Score a governed-agent runtime against the ACGS governance benchmark.",
    )
    parser.add_argument(
        "--scenarios",
        type=Path,
        default=None,
        help="Directory of scenario JSON files (default: bundled suite).",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Write the full machine-readable report to this path.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="Human-readable report format for stdout (default: text).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Load and summarize the corpus without running a target.",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        help="Exit non-zero if the Governance Score is below this threshold.",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit non-zero if any critical scenario fails.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    suite_dir = args.scenarios or default_suite_dir()
    scenarios = load_suite(suite_dir)

    if args.list:
        by_cat = {c: sum(1 for s in scenarios if s.category == c) for c in CATEGORIES}
        print(f"Loaded {len(scenarios)} scenarios from {suite_dir}")
        for cat, count in by_cat.items():
            print(f"  {cat:<22} {count}")
        return 0

    # Import the reference target lazily so --list works without gove_zone.
    from acgs_benchmark.targets import GoveZoneTarget

    target = GoveZoneTarget()
    report = run_benchmark(target, scenarios, schema_version=SCHEMA_VERSION)

    if args.format == "markdown":
        print(render_markdown(report))
    else:
        print(render_text(report))

    if args.json is not None:
        args.json.write_text(report.to_json() + "\n", encoding="utf-8")
        print(f"\nWrote machine-readable report to {args.json}", file=sys.stderr)

    exit_code = 0
    if args.fail_on_critical and report.critical_failures:
        exit_code = 2
    if args.fail_under is not None and report.governance_score < args.fail_under:
        exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
