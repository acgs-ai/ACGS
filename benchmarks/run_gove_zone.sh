#!/usr/bin/env bash
# Run the gove-zone governed-actions scaling benchmark from the repo root.
# Usage: ./benchmarks/run_gove_zone.sh [--scales 100 1000 100000] [--json out.json]
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run --package gove-zone --extra crypto \
  python packages/gove-zone/benchmarks/governed_actions_bench.py "$@"
